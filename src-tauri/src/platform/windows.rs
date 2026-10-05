//! Windows: Credential Manager for the device key (via keyring, DPAPI-backed),
//! Windows Hello (KeyCredentialManager) for quick unlock, a clipboard that
//! stays out of clipboard history / cloud clipboard, and session-lock / sleep
//! notifications from a hidden window; foreground-window capture and
//! `SendInput` auto-type, the OpenSSH service status, the native messaging
//! host registration (HKCU), and process / SID helpers for the IPC pipes.

use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use windows::core::{w, Array, HSTRING, PCWSTR, PWSTR};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Foundation::{
    CloseHandle, GlobalFree, LocalFree, ERROR_FILE_NOT_FOUND, HANDLE, HGLOBAL, HLOCAL, HWND,
    LPARAM, LRESULT, WPARAM,
};
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW,
    SetClipboardData,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows::Win32::System::Registry::{
    RegDeleteKeyValueW, RegDeleteTreeW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ,
    RRF_RT_REG_BINARY, RRF_RT_REG_SZ,
};
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatus,
    QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_AUTO_START, SERVICE_DEMAND_START,
    SERVICE_DISABLED, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, VIRTUAL_KEY, VK_BACK, VK_CONTROL,
    VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_LEFT, VK_LWIN, VK_MENU, VK_RETURN, VK_RIGHT,
    VK_RWIN, VK_SHIFT, VK_SPACE, VK_TAB, VK_UP,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, FindWindowW, GetForegroundWindow,
    GetMessageW, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic,
    IsWindow, RegisterClassW, SetForegroundWindow, ShowWindow, TranslateMessage, MSG,
    PBT_APMSUSPEND, SW_RESTORE, WINDOW_EX_STYLE, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE,
    WNDCLASSW, WS_OVERLAPPED, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
    WTS_SESSION_LOGOFF,
};

use super::{LockCallback, Platform, SystemAgent, TargetWindow, MINIMIZED_ARG, NATIVE_HOST_NAME};
use crate::autotype::{Key, Step};

pub struct Windows;

impl Platform for Windows {
    fn key_store_name(&self) -> &'static str {
        "Windows 凭据管理器"
    }

    fn quick_unlock_label(&self) -> &'static str {
        "Windows Hello"
    }

    fn quick_unlock_supported(&self) -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .unwrap_or(false)
    }

    fn quick_unlock_create(&self, name: &str, challenge: &[u8]) -> Result<Vec<u8>, String> {
        let _focus = PromptFocus::start();
        let res = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(name),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.join())
        .map_err(|e| format!("Windows Hello：{}", e.message()))?;
        check_status(res.Status().map_err(|e| e.message())?)?;
        let cred = res.Credential().map_err(|e| e.message())?;
        sign(&cred, challenge)
    }

    fn quick_unlock_sign(&self, name: &str, challenge: &[u8]) -> Result<Vec<u8>, String> {
        let _focus = PromptFocus::start();
        let res = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
            .and_then(|op| op.join())
            .map_err(|e| format!("Windows Hello：{}", e.message()))?;
        check_status(res.Status().map_err(|e| e.message())?)?;
        let cred = res.Credential().map_err(|e| e.message())?;
        sign(&cred, challenge)
    }

    fn quick_unlock_delete(&self, name: &str) {
        if let Err(e) =
            KeyCredentialManager::DeleteAsync(&HSTRING::from(name)).and_then(|op| op.join())
        {
            log::info!("deleting the Windows Hello key: {}", e.message());
        }
    }

    fn clipboard_set(&self, text: &str, secret: bool) -> Result<(), String> {
        let _open = Clipboard::open()?;
        unsafe {
            EmptyClipboard().map_err(|e| e.message())?;
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            put(CF_UNICODETEXT.0 as u32, bytes_of(&wide))?;
            if secret {
                // https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats#cloud-clipboard-and-clipboard-history-formats
                let zero = 0u32.to_ne_bytes();
                for name in [
                    w!("ExcludeClipboardContentFromMonitorProcessing"),
                    w!("CanIncludeInClipboardHistory"),
                    w!("CanUploadToCloudClipboard"),
                ] {
                    let fmt = RegisterClipboardFormatW(name);
                    if fmt != 0 {
                        put(fmt, &zero)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn clipboard_get(&self) -> Option<String> {
        let _open = Clipboard::open().ok()?;
        unsafe {
            let h = GetClipboardData(CF_UNICODETEXT.0 as u32).ok()?;
            let g = HGLOBAL(h.0);
            let p = GlobalLock(g) as *const u16;
            if p.is_null() {
                return None;
            }
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            let _ = GlobalUnlock(g);
            Some(s)
        }
    }

    fn clipboard_clear(&self) {
        if let Ok(_open) = Clipboard::open() {
            unsafe {
                let _ = EmptyClipboard();
            }
        }
    }

    // Per-user Run entry. (The autostart plugin writes to HKLM when the app
    // runs elevated, which would start it for every user of the machine.)
    fn autostart_enabled(&self, _app: &tauri::AppHandle) -> bool {
        unsafe {
            let mut size = 0u32;
            if RegGetValueW(
                HKEY_CURRENT_USER,
                RUN_KEY,
                RUN_VALUE,
                RRF_RT_REG_SZ,
                None,
                None,
                Some(&mut size),
            )
            .is_err()
            {
                return false;
            }
            // Task Manager's "disable" leaves the Run entry and marks it here (odd first byte)
            let mut buf = [0u8; 12];
            let mut len = buf.len() as u32;
            let r = RegGetValueW(
                HKEY_CURRENT_USER,
                APPROVED_KEY,
                RUN_VALUE,
                RRF_RT_REG_BINARY,
                None,
                Some(buf.as_mut_ptr().cast()),
                Some(&mut len),
            );
            !(r.is_ok() && len > 0 && buf[0] & 1 == 1)
        }
    }

    fn set_autostart(&self, _app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
        unsafe {
            if enabled {
                let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                let cmd = format!("\"{}\" {MINIMIZED_ARG}", exe.display());
                let wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
                RegSetKeyValueW(
                    HKEY_CURRENT_USER,
                    RUN_KEY,
                    RUN_VALUE,
                    REG_SZ.0,
                    Some(wide.as_ptr().cast()),
                    (wide.len() * 2) as u32,
                )
                .ok()
                .map_err(|e| e.message())?;
                let _ = RegDeleteKeyValueW(HKEY_CURRENT_USER, APPROVED_KEY, RUN_VALUE);
            } else {
                let r = RegDeleteKeyValueW(HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE);
                if r != ERROR_FILE_NOT_FOUND {
                    r.ok().map_err(|e| e.message())?;
                }
            }
        }
        Ok(())
    }

    fn watch_session_lock(&self, on_lock: LockCallback) {
        if ON_LOCK.set(on_lock).is_err() {
            return;
        }
        std::thread::Builder::new()
            .name("session-watch".into())
            .spawn(|| {
                if let Err(e) = unsafe { session_window() } {
                    log::warn!("session-lock notifications unavailable: {}", e.message());
                }
            })
            .expect("spawn session watcher");
    }

    fn foreground_window(&self) -> Option<TargetWindow> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.is_invalid() {
                return None;
            }
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == 0 || pid == std::process::id() {
                return None;
            }
            let len = GetWindowTextLengthW(hwnd).max(0) as usize;
            let mut buf = vec![0u16; len + 1];
            let n = GetWindowTextW(hwnd, &mut buf).max(0) as usize;
            let process = process_image(pid)
                .and_then(|p| {
                    std::path::Path::new(&p)
                        .file_name()
                        .map(|f| f.to_string_lossy().into_owned())
                })
                .unwrap_or_default();
            Some(TargetWindow {
                handle: hwnd.0 as isize,
                title: String::from_utf16_lossy(&buf[..n.min(len)]),
                process,
            })
        }
    }

    fn auto_type_supported(&self) -> bool {
        true
    }

    fn auto_type(&self, target: &TargetWindow, steps: &[Step]) -> Result<(), String> {
        let hwnd = HWND(target.handle as *mut c_void);
        unsafe {
            if !IsWindow(Some(hwnd)).as_bool() {
                return Err("目标窗口已经关闭".into());
            }
            wait_modifiers_released();
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            let start = Instant::now();
            while GetForegroundWindow() != hwnd {
                let _ = SetForegroundWindow(hwnd);
                if start.elapsed() > Duration::from_millis(1500) {
                    return Err("无法切换到目标窗口，已取消自动输入".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            // let the window settle its focus (e.g. a browser's input field)
            std::thread::sleep(Duration::from_millis(120));
            for step in steps {
                if GetForegroundWindow() != hwnd {
                    return Err("目标窗口失去焦点，已停止自动输入".into());
                }
                match step {
                    Step::Text(t) => {
                        for unit in t.encode_utf16() {
                            match unit {
                                0x0A | 0x0D => send_vk(VK_RETURN)?,
                                0x09 => send_vk(VK_TAB)?,
                                u => send_unicode(u)?,
                            }
                            std::thread::sleep(Duration::from_millis(4));
                            if GetForegroundWindow() != hwnd {
                                return Err("目标窗口失去焦点，已停止自动输入".into());
                            }
                        }
                    }
                    Step::Key(k) => send_vk(vk_of(*k))?,
                    Step::Delay(ms) => std::thread::sleep(Duration::from_millis(u64::from(*ms))),
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        }
        Ok(())
    }

    fn ssh_agent_default_endpoint(&self, _data_dir: &Path) -> String {
        "openssh-ssh-agent".into()
    }

    fn ssh_auth_sock(&self, endpoint: &str) -> String {
        format!(r"\\.\pipe\{endpoint}")
    }

    fn system_ssh_agent(&self) -> SystemAgent {
        unsafe { query_service(w!("ssh-agent")) }.unwrap_or_default()
    }

    fn endpoint_owner(&self, endpoint: &str) -> Option<String> {
        // open the pipe as a client for a moment and ask who serves it
        let path = HSTRING::from(format!(r"\\.\pipe\{endpoint}"));
        unsafe {
            let h = CreateFileW(
                &path,
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
            .ok()?;
            let mut pid = 0u32;
            let r = GetNamedPipeServerProcessId(h, &mut pid);
            let _ = CloseHandle(h);
            r.ok()?;
            let exe = process_image(pid)?;
            std::path::Path::new(&exe)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
        }
    }

    fn register_native_host(&self, data_dir: &Path, manifest: &str) -> Result<Vec<String>, String> {
        let dir = data_dir.join("native-messaging");
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let file = dir.join(format!("{NATIVE_HOST_NAME}.json"));
        std::fs::write(&file, manifest).map_err(|e| format!("{}: {e}", file.display()))?;
        let value: Vec<u16> = file
            .display()
            .to_string()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut done = Vec::new();
        for key in native_host_keys() {
            let k = HSTRING::from(key.as_str());
            unsafe {
                RegSetKeyValueW(
                    HKEY_CURRENT_USER,
                    &k,
                    PCWSTR::null(),
                    REG_SZ.0,
                    Some(value.as_ptr().cast()),
                    (value.len() * 2) as u32,
                )
                .ok()
                .map_err(|e| format!("HKCU\\{key}: {}", e.message()))?;
            }
            done.push(format!("HKCU\\{key}"));
        }
        Ok(done)
    }

    fn unregister_native_host(&self, data_dir: &Path) {
        for key in native_host_keys() {
            let k = HSTRING::from(key.as_str());
            let _ = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, &k) };
        }
        let _ = std::fs::remove_file(
            data_dir
                .join("native-messaging")
                .join(format!("{NATIVE_HOST_NAME}.json")),
        );
    }
}

/// Registry keys (under HKCU) where Chrome, Edge and Chromium look for the host.
fn native_host_keys() -> Vec<String> {
    [r"Google\Chrome", r"Microsoft\Edge", "Chromium"]
        .iter()
        .map(|b| format!(r"Software\{b}\NativeMessagingHosts\{NATIVE_HOST_NAME}"))
        .collect()
}

/// The registry value Chrome reads for the host.
#[cfg(test)]
pub fn native_host_registered_path() -> Option<String> {
    let key = HSTRING::from(native_host_keys()[0].as_str());
    let mut buf = [0u16; 1024];
    let mut len = (buf.len() * 2) as u32;
    unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            &key,
            PCWSTR::null(),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut len),
        )
        .ok()
        .ok()?;
    }
    let n = (len as usize / 2).saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..n]))
}

unsafe fn query_service(name: PCWSTR) -> Option<SystemAgent> {
    let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).ok()?;
    let svc = match OpenServiceW(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG) {
        Ok(s) => s,
        Err(_) => {
            let _ = CloseServiceHandle(scm);
            return Some(SystemAgent {
                state: "not_installed".into(),
                start_type: String::new(),
            });
        }
    };
    let mut status = SERVICE_STATUS::default();
    let state = if QueryServiceStatus(svc, &mut status).is_ok() {
        if status.dwCurrentState == SERVICE_RUNNING {
            "running"
        } else {
            "stopped"
        }
    } else {
        ""
    };
    let mut needed = 0u32;
    let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    let start_type = if QueryServiceConfigW(
        svc,
        Some(buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
        (buf.len() * 8) as u32,
        &mut needed,
    )
    .is_ok()
    {
        let cfg = &*(buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>());
        match cfg.dwStartType {
            SERVICE_AUTO_START => "auto",
            SERVICE_DEMAND_START => "manual",
            SERVICE_DISABLED => "disabled",
            _ => "",
        }
    } else {
        ""
    };
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    Some(SystemAgent {
        state: state.into(),
        start_type: start_type.into(),
    })
}

/// The SID of the user running this process, as `S-1-5-21-…`.
pub fn current_user_sid() -> Result<String, String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(|e| e.message())?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        // u64 storage: TOKEN_USER holds pointers and must be aligned
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let r = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 8) as u32,
            &mut len,
        );
        let _ = CloseHandle(token);
        r.map_err(|e| e.message())?;
        let user = &*(buf.as_ptr().cast::<TOKEN_USER>());
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut s).map_err(|e| e.message())?;
        let out = s.to_string().map_err(|e| e.to_string());
        let _ = LocalFree(Some(HLOCAL(s.0.cast())));
        out
    }
}

/// Full path of a process's executable.
pub fn process_image(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let r =
            QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(h);
        r.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

pub fn parent_pid(pid: u32) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut e = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = None;
        let mut ok = Process32FirstW(snap, &mut e).is_ok();
        while ok {
            if e.th32ProcessID == pid {
                found = Some(e.th32ParentProcessID).filter(|p| *p != 0);
                break;
            }
            ok = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = CloseHandle(snap);
        found
    }
}

fn vk_of(k: Key) -> VIRTUAL_KEY {
    match k {
        Key::Tab => VK_TAB,
        Key::Enter => VK_RETURN,
        Key::Space => VK_SPACE,
        Key::Backspace => VK_BACK,
        Key::Delete => VK_DELETE,
        Key::Escape => VK_ESCAPE,
        Key::Up => VK_UP,
        Key::Down => VK_DOWN,
        Key::Left => VK_LEFT,
        Key::Right => VK_RIGHT,
        Key::Home => VK_HOME,
        Key::End => VK_END,
    }
}

fn key_input(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(inputs: &[INPUT]) -> Result<(), String> {
    let n = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    if n as usize != inputs.len() {
        // UIPI: a window of a higher integrity level (an elevated program) drops our input
        return Err("输入被系统拦截（目标程序可能以管理员身份运行）".into());
    }
    Ok(())
}

/// One UTF-16 unit as a Unicode "key": independent of the keyboard layout and IME.
fn send_unicode(unit: u16) -> Result<(), String> {
    send(&[
        key_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE),
        key_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
    ])
}

fn send_vk(vk: VIRTUAL_KEY) -> Result<(), String> {
    let ext = if matches!(
        vk,
        VK_UP | VK_DOWN | VK_LEFT | VK_RIGHT | VK_HOME | VK_END | VK_DELETE
    ) {
        KEYEVENTF_EXTENDEDKEY
    } else {
        KEYBD_EVENT_FLAGS(0)
    };
    send(&[
        key_input(vk, 0, ext),
        key_input(vk, 0, ext | KEYEVENTF_KEYUP),
    ])
}

/// The user may still hold Ctrl / Shift / Alt from the shortcut; typed text
/// would turn into shortcuts. Waits up to two seconds for them to be released.
fn wait_modifiers_released() {
    let start = Instant::now();
    let held = || {
        [VK_CONTROL, VK_SHIFT, VK_MENU, VK_LWIN, VK_RWIN]
            .iter()
            .any(|k| unsafe { GetAsyncKeyState(i32::from(k.0)) } as u16 & 0x8000 != 0)
    };
    while held() && start.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(20));
    }
}

const RUN_KEY: PCWSTR = w!(r"Software\Microsoft\Windows\CurrentVersion\Run");
const APPROVED_KEY: PCWSTR =
    w!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run");
const RUN_VALUE: PCWSTR = w!("NyaPassword");

fn check_status(s: KeyCredentialStatus) -> Result<(), String> {
    match s {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled => Err("已取消 Windows Hello 验证".into()),
        KeyCredentialStatus::NotFound => Err(
            "找不到 Windows Hello 密钥（可能已重置 PIN 或生物识别），请用主密码解锁后重新开启"
                .into(),
        ),
        KeyCredentialStatus::UserPrefersPassword => Err("请用主密码解锁".into()),
        KeyCredentialStatus::SecurityDeviceLocked => Err("安全设备已锁定，请稍后再试".into()),
        KeyCredentialStatus::CredentialAlreadyExists => Err("Windows Hello 密钥已存在".into()),
        _ => Err("Windows Hello 不可用（请在系统设置中设置 PIN 或生物识别）".into()),
    }
}

fn sign(cred: &KeyCredential, challenge: &[u8]) -> Result<Vec<u8>, String> {
    let buf = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|e| e.message())?;
    let res = cred
        .RequestSignAsync(&buf)
        .and_then(|op| op.join())
        .map_err(|e| format!("Windows Hello：{}", e.message()))?;
    check_status(res.Status().map_err(|e| e.message())?)?;
    let out = res.Result().map_err(|e| e.message())?;
    let mut arr = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&out, &mut arr).map_err(|e| e.message())?;
    Ok(arr.to_vec())
}

/// The Windows Hello prompt of a desktop (non-UWP) app often opens behind the
/// app window; bring it to the front while a request is pending.
struct PromptFocus(Arc<AtomicBool>);

impl PromptFocus {
    fn start() -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        let _ = std::thread::Builder::new()
            .name("hello-focus".into())
            .spawn(move || {
                let start = Instant::now();
                while !d.load(Ordering::Relaxed) && start.elapsed() < Duration::from_secs(10) {
                    if let Ok(hwnd) =
                        unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), PCWSTR::null()) }
                    {
                        if !hwnd.is_invalid() {
                            let _ = unsafe { SetForegroundWindow(hwnd) };
                            return;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
        Self(done)
    }
}

impl Drop for PromptFocus {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// An open clipboard, closed on drop. Another program may hold it briefly: retry.
struct Clipboard;

impl Clipboard {
    fn open() -> Result<Self, String> {
        let mut last = String::new();
        for _ in 0..20 {
            match unsafe { OpenClipboard(None) } {
                Ok(()) => return Ok(Clipboard),
                Err(e) => last = e.message(),
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(format!("剪贴板被其他程序占用：{last}"))
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        let _ = unsafe { CloseClipboard() };
    }
}

fn bytes_of(w: &[u16]) -> &[u8] {
    // SAFETY: u16 has no padding; the slice covers exactly the same memory.
    unsafe { std::slice::from_raw_parts(w.as_ptr() as *const u8, std::mem::size_of_val(w)) }
}

/// Copies `data` into a movable global block and hands it to the clipboard.
unsafe fn put(format: u32, data: &[u8]) -> Result<(), String> {
    let g = GlobalAlloc(GMEM_MOVEABLE, data.len().max(1)).map_err(|e| e.message())?;
    let p = GlobalLock(g) as *mut u8;
    if p.is_null() {
        let _ = GlobalFree(Some(g));
        return Err("GlobalLock failed".into());
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
    let _ = GlobalUnlock(g);
    if let Err(e) = SetClipboardData(format, Some(HANDLE(g.0))) {
        let _ = GlobalFree(Some(g));
        return Err(e.message());
    }
    // the clipboard owns the block now
    Ok(())
}

static ON_LOCK: OnceLock<LockCallback> = OnceLock::new();

unsafe extern "system" fn session_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let lock = match msg {
        WM_WTSSESSION_CHANGE => matches!(
            wparam.0 as u32,
            WTS_SESSION_LOCK | WTS_SESSION_LOGOFF | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT
        ),
        WM_POWERBROADCAST => wparam.0 as u32 == PBT_APMSUSPEND,
        _ => false,
    };
    if lock {
        if let Some(f) = ON_LOCK.get() {
            f();
        }
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// A hidden top-level window (message-only windows miss the power broadcast)
/// registered for session notifications, with its own message loop.
unsafe fn session_window() -> windows::core::Result<()> {
    let hinst = GetModuleHandleW(None)?;
    let class = w!("NyaPasswordSessionWatch");
    let wc = WNDCLASSW {
        lpfnWndProc: Some(session_proc),
        hInstance: hinst.into(),
        lpszClassName: class,
        ..Default::default()
    };
    RegisterClassW(&wc);
    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class,
        w!("NyaPassword session watch"),
        WS_OVERLAPPED,
        0,
        0,
        0,
        0,
        None,
        None,
        Some(hinst.into()),
        None,
    )?;
    WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)?;
    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_and_own_process() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        let exe = process_image(std::process::id()).unwrap();
        assert!(exe.to_lowercase().ends_with(".exe"));
        assert!(parent_pid(std::process::id()).is_some());
        // the OpenSSH service query never fails hard
        let _ = Windows.system_ssh_agent();
    }

    /// Writes the real HKCU registration and removes it again. Ignored by
    /// default (it touches the user's registry): `cargo test -- --ignored native_host`.
    #[test]
    #[ignore]
    fn native_host_registration_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let done = Windows
            .register_native_host(dir.path(), r#"{"name":"app.nya.password"}"#)
            .unwrap();
        assert_eq!(done.len(), 3);
        let path = native_host_registered_path().unwrap();
        assert!(
            path.ends_with(r"native-messaging\app.nya.password.json"),
            "{path}"
        );
        assert!(std::path::Path::new(&path).exists());
        Windows.unregister_native_host(dir.path());
        assert!(native_host_registered_path().is_none());
        assert!(!std::path::Path::new(&path).exists());
    }
}
