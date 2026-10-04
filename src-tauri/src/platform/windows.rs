//! Windows: Credential Manager for the device key (via keyring, DPAPI-backed),
//! Windows Hello (KeyCredentialManager) for quick unlock, a clipboard that
//! stays out of clipboard history / cloud clipboard, and session-lock / sleep
//! notifications from a hidden window.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use windows::core::{w, Array, HSTRING, PCWSTR};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Foundation::{
    GlobalFree, ERROR_FILE_NOT_FOUND, HANDLE, HGLOBAL, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW,
    SetClipboardData,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::Registry::{
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ,
    RRF_RT_REG_BINARY, RRF_RT_REG_SZ,
};
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, FindWindowW, GetMessageW, RegisterClassW,
    SetForegroundWindow, TranslateMessage, MSG, PBT_APMSUSPEND, WINDOW_EX_STYLE, WM_POWERBROADCAST,
    WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT,
    WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
};

use super::{LockCallback, Platform, MINIMIZED_ARG};

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
