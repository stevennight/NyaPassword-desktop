//! Everything that differs between Windows, macOS and Linux sits behind
//! [`Platform`] (design doc §10.3). Windows is the main target; the macOS and
//! Linux implementations build and run in CI but are untested on real
//! machines ("experimental").

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_autostart::ManagerExt;

use crate::autotype::Step;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
pub(crate) mod windows;

/// Keyring service / user of the device key.
const KEYRING_SERVICE: &str = "app.nya.password";
const KEYRING_USER: &str = "device-key";

/// Passed by the autostart entry: start hidden in the tray.
pub const MINIMIZED_ARG: &str = "--minimized";

pub type LockCallback = Arc<dyn Fn() + Send + Sync>;

/// The window that had the focus when Quick Access opened (auto-type goes back to it).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetWindow {
    /// Native handle (`HWND` on Windows); only meaningful to the platform layer.
    #[serde(skip)]
    pub handle: isize,
    pub title: String,
    /// File name of the process executable, e.g. `chrome.exe`.
    pub process: String,
}

/// The OS's own ssh-agent, which may own the endpoint we want.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct SystemAgent {
    /// `""` (none / not applicable), `running`, `stopped`.
    pub state: String,
    /// `auto`, `manual`, `disabled` or `""`.
    pub start_type: String,
}

/// Name of the native messaging host (`allowed_origins` live in its manifest).
pub const NATIVE_HOST_NAME: &str = "app.nya.password";

pub const UNSUPPORTED_AUTOTYPE: &str =
    "此平台暂不支持自动输入（目前只支持 Windows），请使用复制用户名 / 密码";
pub trait Platform: Send + Sync {
    // ------------------------------------------------------------ device key

    /// Where [`Platform::store_device_key`] keeps the key, for the settings page.
    fn key_store_name(&self) -> &'static str;

    /// `Ok(None)`: the store works but has no key. `Err`: the store is unavailable.
    fn load_device_key(&self) -> Result<Option<Vec<u8>>, String> {
        let entry =
            keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(|e| e.to_string())?;
        match entry.get_secret() {
            Ok(k) => Ok(Some(k)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn store_device_key(&self, key: &[u8]) -> Result<(), String> {
        keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .and_then(|e| e.set_secret(key))
            .map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------ quick unlock

    /// Shown in the UI ("使用 Windows Hello 解锁").
    fn quick_unlock_label(&self) -> &'static str;

    /// The OS offers a usable biometric / PIN key here.
    fn quick_unlock_supported(&self) -> bool {
        false
    }

    /// Creates (replacing) the OS key `name` and signs `challenge` with it. The
    /// signature must be deterministic: it is the secret the wrapping key comes from.
    fn quick_unlock_create(&self, _name: &str, _challenge: &[u8]) -> Result<Vec<u8>, String> {
        Err("此平台暂不支持快速解锁".into())
    }

    /// Signs `challenge` with the existing OS key `name` (prompts the user).
    fn quick_unlock_sign(&self, _name: &str, _challenge: &[u8]) -> Result<Vec<u8>, String> {
        Err("此平台暂不支持快速解锁".into())
    }

    fn quick_unlock_delete(&self, _name: &str) {}

    // ------------------------------------------------------------ clipboard

    /// Puts `text` on the clipboard; `secret` keeps it out of clipboard
    /// history and cloud clipboard where the OS supports that.
    fn clipboard_set(&self, text: &str, secret: bool) -> Result<(), String>;
    fn clipboard_get(&self) -> Option<String>;
    fn clipboard_clear(&self);

    // ------------------------------------------------------------ lock screen

    /// Calls `on_lock` when the session locks, the user switches away or the
    /// machine goes to sleep. Returns immediately (watches on its own thread).
    fn watch_session_lock(&self, on_lock: LockCallback);

    // ------------------------------------------------------------ autostart

    /// Start with the OS session, minimized to the tray.
    fn autostart_enabled(&self, app: &AppHandle) -> bool {
        app.autolaunch().is_enabled().unwrap_or(false)
    }

    fn set_autostart(&self, app: &AppHandle, enabled: bool) -> Result<(), String> {
        let al = app.autolaunch();
        if enabled {
            al.enable().map_err(|e| e.to_string())
        } else {
            al.disable().map_err(|e| e.to_string())
        }
    }

    // ------------------------------------------------------------ quick access / auto-type

    /// The focused window of another program, captured before Quick Access shows.
    fn foreground_window(&self) -> Option<TargetWindow> {
        None
    }

    fn auto_type_supported(&self) -> bool {
        false
    }

    /// Focuses `target` and types `steps` into it. Stops as soon as another
    /// window takes the focus, so secrets never go to the wrong window.
    fn auto_type(&self, _target: &TargetWindow, _steps: &[Step]) -> Result<(), String> {
        Err(UNSUPPORTED_AUTOTYPE.into())
    }

    // ------------------------------------------------------------ ssh-agent

    /// Where the agent listens unless the user picked something else:
    /// a pipe name on Windows, a socket path elsewhere.
    fn ssh_agent_default_endpoint(&self, data_dir: &Path) -> String {
        data_dir.join("ssh-agent.sock").display().to_string()
    }

    /// The value for `SSH_AUTH_SOCK` / `IdentityAgent` for an endpoint.
    fn ssh_auth_sock(&self, endpoint: &str) -> String {
        endpoint.to_string()
    }

    fn system_ssh_agent(&self) -> SystemAgent {
        SystemAgent::default()
    }

    /// The program serving an endpoint we could not take (e.g. `Bitwarden.exe`).
    fn endpoint_owner(&self, _endpoint: &str) -> Option<String> {
        None
    }

    // ------------------------------------------------------------ browser bridge

    /// Installs the native messaging host manifest for Chrome, Edge and
    /// Chromium; returns where it was registered.
    fn register_native_host(&self, data_dir: &Path, manifest: &str) -> Result<Vec<String>, String> {
        let _ = data_dir;
        let mut done = Vec::new();
        for dir in unix_native_host_dirs() {
            // only browsers that exist for this user
            if dir.parent().is_some_and(|p| p.exists()) {
                std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                let file = dir.join(format!("{NATIVE_HOST_NAME}.json"));
                std::fs::write(&file, manifest).map_err(|e| format!("{}: {e}", file.display()))?;
                done.push(file.display().to_string());
            }
        }
        Ok(done)
    }

    fn unregister_native_host(&self, data_dir: &Path) {
        let _ = data_dir;
        for dir in unix_native_host_dirs() {
            let _ = std::fs::remove_file(dir.join(format!("{NATIVE_HOST_NAME}.json")));
        }
    }

    /// The executable the browser starts as the host.
    fn native_host_exe(&self) -> Result<PathBuf, String> {
        // an AppImage runs from a temporary mount; the browser must start the image itself
        if let Some(p) = std::env::var_os("APPIMAGE") {
            return Ok(PathBuf::from(p));
        }
        std::env::current_exe().map_err(|e| e.to_string())
    }
}

/// `NativeMessagingHosts` folders of Chrome, Edge and Chromium (macOS, Linux).
fn unix_native_host_dirs() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return vec![];
    };
    let bases: &[&str] = if cfg!(target_os = "macos") {
        &[
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Microsoft Edge",
            "Library/Application Support/Chromium",
        ]
    } else {
        &[
            ".config/google-chrome",
            ".config/microsoft-edge",
            ".config/chromium",
        ]
    };
    bases
        .iter()
        .map(|b| home.join(b).join("NativeMessagingHosts"))
        .collect()
}

/// The implementation for the platform this build runs on.
pub fn native() -> &'static dyn Platform {
    #[cfg(windows)]
    {
        &windows::Windows
    }
    #[cfg(target_os = "macos")]
    {
        &macos::MacOs
    }
    #[cfg(target_os = "linux")]
    {
        &linux::Linux
    }
}

/// `windows`, `macos` or `linux` (the device platform reported to the server).
pub fn os_name() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Clipboard through arboard (macOS, Linux). The clipboard object stays alive:
/// on X11 / Wayland the owner must keep serving the content.
#[cfg(not(windows))]
pub(crate) mod arboard_clipboard {
    use std::sync::Mutex;

    static CLIP: Mutex<Option<arboard::Clipboard>> = Mutex::new(None);

    fn with<T>(
        f: impl FnOnce(&mut arboard::Clipboard) -> Result<T, arboard::Error>,
    ) -> Result<T, String> {
        let mut g = CLIP.lock().map_err(|_| "clipboard lock".to_string())?;
        if g.is_none() {
            *g = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        f(g.as_mut().expect("set above")).map_err(|e| e.to_string())
    }

    pub fn set(text: &str, secret: bool) -> Result<(), String> {
        with(|c| {
            #[cfg(target_os = "linux")]
            if secret {
                use arboard::SetExtLinux;
                // x-kde-passwordManagerHint: clipboard managers skip it
                return c.set().exclude_from_history().text(text.to_string());
            }
            let _ = secret;
            c.set_text(text.to_string())
        })
    }

    pub fn get() -> Option<String> {
        with(|c| c.get_text()).ok()
    }

    pub fn clear() {
        let _ = with(|c| c.clear());
    }
}
