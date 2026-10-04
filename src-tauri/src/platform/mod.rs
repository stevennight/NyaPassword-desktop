//! Everything that differs between Windows, macOS and Linux sits behind
//! [`Platform`] (design doc §10.3). Windows is the main target; the macOS and
//! Linux implementations build and run in CI but are untested on real
//! machines ("experimental").

use std::sync::Arc;

use tauri::AppHandle;
use tauri_plugin_autostart::ManagerExt;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// Keyring service / user of the device key.
const KEYRING_SERVICE: &str = "app.nya.password";
const KEYRING_USER: &str = "device-key";

/// Passed by the autostart entry: start hidden in the tray.
pub const MINIMIZED_ARG: &str = "--minimized";

pub type LockCallback = Arc<dyn Fn() + Send + Sync>;

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
