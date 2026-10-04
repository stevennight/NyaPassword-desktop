//! Linux (experimental, no real-machine testing). The device key lives in the
//! Secret Service (GNOME Keyring / KWallet). There is no biometric unlock;
//! screen-lock detection (logind `Lock` / org.freedesktop.ScreenSaver) is not
//! implemented yet. Secrets on the clipboard carry the KDE password-manager
//! hint so clipboard managers skip them.

use super::{arboard_clipboard, LockCallback, Platform};

pub struct Linux;

impl Platform for Linux {
    fn key_store_name(&self) -> &'static str {
        "Secret Service（GNOME 钥匙圈 / KWallet）"
    }

    fn quick_unlock_label(&self) -> &'static str {
        ""
    }

    fn clipboard_set(&self, text: &str, secret: bool) -> Result<(), String> {
        arboard_clipboard::set(text, secret)
    }

    fn clipboard_get(&self) -> Option<String> {
        arboard_clipboard::get()
    }

    fn clipboard_clear(&self) {
        arboard_clipboard::clear()
    }

    fn watch_session_lock(&self, _on_lock: LockCallback) {
        log::info!(
            "screen-lock detection is not implemented on Linux yet; idle auto-lock still applies"
        );
    }
}
