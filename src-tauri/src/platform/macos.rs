//! macOS (experimental, no real-machine testing). The device key lives in the
//! login keychain. Not yet implemented: Touch ID quick unlock (needs
//! LocalAuthentication + a biometry-protected keychain item), screen-lock
//! detection (com.apple.screenIsLocked) and the concealed pasteboard type.

use super::{arboard_clipboard, LockCallback, Platform};

pub struct MacOs;

impl Platform for MacOs {
    fn key_store_name(&self) -> &'static str {
        "macOS 钥匙串"
    }

    fn quick_unlock_label(&self) -> &'static str {
        "Touch ID"
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
            "screen-lock detection is not implemented on macOS yet; idle auto-lock still applies"
        );
    }
}
