//! macOS platform integration. The device key lives in the login keychain.
//! macOS presents its native authorization sheet for protected actions. On an
//! Apple Silicon Mac that sheet can be completed with Touch ID and falls back
//! to the account password according to the user's macOS settings.

use std::process::Command;

use super::{arboard_clipboard, LockCallback, Platform};

pub struct MacOs;

impl Platform for MacOs {
    fn key_store_name(&self) -> &'static str {
        "macOS 钥匙串"
    }

    fn quick_unlock_label(&self) -> &'static str {
        "Touch ID / 系统验证"
    }

    fn user_consent_available(&self) -> bool {
        // `osascript` is shipped with macOS and invokes Authorization Services
        // for this operation. It is available on both Intel and Apple Silicon.
        // The actual sheet decides whether Touch ID is available and offers the
        // normal password fallback when it is not.
        cfg!(target_os = "macos")
    }

    fn user_consent_verify(&self, message: &str) -> Result<(), String> {
        let reason = message.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "do shell script \"/usr/bin/true\" with administrator privileges with prompt \"{reason}\""
        );
        let result = Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .output()
            .map_err(|e| format!("无法启动 macOS 系统验证：{e}"))?;
        if result.status.success() {
            Ok(())
        } else {
            let detail = String::from_utf8_lossy(&result.stderr).trim().to_string();
            if detail.is_empty() {
                Err(format!("已取消 macOS 系统验证：{reason}"))
            } else {
                Err(format!("macOS 系统验证失败：{detail}"))
            }
        }
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
