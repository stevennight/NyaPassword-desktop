//! macOS platform integration. The device key lives in the login keychain.
//! macOS presents its native authorization sheet for protected actions. On an
//! Apple Silicon Mac that sheet can be completed with Touch ID and falls back
//! to the account password according to the user's macOS settings.

use std::process::Command;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;


use super::{arboard_clipboard, LockCallback, Platform};

pub struct MacOs;

const TOUCH_ID_SECRET_PREFIX: &str = "touch-id-quick-unlock.";

fn authenticate(reason: &str) -> Result<(), String> {
    let escaped = reason.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "use framework \"LocalAuthentication\"\nproperty finished : false\nproperty accepted : false\nset context to current application's LAContext's alloc()'s init()\nset policy to 2\nset canUse to context's canEvaluatePolicy:error:(policy, missing value)\nif canUse is false then return \"UNAVAILABLE\"\ncontext's evaluatePolicy:localizedReason:reply:(policy, \"{escaped}\", my replyHandler)\nrepeat while finished is false\n    delay 0.1\nend repeat\nif accepted then return \"OK\"\nreturn \"NO\"\non replyHandler(success, failure)\n    set accepted to success as boolean\n    set finished to true\nend replyHandler"
    );
    let output = Command::new("/usr/bin/osascript")
        .args(["-l", "AppleScript", "-e", &script])
        .output()
        .map_err(|e| format!("无法启动 macOS LocalAuthentication：{e}"))?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "OK" => Ok(()),
        "UNAVAILABLE" => Err("Touch ID / macOS 系统验证不可用，请先输入主密码".into()),
        _ => Err("已取消或未通过 Touch ID / macOS 系统验证".into()),
    }
}

fn secret_name(name: &str) -> String {
    format!("{TOUCH_ID_SECRET_PREFIX}{name}")
}

fn sign_with_secret(secret: &[u8], challenge: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(challenge);
    Ok(mac.finalize().into_bytes().to_vec())
}

impl Platform for MacOs {
    fn key_store_name(&self) -> &'static str {
        "macOS 钥匙串"
    }

    fn quick_unlock_label(&self) -> &'static str {
        "Touch ID"
    }

    fn quick_unlock_supported(&self) -> bool {
        cfg!(target_os = "macos")
    }

    fn quick_unlock_create(&self, name: &str, challenge: &[u8]) -> Result<Vec<u8>, String> {
        authenticate("NyaPassword：开启 Touch ID 快速解锁")?;
        let secret = Uuid::new_v4().as_bytes().to_vec();
        self.store_secret(&secret_name(name), &secret)?;
        sign_with_secret(&secret, challenge)
    }

    fn quick_unlock_sign(&self, name: &str, challenge: &[u8]) -> Result<Vec<u8>, super::QuickError> {
        authenticate("NyaPassword：使用 Touch ID 解锁")
            .map_err(super::QuickError::Other)?;
        let secret = self
            .load_secret(&secret_name(name))
            .map_err(super::QuickError::Other)?
            .ok_or_else(|| super::QuickError::Invalidated("Touch ID 快速解锁密钥不存在".into()))?;
        sign_with_secret(&secret, challenge).map_err(super::QuickError::Other)
    }

    fn quick_unlock_delete(&self, name: &str) {
        let _ = self.delete_secret(&secret_name(name));
    }

    fn user_consent_available(&self) -> bool {
        // `osascript` is shipped with macOS and invokes Authorization Services
        // for this operation. It is available on both Intel and Apple Silicon.
        // The actual sheet decides whether Touch ID is available and offers the
        // normal password fallback when it is not.
        self.quick_unlock_supported()
    }

    fn user_consent_verify(&self, message: &str) -> Result<(), String> {
        let reason = message.replace('\\', "\\\\").replace('"', "\\\"");
        authenticate(&reason)
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
