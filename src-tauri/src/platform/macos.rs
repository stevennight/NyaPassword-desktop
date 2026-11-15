//! macOS platform integration. The device key lives in the login keychain.
//! macOS presents its native authorization sheet for protected actions. On an
//! Apple Silicon Mac that sheet can be completed with Touch ID and falls back
//! to the account password according to the user's macOS settings.

use std::ffi::CString;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;


use super::{arboard_clipboard, LockCallback, Platform};

pub struct MacOs;

const TOUCH_ID_SECRET_PREFIX: &str = "touch-id-quick-unlock.";

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn npw_touch_id_available() -> i32;
    fn npw_touch_id_authenticate(reason: *const std::ffi::c_char) -> i32;
}

fn authenticate(reason: &str) -> Result<(), String> {
    let reason = CString::new(reason).map_err(|_| "Touch ID 验证说明包含无效字符".to_string())?;
    let result = unsafe { npw_touch_id_authenticate(reason.as_ptr()) };
    match result {
        0 => Ok(()),
        -2 => Err("Touch ID 不可用，请在系统设置中录入指纹后重试".into()),
        -3 => Err("Touch ID 验证超时".into()),
        _ => Err("已取消或未通过 Touch ID 验证".into()),
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
        unsafe { npw_touch_id_available() != 0 }
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
