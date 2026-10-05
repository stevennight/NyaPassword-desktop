//! Verifying the user again without locking, before an item marked
//! "使用前需要验证" (`ItemContent::reprompt`) gives out its secrets: in the
//! vault window, Quick Access and the SSH signature prompt.
//!
//! - The master password: checked by the core (`Client::verify_password`).
//! - Windows Hello: when quick unlock is on, the same signature path as quick
//!   unlock (the Hello key signs the stored challenge, the derived key must
//!   open the stored account key, and the core checks that it is this
//!   account's key); otherwise a plain Hello presence check
//!   (`UserConsentVerifier`). The password always works.
//!
//! This is a guard against someone using the unlocked app, not encryption.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use npw_core::Client;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{BridgeError, CmdResult};
use crate::platform::Platform;
use crate::quick_unlock;
use crate::state::AppState;

/// How Windows Hello (or another OS method) can verify the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Biometric {
    /// Quick unlock is on: its Hello key signs the stored challenge.
    QuickUnlockKey,
    /// Only a presence check (no key of ours).
    Consent,
}

/// Which OS method to offer, if any.
pub fn biometric_method(
    supported: bool,
    quick_unlock_stored: bool,
    consent_available: bool,
) -> Option<Biometric> {
    if supported && quick_unlock_stored {
        Some(Biometric::QuickUnlockKey)
    } else if consent_available {
        Some(Biometric::Consent)
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VerifyOptions {
    /// `verify_user` without a password can be offered.
    pub biometric: bool,
    /// "Windows Hello".
    pub label: String,
}

/// What a verification needs; built on the command's thread, used on a worker
/// thread (Windows Hello blocks while its dialog is open).
pub struct Verifier {
    platform: &'static dyn Platform,
    dir: PathBuf,
    client: Arc<Client>,
}

impl Verifier {
    pub fn new(st: &AppState) -> CmdResult<Self> {
        Ok(Self {
            platform: st.platform,
            dir: st.dir.clone(),
            client: st.client()?,
        })
    }

    fn stored(&self) -> Option<quick_unlock::Stored> {
        let account = self.client.lock_state().account_id;
        quick_unlock::load(&self.dir).filter(|s| !account.is_empty() && s.account_id == account)
    }

    /// Blocking.
    pub fn method(&self) -> Option<Biometric> {
        let supported = self.platform.quick_unlock_supported();
        let stored = supported && self.stored().is_some();
        // the presence check is only asked about when the key path is not there
        let consent = !stored && self.platform.user_consent_available();
        biometric_method(supported, stored, consent)
    }

    /// Blocking.
    pub fn options(&self) -> VerifyOptions {
        VerifyOptions {
            biometric: self.client.is_unlocked() && self.method().is_some(),
            label: self.platform.quick_unlock_label().into(),
        }
    }

    /// Verifies with the master password, or with Windows Hello when there is
    /// none. Blocking (the Hello dialog). Only while unlocked.
    pub fn verify(&self, password: Option<&str>) -> CmdResult<()> {
        if !self.client.is_unlocked() {
            return Err(npw_core::CoreError::Locked.into());
        }
        if let Some(pw) = password.filter(|p| !p.is_empty()) {
            self.client.verify_password(pw)?;
            return Ok(());
        }
        let label = self.platform.quick_unlock_label();
        match self.method() {
            Some(Biometric::QuickUnlockKey) => {
                let stored = self
                    .stored()
                    .ok_or_else(|| BridgeError::invalid(format!("没有开启 {label} 解锁")))?;
                let challenge = quick_unlock::challenge(&stored).map_err(BridgeError::invalid)?;
                let name = quick_unlock::credential_name(&stored.account_id);
                let signature = Zeroizing::new(
                    self.platform
                        .quick_unlock_sign(&name, &challenge)
                        .map_err(BridgeError::invalid)?,
                );
                let ak = quick_unlock::unwrap(&stored, &signature).map_err(BridgeError::invalid)?;
                self.client.verify_key(&ak)?;
                Ok(())
            }
            Some(Biometric::Consent) => self
                .platform
                .user_consent_verify("NyaPassword：验证身份以使用这个条目")
                .map_err(BridgeError::invalid),
            None => Err(BridgeError::invalid(format!(
                "{label} 不可用，请输入主密码"
            ))),
        }
    }
}

/// How long a Quick Access verification waits to be used.
pub const GRANT_TTL: Duration = Duration::from_secs(120);

/// One verification for one item, used up by the next secret it releases
/// (Quick Access: auto-type, copying the password or the code).
#[derive(Default)]
pub struct ItemGrant(Mutex<Option<(String, String, Instant)>>);

impl ItemGrant {
    pub fn grant(&self, vault_id: &str, item_id: &str) {
        *self.0.lock().expect("grant") = Some((vault_id.into(), item_id.into(), Instant::now()));
    }

    /// Whether this item was verified (within [`GRANT_TTL`]); a grant is used once.
    pub fn take(&self, vault_id: &str, item_id: &str) -> bool {
        let mut g = self.0.lock().expect("grant");
        let ok = g
            .as_ref()
            .is_some_and(|(v, i, at)| v == vault_id && i == item_id && at.elapsed() < GRANT_TTL);
        if ok {
            *g = None;
        }
        ok
    }

    pub fn clear(&self) {
        *self.0.lock().expect("grant") = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_prefers_the_quick_unlock_key() {
        assert_eq!(
            biometric_method(true, true, true),
            Some(Biometric::QuickUnlockKey)
        );
        assert_eq!(
            biometric_method(true, true, false),
            Some(Biometric::QuickUnlockKey)
        );
        assert_eq!(
            biometric_method(true, false, true),
            Some(Biometric::Consent)
        );
        // a stored key without OS support (Hello removed) cannot be used
        assert_eq!(
            biometric_method(false, true, true),
            Some(Biometric::Consent)
        );
        assert_eq!(biometric_method(false, true, false), None);
        assert_eq!(biometric_method(false, false, false), None);
    }

    #[test]
    fn grants_are_per_item_and_single_use() {
        let g = ItemGrant::default();
        assert!(!g.take("v", "a"));
        g.grant("v", "a");
        assert!(!g.take("v", "b"), "another item");
        assert!(!g.take("w", "a"), "same id in another vault");
        assert!(g.take("v", "a"));
        assert!(!g.take("v", "a"), "used up");
        g.grant("v", "a");
        g.grant("v", "b");
        assert!(!g.take("v", "a"), "a newer verification replaces it");
        assert!(g.take("v", "b"));
        g.grant("v", "a");
        g.clear();
        assert!(!g.take("v", "a"));
    }

    #[test]
    fn grants_expire() {
        let g = ItemGrant::default();
        let Some(old) = Instant::now().checked_sub(GRANT_TTL + Duration::from_secs(1)) else {
            return; // the clock started less than the TTL ago
        };
        *g.0.lock().unwrap() = Some(("v".into(), "a".into(), old));
        assert!(!g.take("v", "a"));
    }
}
