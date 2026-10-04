//! Quick unlock (design doc §4.5). Enabling: the OS creates a key that needs
//! the user (Windows Hello: face / fingerprint / PIN) and signs a random
//! 32-byte challenge; HKDF-SHA256 of that signature is the wrapping key for
//! the account key AK. The challenge and the wrapped AK are stored in
//! `quick-unlock.json`; the signature exists only while unlocking.
//!
//! Rules: offered only after a master-password unlock in this app run, and
//! only within 14 days of the last master-password unlock.

use std::path::Path;

use hkdf::Hkdf;
use npw_crypto::{aad, b64, envelope, unb64, Key32};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const FILE: &str = "quick-unlock.json";
pub const MAX_AGE_MS: i64 = 14 * 24 * 60 * 60 * 1000;
const HKDF_INFO: &[u8] = b"npw/desktop/quick-unlock/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Stored {
    pub version: u32,
    pub account_id: String,
    /// base64 of the 32-byte challenge the OS key signs.
    pub challenge: String,
    /// base64 envelope of AK under the derived key, AAD `aad::quick_unlock(account)`.
    pub wrapped: String,
    pub created_at: i64,
}

/// Name of the OS key (Windows Hello credential) for an account.
pub fn credential_name(account_id: &str) -> String {
    format!("NyaPassword.{account_id}")
}

fn account_bytes(account_id: &str) -> Result<[u8; 16], String> {
    uuid::Uuid::parse_str(account_id)
        .map(|u| *u.as_bytes())
        .map_err(|_| "bad account id".to_string())
}

pub fn wrapping_key(signature: &[u8], challenge: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(challenge), signature);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Key32::from_bytes(*okm)
}

/// Wraps the account key for `account_id` under the key derived from `signature`.
pub fn wrap(
    account_key: &[u8],
    signature: &[u8],
    challenge: &[u8],
    account_id: &str,
    now_ms: i64,
) -> Result<Stored, String> {
    let wk = wrapping_key(signature, challenge);
    let wrapped = envelope::seal(
        &wk,
        account_key,
        &aad::quick_unlock(&account_bytes(account_id)?),
    );
    Ok(Stored {
        version: 1,
        account_id: account_id.into(),
        challenge: b64(challenge),
        wrapped: b64(&wrapped),
        created_at: now_ms,
    })
}

pub fn challenge(s: &Stored) -> Result<Vec<u8>, String> {
    unb64(&s.challenge).ok_or_else(|| "quick-unlock.json is damaged".to_string())
}

/// The account key, or an error when the signature (OS key) is not the one it was wrapped with.
pub fn unwrap(s: &Stored, signature: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let wk = wrapping_key(signature, &challenge(s)?);
    let wrapped = unb64(&s.wrapped).ok_or_else(|| "quick-unlock.json is damaged".to_string())?;
    envelope::open(
        &wk,
        &wrapped,
        &aad::quick_unlock(&account_bytes(&s.account_id)?),
    )
    .map(Zeroizing::new)
    .map_err(|_| "快速解锁密钥已失效，请用主密码解锁后重新开启".to_string())
}

/// May the user unlock without the master password right now?
pub fn allowed(password_unlock_this_run: bool, last_password_unlock_ms: i64, now_ms: i64) -> bool {
    password_unlock_this_run
        && last_password_unlock_ms > 0
        && now_ms >= last_password_unlock_ms
        && now_ms - last_password_unlock_ms < MAX_AGE_MS
}

pub fn load(dir: &Path) -> Option<Stored> {
    let b = std::fs::read(dir.join(FILE)).ok()?;
    serde_json::from_slice(&b).ok()
}

pub fn save(dir: &Path, s: &Stored) -> std::io::Result<()> {
    crate::settings::write_atomic(
        &dir.join(FILE),
        &serde_json::to_vec_pretty(s).expect("serializable"),
    )
}

pub fn remove(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(FILE));
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "0190f3c4-8a1b-7c2d-9e3f-4a5b6c7d8e9f";

    #[test]
    fn wrap_and_unwrap() {
        let ak = [7u8; 32];
        let sig = vec![1u8; 256];
        let ch = [9u8; 32];
        let s = wrap(&ak, &sig, &ch, ACCOUNT, 1).unwrap();
        assert_eq!(challenge(&s).unwrap(), ch);
        assert_eq!(&unwrap(&s, &sig).unwrap()[..], &ak[..]);

        // another OS key (different signature) cannot open it
        let mut other = sig.clone();
        other[0] ^= 1;
        assert!(unwrap(&s, &other).is_err());

        // bound to the account (AAD) and to the challenge (HKDF salt)
        let mut moved = s.clone();
        moved.account_id = "0190f3c4-8a1b-7c2d-9e3f-000000000000".into();
        assert!(unwrap(&moved, &sig).is_err());
        let mut rechallenged = s.clone();
        rechallenged.challenge = b64(&[8u8; 32]);
        assert!(unwrap(&rechallenged, &sig).is_err());
    }

    #[test]
    fn wrapping_key_is_deterministic_and_salted() {
        let a = wrapping_key(b"signature", b"challenge-1");
        assert_eq!(a, wrapping_key(b"signature", b"challenge-1"));
        assert_ne!(a, wrapping_key(b"signature", b"challenge-2"));
        assert_ne!(a, wrapping_key(b"signaturf", b"challenge-1"));
    }

    #[test]
    fn rules() {
        let day = 24 * 60 * 60 * 1000;
        let now = 100 * day;
        assert!(allowed(true, now - day, now));
        assert!(
            !allowed(false, now - day, now),
            "needs a password unlock in this run"
        );
        assert!(!allowed(true, now - 14 * day, now), "expires after 14 days");
        assert!(allowed(true, now - 14 * day + 1, now));
        assert!(!allowed(true, 0, now));
        assert!(!allowed(true, now + day, now), "clock went backwards");
    }

    #[test]
    fn file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).is_none());
        let s = wrap(&[1u8; 32], b"sig", &[2u8; 32], ACCOUNT, 5).unwrap();
        save(dir.path(), &s).unwrap();
        assert_eq!(load(dir.path()), Some(s));
        remove(dir.path());
        assert!(load(dir.path()).is_none());
    }
}
