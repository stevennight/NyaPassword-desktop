//! Device-local unlock rules and PIN material (design doc §4.5,
//! 加密规格.md §4.4, 威胁模型.md §3.8.2).
//!
//! One record (the "guard") per device, kept in the OS credential store next
//! to the device key (Windows Credential Manager, i.e. DPAPI for the current
//! user), never in a plain file:
//!
//! - when the master password was last entered on this device. Biometrics
//!   (Windows Hello) and the PIN stop working 14 days after it, and while the
//!   clock reads earlier than the latest time this app has seen (a clock set
//!   back must not extend the 14 days). Editing a file cannot extend it.
//! - the PIN blob (the account key under Argon2id(PIN), npw-core `pin.rs`)
//!   and the count of wrong tries in a row. A try is counted and saved
//!   *before* the PIN is checked, so killing the app during a try does not
//!   give a free one; [`PIN_MAX_TRIES`] wrong tries delete the PIN.
//!
//! Without a usable credential store (the `device-key.bin` fallback) the
//! guard lives in memory only: no PIN, and quick unlock needs the master
//! password in this run of the app.

use std::sync::Mutex;

use npw_core::{CoreError, PinBlob};
use serde::{Deserialize, Serialize};

/// Biometrics and the PIN need the master password again after this long.
pub const MAX_AGE_MS: i64 = 14 * 24 * 60 * 60 * 1000;
/// Wrong PIN tries in a row before the PIN is deleted.
pub const PIN_MAX_TRIES: u32 = 5;
/// How far the clock may go back (time sync) before quick unlock is suspended.
pub const CLOCK_SLACK_MS: i64 = 10 * 60 * 1000;
/// Name of the credential store entry.
pub const ENTRY: &str = "unlock-guard";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Guard {
    pub account_id: String,
    /// Unix ms of the last master-password unlock on this device.
    pub password_unlock_at: i64,
    /// The latest clock reading this app has seen.
    pub seen_at: i64,
    pub pin: Option<PinState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PinState {
    pub blob: PinBlob,
    /// Wrong tries in a row, counted before each try.
    pub tries: u32,
}

/// Why biometrics and the PIN cannot be used now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    /// No master-password unlock recorded on this device (for this account).
    NoPassword,
    /// The app restarted and "biometrics at start" is off.
    Restarted,
    /// 14 days since the last master-password unlock.
    Expired,
    /// The clock went back.
    ClockBack,
}

impl Stale {
    pub fn message(self) -> &'static str {
        match self {
            Stale::NoPassword => "请先在这台设备上用主密码解锁一次",
            Stale::Restarted => {
                "启动后第一次解锁需要主密码（设置里可开启“启动时可直接用生物识别解锁”）"
            }
            Stale::Expired => "距上次输入主密码已超过 14 天，生物识别和 PIN 已暂停，请输入主密码",
            Stale::ClockBack => "系统时间早于上次使用的时间，请输入主密码",
        }
    }
}

/// The 14-day rule (and the clock check) for one guard.
pub fn fresh(g: &Guard, now: i64) -> Result<(), Stale> {
    if g.password_unlock_at <= 0 {
        return Err(Stale::NoPassword);
    }
    if now + CLOCK_SLACK_MS < g.seen_at.max(g.password_unlock_at) {
        return Err(Stale::ClockBack);
    }
    if now - g.password_unlock_at >= MAX_AGE_MS {
        return Err(Stale::Expired);
    }
    Ok(())
}

/// Where the guard is persisted (the OS credential store; a map in tests).
pub trait SecretStore: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, String>;
    fn save(&self, data: &[u8]) -> Result<(), String>;
    fn delete(&self) -> Result<(), String>;
}

/// The guard entry in the platform's credential store.
pub struct PlatformStore(pub &'static dyn crate::platform::Platform);

impl SecretStore for PlatformStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        self.0.load_secret(ENTRY)
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        self.0.store_secret(ENTRY, data)
    }
    fn delete(&self) -> Result<(), String> {
        self.0.delete_secret(ENTRY)
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct PinStatus {
    /// The PIN can be set up on this device (the credential store works).
    pub supported: bool,
    /// A PIN is set (it may be suspended).
    pub set: bool,
    /// A PIN is set and may be used now.
    pub usable: bool,
    pub tries_left: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PinError {
    NotSet,
    Stale(Stale),
    /// Wrong PIN; `left` more tries.
    Wrong {
        left: u32,
    },
    /// The last allowed try was wrong: the PIN was deleted.
    Wiped,
    /// The try could not be counted (credential store): not tried.
    Store(String),
    /// Something else failed while checking (the try is not counted).
    Core(String, String),
}

impl From<PinError> for crate::error::BridgeError {
    fn from(e: PinError) -> Self {
        use crate::error::BridgeError as B;
        match e {
            PinError::NotSet => B::invalid("没有设置 PIN，请输入主密码"),
            PinError::Stale(s) => B::new("password_required", s.message()),
            PinError::Wrong { left } => {
                B::new("wrong_pin", format!("PIN 不正确，还可以再试 {left} 次"))
            }
            PinError::Wiped => B::new(
                "pin_wiped",
                format!("PIN 连续输错 {PIN_MAX_TRIES} 次，已作废。请输入主密码，然后在设置里重新设置 PIN"),
            ),
            PinError::Store(m) => B::invalid(format!("无法记录 PIN 尝试次数（{m}），这次没有验证")),
            PinError::Core(code, message) => B::new(&code, message),
        }
    }
}

/// The guard of this device: a cached copy, written through to the store.
pub struct Guards {
    store: Option<Box<dyn SecretStore>>,
    /// `None` until first loaded.
    slot: Mutex<Option<Guard>>,
}

impl Guards {
    /// `store`: `None` keeps the guard in memory only (no PIN).
    pub fn new(store: Option<Box<dyn SecretStore>>) -> Self {
        Self {
            store,
            slot: Mutex::new(None),
        }
    }

    pub fn persistent(&self) -> bool {
        self.store.is_some()
    }

    fn current(&self, slot: &mut Option<Guard>) -> Guard {
        if slot.is_none() {
            let loaded = self
                .store
                .as_ref()
                .and_then(|s| match s.load() {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("cannot read the unlock guard: {e}");
                        None
                    }
                })
                .and_then(|b| serde_json::from_slice::<Guard>(&b).ok());
            *slot = Some(loaded.unwrap_or_default());
        }
        slot.clone().unwrap_or_default()
    }

    /// Saves `g`; the cached copy changes only when that worked.
    fn put(&self, slot: &mut Option<Guard>, g: Guard) -> Result<(), String> {
        if let Some(s) = &self.store {
            s.save(&serde_json::to_vec(&g).expect("json"))?;
        }
        *slot = Some(g);
        Ok(())
    }

    /// Saves `g`, or at least keeps it for this run.
    fn put_or_keep(&self, slot: &mut Option<Guard>, g: Guard) {
        if let Err(e) = self.put(slot, g.clone()) {
            log::warn!("cannot save the unlock guard: {e}");
            *slot = Some(g);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Guard>> {
        self.slot.lock().expect("guard")
    }

    /// The guard for `account` (empty when it belongs to another account).
    pub fn get(&self, account: &str) -> Guard {
        let mut slot = self.lock();
        let g = self.current(&mut slot);
        if g.account_id == account && !account.is_empty() {
            g
        } else {
            Guard::default()
        }
    }

    /// The master password was entered (unlock, sign-in, registration).
    pub fn record_password_unlock(&self, account: &str, now: i64) {
        let mut slot = self.lock();
        let mut g = self.current(&mut slot);
        if g.account_id != account {
            g = Guard {
                account_id: account.into(),
                ..Default::default()
            };
        }
        g.password_unlock_at = now;
        g.seen_at = g.seen_at.max(now);
        self.put_or_keep(&mut slot, g);
    }

    /// Remembers the latest clock reading (after any unlock).
    pub fn touch(&self, account: &str, now: i64) {
        let mut slot = self.lock();
        let mut g = self.current(&mut slot);
        if g.account_id != account || now <= g.seen_at {
            return;
        }
        g.seen_at = now;
        self.put_or_keep(&mut slot, g);
    }

    /// May biometrics unlock now? `password_this_run`: the master password
    /// was entered since the app started; `at_start`: the setting
    /// "启动时可直接用生物识别解锁".
    pub fn quick_allowed(
        &self,
        account: &str,
        now: i64,
        password_this_run: bool,
        at_start: bool,
    ) -> Result<(), Stale> {
        fresh(&self.get(account), now)?;
        if !password_this_run && !at_start {
            return Err(Stale::Restarted);
        }
        Ok(())
    }

    pub fn pin_status(&self, account: &str, now: i64) -> PinStatus {
        let g = self.get(account);
        let set = g.pin.is_some();
        PinStatus {
            supported: self.persistent(),
            set,
            usable: set && fresh(&g, now).is_ok(),
            tries_left: g
                .pin
                .map(|p| PIN_MAX_TRIES.saturating_sub(p.tries))
                .unwrap_or(0),
        }
    }

    /// Stores a new PIN blob (replacing any). Needs the credential store and
    /// a recent master-password unlock.
    pub fn set_pin(&self, account: &str, blob: PinBlob, now: i64) -> Result<(), String> {
        if !self.persistent() {
            return Err("系统凭据存储不可用，这台设备不能设置 PIN".into());
        }
        let mut slot = self.lock();
        let mut g = self.current(&mut slot);
        if g.account_id != account || blob.account_id != account {
            return Err(Stale::NoPassword.message().into());
        }
        fresh(&g, now).map_err(|s| s.message().to_string())?;
        g.pin = Some(PinState { blob, tries: 0 });
        self.put(&mut slot, g)
    }

    /// Deletes the PIN (settings, a master-password change).
    pub fn remove_pin(&self) -> Result<(), String> {
        let mut slot = self.lock();
        let mut g = self.current(&mut slot);
        if g.pin.is_none() {
            return Ok(());
        }
        g.pin = None;
        self.put(&mut slot, g)
    }

    /// Signing out: everything goes.
    pub fn forget(&self) {
        let mut slot = self.lock();
        *slot = Some(Guard::default());
        if let Some(s) = &self.store {
            if let Err(e) = s.delete() {
                log::warn!("cannot delete the unlock guard: {e}");
            }
        }
    }

    /// One PIN try. Counts it (and saves the count) first, then runs
    /// `check` (Argon2, the core opens the blob); resets the count on
    /// success; deletes the PIN after the last allowed wrong try. Tries are
    /// serialized (the guard stays locked during `check`).
    pub fn try_pin(
        &self,
        account: &str,
        now: i64,
        check: impl FnOnce(&PinBlob) -> Result<(), CoreError>,
    ) -> Result<(), PinError> {
        let mut slot = self.lock();
        let mut g = self.current(&mut slot);
        if g.account_id != account {
            return Err(PinError::NotSet);
        }
        let Some(mut pin) = g.pin.clone() else {
            return Err(PinError::NotSet);
        };
        fresh(&g, now).map_err(PinError::Stale)?;
        if pin.tries >= PIN_MAX_TRIES {
            g.pin = None;
            let _ = self.put(&mut slot, g);
            return Err(PinError::Wiped);
        }
        pin.tries += 1;
        g.pin = Some(pin.clone());
        self.put(&mut slot, g.clone()).map_err(PinError::Store)?;
        match check(&pin.blob) {
            Ok(()) => {
                pin.tries = 0;
                g.pin = Some(pin);
                g.seen_at = g.seen_at.max(now);
                if let Err(e) = self.put(&mut slot, g) {
                    log::warn!("cannot reset the PIN tries: {e}");
                }
                Ok(())
            }
            Err(CoreError::WrongPassword) => {
                if pin.tries >= PIN_MAX_TRIES {
                    g.pin = None;
                    if let Err(e) = self.put(&mut slot, g) {
                        log::warn!("cannot delete the PIN: {e}");
                    }
                    Err(PinError::Wiped)
                } else {
                    Err(PinError::Wrong {
                        left: PIN_MAX_TRIES - pin.tries,
                    })
                }
            }
            Err(e) => {
                // not a wrong PIN (locked, a damaged blob): do not count it
                pin.tries -= 1;
                g.pin = Some(pin);
                let _ = self.put(&mut slot, g);
                Err(PinError::Core(e.code().into(), e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const A: &str = "0192f0c0-0000-7000-8000-000000000001";
    const DAY: i64 = 24 * 60 * 60 * 1000;

    /// An in-memory credential store that can fail on purpose and counts writes.
    #[derive(Default)]
    struct Mem {
        data: Mutex<Option<Vec<u8>>>,
        fail_save: std::sync::atomic::AtomicBool,
        saves: std::sync::atomic::AtomicUsize,
    }

    impl SecretStore for Arc<Mem> {
        fn load(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.data.lock().unwrap().clone())
        }
        fn save(&self, d: &[u8]) -> Result<(), String> {
            if self.fail_save.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("store unavailable".into());
            }
            self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.data.lock().unwrap() = Some(d.to_vec());
            Ok(())
        }
        fn delete(&self) -> Result<(), String> {
            *self.data.lock().unwrap() = None;
            Ok(())
        }
    }

    impl Mem {
        fn stored(&self) -> Guard {
            serde_json::from_slice(self.data.lock().unwrap().as_deref().unwrap()).unwrap()
        }
    }

    fn blob() -> PinBlob {
        PinBlob {
            version: 1,
            account_id: A.into(),
            salt: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            kdf: npw_crypto::KdfParams::insecure_for_tests(),
            wrapped: "x".into(),
        }
    }

    fn guards() -> (Arc<Mem>, Guards) {
        let m = Arc::new(Mem::default());
        (m.clone(), Guards::new(Some(Box::new(m))))
    }

    #[test]
    fn fourteen_days_and_the_clock() {
        let now = 100 * DAY;
        let g = |at: i64, seen: i64| Guard {
            account_id: A.into(),
            password_unlock_at: at,
            seen_at: seen,
            pin: None,
        };
        assert_eq!(fresh(&Guard::default(), now), Err(Stale::NoPassword));
        assert_eq!(fresh(&g(now - DAY, now - DAY), now), Ok(()));
        assert_eq!(fresh(&g(now - 14 * DAY + 1, now), now), Ok(()));
        assert_eq!(fresh(&g(now - 14 * DAY, now), now), Err(Stale::Expired));
        // the clock went back past the latest reading: suspended
        assert_eq!(fresh(&g(now - DAY, now + DAY), now), Err(Stale::ClockBack));
        assert_eq!(fresh(&g(now + DAY, now + DAY), now), Err(Stale::ClockBack));
        // a few minutes back (time sync) is fine
        assert_eq!(fresh(&g(now - DAY, now + 60_000), now), Ok(()));
    }

    #[test]
    fn biometrics_at_start_follow_the_setting() {
        let (_, gs) = guards();
        let now = 50 * DAY;
        assert_eq!(gs.quick_allowed(A, now, true, true), Err(Stale::NoPassword));
        gs.record_password_unlock(A, now - DAY);
        assert_eq!(gs.quick_allowed(A, now, true, false), Ok(()));
        assert_eq!(gs.quick_allowed(A, now, false, true), Ok(()));
        assert_eq!(
            gs.quick_allowed(A, now, false, false),
            Err(Stale::Restarted)
        );
        assert_eq!(
            gs.quick_allowed(A, now + 13 * DAY, false, true),
            Err(Stale::Expired)
        );
        // another account on this device
        assert_eq!(
            gs.quick_allowed("other", now, true, true),
            Err(Stale::NoPassword)
        );
    }

    #[test]
    fn the_guard_survives_a_restart_and_a_clock_set_back() {
        let (m, gs) = guards();
        let now = 10 * DAY;
        gs.record_password_unlock(A, now);
        gs.touch(A, now + 3 * DAY);
        // a new run reads the credential store
        let again = Guards::new(Some(Box::new(m.clone())));
        assert_eq!(again.get(A).password_unlock_at, now);
        assert_eq!(again.get(A).seen_at, now + 3 * DAY);
        assert_eq!(
            again.quick_allowed(A, now + DAY, false, true),
            Err(Stale::ClockBack)
        );
        assert_eq!(again.quick_allowed(A, now + 3 * DAY, false, true), Ok(()));
    }

    #[test]
    fn memory_only_without_a_credential_store() {
        let gs = Guards::new(None);
        let now = 5 * DAY;
        gs.record_password_unlock(A, now);
        assert_eq!(gs.quick_allowed(A, now, true, false), Ok(()));
        assert!(!gs.pin_status(A, now).supported);
        assert!(gs.set_pin(A, blob(), now).is_err());
        // a restart forgets it
        assert_eq!(
            Guards::new(None).quick_allowed(A, now, false, true),
            Err(Stale::NoPassword)
        );
    }

    #[test]
    fn pin_needs_a_recent_password_and_the_right_account() {
        let (_, gs) = guards();
        let now = 30 * DAY;
        assert!(gs.set_pin(A, blob(), now).is_err(), "no password yet");
        gs.record_password_unlock(A, now);
        let mut other = blob();
        other.account_id = "other".into();
        assert!(gs.set_pin(A, other, now).is_err());
        gs.set_pin(A, blob(), now).unwrap();
        let st = gs.pin_status(A, now);
        assert!(st.set && st.usable && st.supported);
        assert_eq!(st.tries_left, PIN_MAX_TRIES);
        // suspended after 14 days, but still set
        let st = gs.pin_status(A, now + 14 * DAY);
        assert!(st.set && !st.usable);
        assert_eq!(
            gs.try_pin(A, now + 14 * DAY, |_| Ok(())),
            Err(PinError::Stale(Stale::Expired))
        );
        // the password again: usable again
        gs.record_password_unlock(A, now + 14 * DAY);
        assert_eq!(gs.try_pin(A, now + 14 * DAY, |_| Ok(())), Ok(()));
        // a new password unlock by another account drops this PIN
        gs.record_password_unlock("other", now + 15 * DAY);
        assert!(!gs.pin_status(A, now + 15 * DAY).set);
    }

    #[test]
    fn five_wrong_tries_delete_the_pin_and_success_resets_the_count() {
        let (m, gs) = guards();
        let now = 3 * DAY;
        gs.record_password_unlock(A, now);
        gs.set_pin(A, blob(), now).unwrap();
        let wrong = |_: &PinBlob| Err(CoreError::WrongPassword);
        assert_eq!(gs.try_pin(A, now, wrong), Err(PinError::Wrong { left: 4 }));
        assert_eq!(gs.try_pin(A, now, wrong), Err(PinError::Wrong { left: 3 }));
        assert_eq!(m.stored().pin.unwrap().tries, 2);
        // a right PIN resets the count
        assert_eq!(gs.try_pin(A, now, |_| Ok(())), Ok(()));
        assert_eq!(m.stored().pin.unwrap().tries, 0);
        for left in (1..PIN_MAX_TRIES).rev() {
            assert_eq!(gs.try_pin(A, now, wrong), Err(PinError::Wrong { left }));
        }
        assert_eq!(gs.try_pin(A, now, wrong), Err(PinError::Wiped));
        assert!(m.stored().pin.is_none());
        assert!(!gs.pin_status(A, now).set);
        assert_eq!(gs.try_pin(A, now, |_| Ok(())), Err(PinError::NotSet));
        // the password unlock record stays
        assert!(m.stored().password_unlock_at > 0);
    }

    #[test]
    fn a_try_is_saved_before_the_check() {
        let (m, gs) = guards();
        let now = 3 * DAY;
        gs.record_password_unlock(A, now);
        gs.set_pin(A, blob(), now).unwrap();
        // the app dies during the check: the try is already counted
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = gs.try_pin(A, now, |_| -> Result<(), CoreError> {
                assert_eq!(m.stored().pin.as_ref().unwrap().tries, 1);
                panic!("killed");
            });
        }));
        assert!(r.is_err());
        let restarted = Guards::new(Some(Box::new(m.clone())));
        assert_eq!(restarted.pin_status(A, now).tries_left, PIN_MAX_TRIES - 1);

        // the count cannot be saved: no try at all
        m.fail_save.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut checked = false;
        let r = restarted.try_pin(A, now, |_| {
            checked = true;
            Ok(())
        });
        assert!(matches!(r, Err(PinError::Store(_))));
        assert!(!checked);
        m.fail_save
            .store(false, std::sync::atomic::Ordering::SeqCst);

        // other errors (locked, damaged blob) are not counted
        let r = restarted.try_pin(A, now, |_| Err(CoreError::Locked));
        assert!(matches!(r, Err(PinError::Core(ref c, _)) if c == "locked"));
        assert_eq!(restarted.pin_status(A, now).tries_left, PIN_MAX_TRIES - 1);
    }

    #[test]
    fn a_failing_store_keeps_the_password_time_for_this_run_only() {
        let (m, gs) = guards();
        m.fail_save.store(true, std::sync::atomic::Ordering::SeqCst);
        gs.record_password_unlock(A, DAY);
        assert_eq!(gs.quick_allowed(A, DAY, true, false), Ok(()));
        assert!(m.data.lock().unwrap().is_none());
        assert!(gs.set_pin(A, blob(), DAY).is_err());
    }

    #[test]
    fn a_stored_count_at_the_limit_wipes_without_trying() {
        let (m, gs) = guards();
        let now = DAY;
        gs.record_password_unlock(A, now);
        gs.set_pin(A, blob(), now).unwrap();
        let mut g = m.stored();
        g.pin.as_mut().unwrap().tries = PIN_MAX_TRIES;
        m.save(&serde_json::to_vec(&g).unwrap()).unwrap();
        let fresh_run = Guards::new(Some(Box::new(m.clone())));
        let mut checked = false;
        assert_eq!(
            fresh_run.try_pin(A, now, |_| {
                checked = true;
                Ok(())
            }),
            Err(PinError::Wiped)
        );
        assert!(!checked);
        assert!(m.stored().pin.is_none());
    }

    #[test]
    fn remove_and_forget() {
        let (m, gs) = guards();
        let now = DAY;
        gs.record_password_unlock(A, now);
        gs.set_pin(A, blob(), now).unwrap();
        gs.remove_pin().unwrap();
        assert!(m.stored().pin.is_none());
        assert_eq!(m.stored().password_unlock_at, now);
        gs.forget();
        assert!(m.data.lock().unwrap().is_none());
        assert_eq!(gs.get(A), Guard::default());
    }
}
