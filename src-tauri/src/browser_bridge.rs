//! Browser bridge (design doc §4.5, §10.3): "the desktop app is unlocked ⇒
//! the extension can unlock", over Chrome / Edge native messaging.
//!
//! ```text
//! extension ──native messaging (stdio)──► nyapassword-desktop.exe chrome-extension://<id>/   (host mode, run_host)
//!                                                  │ local pipe / socket, current user only (ipc.rs)
//!                                                  ▼
//!                                        the running app (serve / handle_request)
//! ```
//!
//! Protocol (JSON; every request may carry `rid`, echoed in its reply):
//! - `hello` → `{type: "hello", version, signed_in, unlocked}`.
//! - `pair {id, public_key, account_id, server_url, browser}`: the extension's
//!   long-term P-256 public key. The app shows a window with a six-digit code
//!   (also shown by the extension, [`pairing_code`]); only if the user allows
//!   it, and only for the account this app is signed in to, is the key stored
//!   (`settings.json`, public data only) → `paired`.
//! - `unlock {pairing_id, account_id, server_url, nonce, interactive?}`: if
//!   the pairing belongs to this extension and this account and this app is
//!   unlocked, the account key is sealed to the pairing key ([`seal`]:
//!   ephemeral ECDH P-256, HKDF-SHA256 salted with the extension's nonce,
//!   AES-256-GCM) → `unlock {eph_public_key, iv, ciphertext}`. The extension
//!   opens it with its non-extractable WebCrypto key and calls
//!   `unlockWithKey`, which itself checks the key against the account (a
//!   wrong key cannot unlock anything).
//!   While this app is locked: `locked`, unless `interactive` (the user
//!   opened the popup or clicked in the inline menu). Then the app brings its
//!   own unlock screen to the front (master password, Windows Hello or PIN,
//!   the user's choice) and answers once it is unlocked; `timeout` after
//!   [`UNLOCK_WAIT`], `busy` while another such request waits (one at a time).
//! - `unpair {pairing_id}` → `unpaired`.
//! - Pushed by the app: `{type: "locked"}` when it locks, `{type: "unlocked"}`
//!   when it unlocks.
//!
//! The host process forwards the extension origin Chrome gives it as a first
//! `_origin` frame; the app also checks it against the allowed extension IDs.
//! When the app is not running, the host answers `app_not_running`, except to
//! an interactive `unlock`: it starts the app and relays that request to it
//! ([`host_without_app`]).

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use npw_core::LockState;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc};
use zeroize::Zeroizing;

use crate::ipc::{self, Listener};
use crate::platform::NATIVE_HOST_NAME;
use crate::prompts::{Decision, PromptInfo};
use crate::settings::Pairing;
use crate::state::{now_ms, show_main, AppState, EVENT_UNLOCK_REQUEST};

pub const PROTOCOL_VERSION: u32 = 1;
const UNLOCK_INFO: &[u8] = b"npw/browser-bridge/unlock/v1";
const PAIR_INFO: &[u8] = b"npw/browser-bridge/pair/v1";
/// Largest message either way (Chrome's limit towards the browser is 1 MB).
const MAX_MESSAGE: usize = 64 * 1024;
const PAIR_TIMEOUT: Duration = Duration::from_secs(120);
/// How long an interactive unlock request waits for the user to unlock the app.
pub const UNLOCK_WAIT: Duration = Duration::from_secs(120);
/// Host mode: how long to wait for an app it started to accept connections.
const APP_START_WAIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------- waiting for an unlock

/// One interactive unlock request at a time, woken by every unlock of the app.
#[derive(Default)]
pub struct UnlockWait {
    pending: AtomicBool,
    unlocks: Mutex<u64>,
    cv: Condvar,
}

/// The slot of the one pending request; freed on drop.
pub struct Pending<'a>(&'a UnlockWait);

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.pending.store(false, Ordering::SeqCst);
    }
}

impl UnlockWait {
    /// Takes the slot, or `None` while another request waits.
    pub fn begin(&self) -> Option<Pending<'_>> {
        self.pending
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Pending(self))
    }

    #[cfg(test)]
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::SeqCst)
    }

    /// The app was unlocked.
    pub fn notify(&self) {
        *self.unlocks.lock().expect("unlocks") += 1;
        self.cv.notify_all();
    }

    /// Blocks until `ready()` (re-checked on every [`UnlockWait::notify`] and
    /// at least every 250 ms) or `timeout`; whether it became ready.
    pub fn wait_until(&self, timeout: Duration, ready: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        let mut g = self.unlocks.lock().expect("unlocks");
        loop {
            if ready() {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let step = (deadline - now).min(Duration::from_millis(250));
            g = self.cv.wait_timeout(g, step).expect("unlocks").0;
        }
    }
}

// ---------------------------------------------------------------- crypto

/// The six digits both sides show while pairing (a short authentication
/// string of the extension's public key).
pub fn pairing_code(ext_public: &[u8]) -> String {
    let h = Sha256::digest([PAIR_INFO, ext_public].concat());
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    format!("{n:06}")
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Sealed {
    /// SEC1 uncompressed, base64.
    pub eph_public_key: String,
    pub iv: String,
    pub ciphertext: String,
}

fn derive_key(
    shared: &[u8],
    nonce: &[u8],
    eph_public: &[u8],
    ext_public: &[u8],
    account_id: &str,
) -> Zeroizing<[u8; 32]> {
    let info = [UNLOCK_INFO, eph_public, ext_public, account_id.as_bytes()].concat();
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(nonce), shared)
        .expand(&info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    okm
}

fn aad(account_id: &str) -> Vec<u8> {
    [UNLOCK_INFO, account_id.as_bytes()].concat()
}

fn check_nonce(nonce: &[u8]) -> Result<(), String> {
    if (16..=64).contains(&nonce.len()) {
        Ok(())
    } else {
        Err("nonce must be 16..64 bytes".into())
    }
}

fn seal_with(
    eph: &p256::SecretKey,
    iv: &[u8; 12],
    ext_public: &[u8],
    account_id: &str,
    nonce: &[u8],
    secret: &[u8],
) -> Result<Sealed, String> {
    check_nonce(nonce)?;
    let ext = p256::PublicKey::from_sec1_bytes(ext_public).map_err(|_| "bad public key")?;
    let shared = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), ext.as_affine());
    let eph_public = eph.public_key().to_encoded_point(false).as_bytes().to_vec();
    let key = derive_key(
        shared.raw_secret_bytes(),
        nonce,
        &eph_public,
        ext_public,
        account_id,
    );
    let ct = Aes256Gcm::new_from_slice(key.as_ref())
        .expect("32-byte key")
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: secret,
                aad: &aad(account_id),
            },
        )
        .map_err(|_| "encryption failed")?;
    Ok(Sealed {
        eph_public_key: B64.encode(&eph_public),
        iv: B64.encode(iv),
        ciphertext: B64.encode(ct),
    })
}

/// Seals `secret` (the account key) so that only the holder of the private
/// key of `ext_public` can open it, bound to the account and the request nonce.
pub fn seal(
    ext_public: &[u8],
    account_id: &str,
    nonce: &[u8],
    secret: &[u8],
) -> Result<Sealed, String> {
    let eph = loop {
        let b = Zeroizing::new(npw_crypto::random_bytes::<32>());
        if let Ok(k) = p256::SecretKey::from_slice(b.as_ref()) {
            break k;
        }
    };
    let iv = npw_crypto::random_bytes::<12>();
    seal_with(&eph, &iv, ext_public, account_id, nonce, secret)
}

// ---------------------------------------------------------------- requests

/// What the protocol needs from the app (a trait so it can be tested without one).
pub trait Host: Send + Sync + 'static {
    fn lock_state(&self) -> LockState;
    /// The account key, only while unlocked.
    fn account_key(&self) -> Option<Zeroizing<Vec<u8>>>;
    fn allowed_extension(&self, extension_id: &str) -> bool;
    fn pairings(&self) -> Vec<Pairing>;
    fn save_pairing(&self, p: Pairing);
    fn remove_pairing(&self, id: &str);
    fn touch_pairing(&self, id: &str);
    /// Asks the user (blocking); `true` = allowed.
    fn confirm_pairing(&self, browser: &str, extension_id: &str, code: &str) -> bool;
    /// `active`: brings the app's own unlock screen to the front and focuses
    /// it, saying that the extension `browser` asks; `false`: the request ended.
    fn show_unlock(&self, browser: &str, active: bool);
    /// Woken by every unlock of the app.
    fn unlock_wait(&self) -> &UnlockWait;
    fn unlock_timeout(&self) -> Duration {
        UNLOCK_WAIT
    }
}

fn error(code: &str, message: &str) -> Value {
    json!({"type": "error", "code": code, "message": message})
}

fn norm_server(s: &str) -> String {
    s.trim().trim_end_matches('/').to_lowercase()
}

/// The request is for the account this app is signed in to.
fn same_account(st: &LockState, req: &Value) -> Result<(), Value> {
    if !st.signed_in {
        return Err(error("not_signed_in", "NyaPassword 桌面端还没有登录账户"));
    }
    let account = req["account_id"].as_str().unwrap_or_default();
    let server = req["server_url"].as_str().unwrap_or_default();
    if account != st.account_id || norm_server(server) != norm_server(&st.server_url) {
        return Err(error(
            "account_mismatch",
            "扩展和桌面端登录的不是同一个账户（或服务器不同）",
        ));
    }
    Ok(())
}

/// Extension ID from `chrome-extension://<id>/`.
pub fn extension_id(origin: &str) -> Option<String> {
    let id = origin
        .trim()
        .strip_prefix("chrome-extension://")?
        .trim_end_matches('/');
    valid_extension_id(id).then(|| id.to_string())
}

/// The published extension: Chrome Web Store and Edge Add-ons. Always
/// allowed; settings only add other IDs (an unpacked or self-built extension).
pub const STORE_EXTENSION_IDS: &[&str] = &[
    "eiggbhfjinenmhokcjadonmbaecjiinl", // Chrome Web Store
    "iboelkeoigjhfkfnoknclhachocjflnl", // Edge Add-ons
];

/// The store extensions followed by the IDs from settings, without duplicates.
pub fn allowed_extension_ids(extra: &[String]) -> Vec<String> {
    let mut ids: Vec<String> = STORE_EXTENSION_IDS.iter().map(|s| s.to_string()).collect();
    for id in extra {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    ids
}

/// Chrome extension IDs: 32 letters a–p.
pub fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

fn b64_arg(req: &Value, key: &str) -> Result<Vec<u8>, Value> {
    req[key]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .ok_or_else(|| error("invalid", &format!("missing or bad {key}")))
}

/// Answers one request from the extension `extension_id` (blocking: pairing waits for the user).
pub fn handle_request<H: Host + ?Sized>(host: &H, extension_id: &str, req: &Value) -> Value {
    let mut reply = match req["type"].as_str().unwrap_or_default() {
        "hello" => {
            let st = host.lock_state();
            json!({
                "type": "hello",
                "version": PROTOCOL_VERSION,
                "app_version": env!("CARGO_PKG_VERSION"),
                "signed_in": st.signed_in,
                "unlocked": st.unlocked,
            })
        }
        "pair" => pair(host, extension_id, req).unwrap_or_else(|e| e),
        "unlock" => unlock(host, extension_id, req).unwrap_or_else(|e| e),
        "unpair" => {
            let id = req["pairing_id"].as_str().unwrap_or_default();
            if host
                .pairings()
                .iter()
                .any(|p| p.id == id && p.extension_id == extension_id)
            {
                host.remove_pairing(id);
            }
            json!({"type": "unpaired"})
        }
        _ => error("invalid", "unknown request"),
    };
    if let Some(rid) = req.get("rid") {
        reply["rid"] = rid.clone();
    }
    reply
}

fn pair<H: Host + ?Sized>(host: &H, extension_id: &str, req: &Value) -> Result<Value, Value> {
    same_account(&host.lock_state(), req)?;
    let id = req["id"].as_str().unwrap_or_default().to_string();
    if id.is_empty() || id.len() > 64 {
        return Err(error("invalid", "bad pairing id"));
    }
    let public = b64_arg(req, "public_key")?;
    p256::PublicKey::from_sec1_bytes(&public).map_err(|_| error("invalid", "bad public key"))?;
    let public_b64 = B64.encode(&public);
    if host
        .pairings()
        .iter()
        .any(|p| p.id == id && p.public_key == public_b64 && p.extension_id == extension_id)
    {
        return Ok(json!({"type": "paired", "id": id}));
    }
    let browser: String = req["browser"]
        .as_str()
        .unwrap_or("浏览器")
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    if !host.confirm_pairing(&browser, extension_id, &pairing_code(&public)) {
        return Err(error("denied", "桌面端拒绝了配对"));
    }
    let st = host.lock_state();
    host.save_pairing(Pairing {
        id: id.clone(),
        name: browser,
        public_key: public_b64,
        extension_id: extension_id.to_string(),
        account_id: st.account_id,
        created_at: now_ms(),
        last_used_at: 0,
    });
    Ok(json!({"type": "paired", "id": id}))
}

/// Whether a request asks the locked app to show its unlock screen.
pub fn is_interactive_unlock(req: &Value) -> bool {
    req["type"] == "unlock" && req["interactive"] == true
}

/// Shows the app's unlock screen and waits (one request at a time) until the
/// user unlocks it. The new lock state, or `busy` / `timeout`.
fn wait_for_unlock<H: Host + ?Sized>(host: &H, browser: &str) -> Result<LockState, Value> {
    let w = host.unlock_wait();
    let Some(_slot) = w.begin() else {
        return Err(error(
            "busy",
            "桌面端正在等待解锁（另一个请求），请在桌面端完成解锁",
        ));
    };
    host.show_unlock(browser, true);
    let unlocked = w.wait_until(host.unlock_timeout(), || host.lock_state().unlocked);
    host.show_unlock(browser, false);
    if unlocked {
        Ok(host.lock_state())
    } else {
        Err(error("timeout", "桌面端没有在 2 分钟内解锁"))
    }
}

fn unlock<H: Host + ?Sized>(host: &H, extension_id: &str, req: &Value) -> Result<Value, Value> {
    let mut st = host.lock_state();
    same_account(&st, req)?;
    let pid = req["pairing_id"].as_str().unwrap_or_default();
    let pairing = host
        .pairings()
        .into_iter()
        .find(|p| p.id == pid && p.extension_id == extension_id && p.account_id == st.account_id)
        .ok_or_else(|| error("not_paired", "这个扩展还没有与桌面端配对"))?;
    let nonce = b64_arg(req, "nonce")?;
    check_nonce(&nonce).map_err(|e| error("invalid", &e))?;
    if !st.unlocked {
        // only an explicit action in the extension may bring the app forward
        if !is_interactive_unlock(req) {
            return Err(error("locked", "NyaPassword 桌面端已锁定"));
        }
        st = wait_for_unlock(host, &pairing.name)?;
        // still the same account (it could have signed out meanwhile)
        same_account(&st, req)?;
    }
    let public = B64
        .decode(&pairing.public_key)
        .map_err(|_| error("invalid", "stored key"))?;
    let ak = host
        .account_key()
        .ok_or_else(|| error("locked", "NyaPassword 桌面端已锁定"))?;
    let sealed = seal(&public, &st.account_id, &nonce, &ak).map_err(|e| error("invalid", &e))?;
    host.touch_pairing(&pairing.id);
    let mut v = serde_json::to_value(sealed).expect("json");
    v["type"] = "unlock".into();
    Ok(v)
}

// ---------------------------------------------------------------- the app side

/// The local endpoint the host process connects to.
pub fn endpoint() -> Result<String, String> {
    #[cfg(windows)]
    {
        Ok(format!(
            "{NATIVE_HOST_NAME}.browser-bridge.{}",
            crate::platform::windows::current_user_sid()?
        ))
    }
    #[cfg(unix)]
    {
        Ok(unix_data_dir()?
            .join("browser-bridge.sock")
            .display()
            .to_string())
    }
}

/// The app's data folder computed without Tauri (the host process has no app
/// context); the same rule as Tauri's `app_local_data_dir`.
#[cfg(unix)]
fn unix_data_dir() -> Result<std::path::PathBuf, String> {
    use std::path::PathBuf;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set")?;
    let base = if cfg!(target_os = "macos") {
        home.join("Library/Application Support")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".local/share"))
    };
    Ok(base.join(NATIVE_HOST_NAME))
}

/// Serves host connections until aborted (connections end with it).
pub async fn serve<H: Host>(
    mut listener: Listener,
    host: Arc<H>,
    events: broadcast::Sender<String>,
) {
    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((conn, _peer)) => {
                    conns.spawn(connection(conn, host.clone(), events.subscribe()));
                }
                Err(e) => {
                    log::warn!("browser bridge: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

async fn connection<H: Host>(
    conn: ipc::Conn,
    host: Arc<H>,
    mut events: broadcast::Receiver<String>,
) {
    let (mut r, mut w) = tokio::io::split(conn);
    // the first frame names the extension (from the host process)
    let origin = match ipc::read_frame(&mut r, MAX_MESSAGE).await {
        Ok(Some(f)) => serde_json::from_slice::<Value>(&f).ok(),
        _ => None,
    };
    let ext = origin
        .as_ref()
        .filter(|v| v["type"] == "_origin")
        .and_then(|v| v["origin"].as_str())
        .and_then(extension_id);
    let Some(ext) = ext.filter(|id| host.allowed_extension(id)) else {
        let e = error("forbidden", "这个扩展不在桌面端允许的扩展 ID 中");
        let _ = ipc::write_frame(&mut w, e.to_string().as_bytes()).await;
        return;
    };
    // reads in their own task: a read must never be cancelled half-way
    let (in_tx, mut in_rx) = mpsc::channel::<Value>(8);
    let reader = tokio::spawn(async move {
        while let Ok(Some(f)) = ipc::read_frame(&mut r, MAX_MESSAGE).await {
            let v = serde_json::from_slice(&f).unwrap_or(Value::Null);
            if in_tx.send(v).await.is_err() {
                break;
            }
        }
    });
    let (out_tx, mut out_rx) = mpsc::channel::<Value>(8);
    loop {
        let out = tokio::select! {
            req = in_rx.recv() => match req {
                Some(req) => {
                    let (h, e, tx) = (host.clone(), ext.clone(), out_tx.clone());
                    tokio::task::spawn_blocking(move || {
                        let reply = handle_request(&*h, &e, &req);
                        let _ = tx.blocking_send(reply);
                    });
                    continue;
                }
                None => break,
            },
            reply = out_rx.recv() => match reply {
                Some(v) => v,
                None => break,
            },
            ev = events.recv() => match ev {
                Ok(ev) => json!({"type": ev}),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            },
        };
        if ipc::write_frame(&mut w, out.to_string().as_bytes())
            .await
            .is_err()
        {
            break;
        }
    }
    reader.abort();
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct BridgeStatus {
    pub enabled: bool,
    pub running: bool,
    /// Where the host manifest was registered.
    pub registered: Vec<String>,
    pub error: String,
}

pub struct BrowserBridge {
    events: broadcast::Sender<String>,
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    status: Mutex<BridgeStatus>,
    /// The interactive unlock request waiting for the user (one at a time).
    pub wait: UnlockWait,
}

impl Default for BrowserBridge {
    fn default() -> Self {
        Self {
            events: broadcast::channel(16).0,
            task: Mutex::new(None),
            status: Mutex::new(BridgeStatus::default()),
            wait: UnlockWait::default(),
        }
    }
}

impl BrowserBridge {
    /// Tells connected extensions `locked` / `unlocked`.
    pub fn notify(&self, event: &str) {
        let _ = self.events.send(event.to_string());
    }

    pub fn status(&self) -> BridgeStatus {
        self.status.lock().expect("status").clone()
    }

    fn stop(&self) {
        if let Some(t) = self.task.lock().expect("task").take() {
            t.abort();
        }
    }
}

struct AppHost {
    app: AppHandle,
}

impl Host for AppHost {
    fn lock_state(&self) -> LockState {
        let st = self.app.state::<AppState>();
        st.client()
            .map(|c| c.lock_state())
            .unwrap_or_else(|_| LockState {
                signed_in: false,
                unlocked: false,
                login: String::new(),
                server_url: String::new(),
                account_id: String::new(),
                device_id: String::new(),
                last_sync_at: 0,
            })
    }

    fn account_key(&self) -> Option<Zeroizing<Vec<u8>>> {
        let st = self.app.state::<AppState>();
        st.client()
            .ok()?
            .quick_unlock_key()
            .ok()
            .map(Zeroizing::new)
    }

    fn allowed_extension(&self, extension_id: &str) -> bool {
        let st = self.app.state::<AppState>();
        let s = st.settings().browser_bridge;
        s.enabled
            && allowed_extension_ids(&s.extension_ids)
                .iter()
                .any(|i| i == extension_id)
    }

    fn pairings(&self) -> Vec<Pairing> {
        self.app
            .state::<AppState>()
            .settings()
            .browser_bridge
            .pairings
    }

    fn save_pairing(&self, p: Pairing) {
        self.app.state::<AppState>().update_settings(|s| {
            s.browser_bridge.pairings.retain(|x| x.id != p.id);
            s.browser_bridge.pairings.push(p);
        });
    }

    fn remove_pairing(&self, id: &str) {
        self.app
            .state::<AppState>()
            .update_settings(|s| s.browser_bridge.pairings.retain(|x| x.id != id));
    }

    fn touch_pairing(&self, id: &str) {
        let now = now_ms();
        self.app.state::<AppState>().update_settings(|s| {
            if let Some(p) = s.browser_bridge.pairings.iter_mut().find(|p| p.id == id) {
                p.last_used_at = now;
            }
        });
    }

    fn confirm_pairing(&self, browser: &str, extension_id: &str, code: &str) -> bool {
        let st = self.app.state::<AppState>();
        let info = PromptInfo::Pair {
            browser: browser.into(),
            extension_id: extension_id.into(),
            code: code.into(),
        };
        st.prompts.ask(&self.app, info, PAIR_TIMEOUT) != Decision::Deny
    }

    fn show_unlock(&self, browser: &str, active: bool) {
        // the lock screen shows who is asking (bridge-tauri.ts)
        let _ = self
            .app
            .emit(EVENT_UNLOCK_REQUEST, if active { browser } else { "" });
        if !active {
            return;
        }
        show_main(&self.app);
        if let Some(w) = self.app.get_webview_window("main") {
            // Windows may refuse the focus to a background app: flash the taskbar then
            if !w.is_focused().unwrap_or(false) {
                let _ = w.request_user_attention(Some(tauri::UserAttentionType::Critical));
            }
        }
    }

    fn unlock_wait(&self) -> &UnlockWait {
        &self.app.state::<AppState>().inner().bridge.wait
    }
}

fn manifest(exe: &std::path::Path, extension_ids: &[String]) -> String {
    let origins: Vec<String> = extension_ids
        .iter()
        .map(|id| format!("chrome-extension://{id}/"))
        .collect();
    serde_json::to_string_pretty(&json!({
        "name": NATIVE_HOST_NAME,
        "description": "NyaPassword desktop app (unlocks the browser extension)",
        "path": exe.display().to_string(),
        "type": "stdio",
        "allowed_origins": origins,
    }))
    .expect("json")
}

/// Registers the host and serves it, or stops (and, when `unregister`,
/// removes the registration) to match the settings.
pub async fn apply(app: &AppHandle, unregister: bool) -> BridgeStatus {
    let st = app.state::<AppState>();
    st.bridge.stop();
    let s = st.settings().browser_bridge;
    let mut status = BridgeStatus {
        enabled: s.enabled,
        ..Default::default()
    };
    if !s.enabled {
        if unregister {
            st.platform.unregister_native_host(&st.dir);
        }
    } else {
        let ids = allowed_extension_ids(&s.extension_ids);
        let registered = st.platform.native_host_exe().and_then(|exe| {
            st.platform
                .register_native_host(&st.dir, &manifest(&exe, &ids))
        });
        match registered {
            Ok(r) => status.registered = r,
            Err(e) => status.error = format!("无法注册 Native Messaging 宿主：{e}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        match endpoint().and_then(|ep| Listener::bind(&ep).map_err(|e| format!("{ep}: {e}"))) {
            Ok(l) => {
                let host = Arc::new(AppHost { app: app.clone() });
                let task = tauri::async_runtime::spawn(serve(l, host, st.bridge.events.clone()));
                *st.bridge.task.lock().expect("task") = Some(task);
                status.running = true;
            }
            Err(e) => {
                if status.error.is_empty() {
                    status.error = format!("无法监听本地通道：{e}");
                }
            }
        }
    }
    *st.bridge.status.lock().expect("status") = status.clone();
    status
}

// ---------------------------------------------------------------- host mode

/// Native messaging framing: `u32` length in native byte order, then JSON.
async fn read_native<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too long",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

async fn write_native<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_ne_bytes());
    out.extend_from_slice(body);
    w.write_all(&out).await?;
    w.flush().await
}

/// Relays between the browser (`input` / `output`) and the app (`conn`)
/// until either side closes.
#[cfg(test)]
pub async fn relay<I, O>(input: I, output: O, conn: ipc::Conn, origin: &str) -> std::io::Result<()>
where
    I: AsyncRead + Unpin + Send + 'static,
    O: AsyncWrite + Unpin + Send + 'static,
{
    relay_with(input, output, conn, origin, None, || {}).await
}

/// [`relay`], first sending `first` (a request read before the app was
/// reachable); `on_interactive` runs before each interactive unlock request
/// goes up (Windows: lets the app take the foreground).
pub async fn relay_with<I, O>(
    mut input: I,
    mut output: O,
    conn: ipc::Conn,
    origin: &str,
    first: Option<Vec<u8>>,
    on_interactive: fn(),
) -> std::io::Result<()>
where
    I: AsyncRead + Unpin + Send + 'static,
    O: AsyncWrite + Unpin + Send + 'static,
{
    let interactive = |m: &[u8]| {
        serde_json::from_slice::<Value>(m)
            .map(|v| is_interactive_unlock(&v))
            .unwrap_or(false)
    };
    let (mut r, mut w) = tokio::io::split(conn);
    let hello = json!({"type": "_origin", "origin": origin}).to_string();
    ipc::write_frame(&mut w, hello.as_bytes()).await?;
    if let Some(m) = first {
        if interactive(&m) {
            on_interactive();
        }
        ipc::write_frame(&mut w, &m).await?;
    }
    let up = tokio::spawn(async move {
        while let Ok(Some(m)) = read_native(&mut input).await {
            if interactive(&m) {
                on_interactive();
            }
            if ipc::write_frame(&mut w, &m).await.is_err() {
                break;
            }
        }
    });
    let down = tokio::spawn(async move {
        while let Ok(Some(m)) = ipc::read_frame(&mut r, MAX_MESSAGE).await {
            if write_native(&mut output, &m).await.is_err() {
                break;
            }
        }
    });
    // whichever direction ends first ends the relay
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    Ok(())
}

fn not_running(req: &Value, message: &str) -> Vec<u8> {
    let mut e = error("app_not_running", message);
    if let Some(rid) = req.get("rid") {
        e["rid"] = rid.clone();
    }
    e.to_string().into_bytes()
}

/// Host mode while the app is not running (or not serving the bridge):
/// answers every request with `app_not_running`, except an interactive
/// unlock (the user opened the popup / clicked in the inline menu). That one
/// starts the app (`launch`: a normal start, single instance), waits for it
/// to accept connections (`connect`) and is then relayed like any request.
pub async fn host_without_app<I, O, L, C, F>(
    mut input: I,
    mut output: O,
    origin: &str,
    launch: L,
    connect: C,
    start_wait: Duration,
    on_interactive: fn(),
) -> std::io::Result<()>
where
    I: AsyncRead + Unpin + Send + 'static,
    O: AsyncWrite + Unpin + Send + 'static,
    L: Fn() -> Result<(), String>,
    C: Fn() -> F,
    F: Future<Output = std::io::Result<ipc::Conn>>,
{
    while let Some(m) = read_native(&mut input).await? {
        // the app may have been started since the last request
        if let Ok(conn) = connect().await {
            return relay_with(input, output, conn, origin, Some(m), on_interactive).await;
        }
        let req: Value = serde_json::from_slice(&m).unwrap_or(Value::Null);
        if !is_interactive_unlock(&req) {
            let e = not_running(&req, "NyaPassword 桌面端没有运行，或没有开启浏览器扩展联动");
            write_native(&mut output, &e).await?;
            continue;
        }
        // the started app must be allowed to come to the front
        on_interactive();
        let started = match launch() {
            Ok(()) => {
                let deadline = Instant::now() + start_wait;
                loop {
                    match connect().await {
                        Ok(c) => break Ok(c),
                        Err(_) if Instant::now() < deadline => {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                        Err(_) => break Err("桌面端已启动，但没有开启浏览器扩展联动".to_string()),
                    }
                }
            }
            Err(e) => Err(format!("无法启动 NyaPassword 桌面端：{e}")),
        };
        match started {
            Ok(conn) => {
                return relay_with(input, output, conn, origin, Some(m), on_interactive).await;
            }
            Err(msg) => write_native(&mut output, &not_running(&req, &msg)).await?,
        }
    }
    Ok(())
}

/// The browser started us as its native messaging host (`origin` =
/// `chrome-extension://<id>/`). Returns the process exit code.
pub fn run_host(origin: &str) -> i32 {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return 1,
    };
    let foreground: fn() = || crate::platform::native().allow_app_foreground();
    rt.block_on(async {
        let ep = match endpoint() {
            Ok(ep) => ep,
            Err(e) => {
                let e = error("app_not_running", &e).to_string();
                let _ = write_native(&mut tokio::io::stdout(), e.as_bytes()).await;
                return 0;
            }
        };
        let _ = match ipc::connect(&ep).await {
            Ok(conn) => {
                relay_with(
                    tokio::io::stdin(),
                    tokio::io::stdout(),
                    conn,
                    origin,
                    None,
                    foreground,
                )
                .await
            }
            Err(_) => {
                host_without_app(
                    tokio::io::stdin(),
                    tokio::io::stdout(),
                    origin,
                    || crate::platform::native().launch_app(),
                    || ipc::connect(&ep),
                    APP_START_WAIT,
                    foreground,
                )
                .await
            }
        };
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXT: &str = "abcdefghijklmnopabcdefghijklmnop";

    fn ext_key(seed: u8) -> p256::SecretKey {
        p256::SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    fn sec1(k: &p256::SecretKey) -> Vec<u8> {
        k.public_key().to_encoded_point(false).as_bytes().to_vec()
    }

    fn open(
        ext: &p256::SecretKey,
        s: &Sealed,
        account: &str,
        nonce: &[u8],
    ) -> Result<Vec<u8>, String> {
        let eph = B64.decode(&s.eph_public_key).unwrap();
        let eph_pk = p256::PublicKey::from_sec1_bytes(&eph).map_err(|e| e.to_string())?;
        let shared = p256::ecdh::diffie_hellman(ext.to_nonzero_scalar(), eph_pk.as_affine());
        let key = derive_key(shared.raw_secret_bytes(), nonce, &eph, &sec1(ext), account);
        Aes256Gcm::new_from_slice(key.as_ref())
            .unwrap()
            .decrypt(
                Nonce::from_slice(&B64.decode(&s.iv).unwrap()),
                Payload {
                    msg: &B64.decode(&s.ciphertext).unwrap(),
                    aad: &aad(account),
                },
            )
            .map_err(|_| "open failed".to_string())
    }

    #[test]
    fn seal_round_trip_and_binding() {
        let ext = ext_key(7);
        let nonce = [9u8; 32];
        let s = seal(&sec1(&ext), "acc-1", &nonce, b"account key bytes").unwrap();
        assert_eq!(
            open(&ext, &s, "acc-1", &nonce).unwrap(),
            b"account key bytes"
        );
        // another account, nonce or key: nothing
        assert!(open(&ext, &s, "acc-2", &nonce).is_err());
        assert!(open(&ext, &s, "acc-1", &[8u8; 32]).is_err());
        assert!(open(&ext_key(8), &s, "acc-1", &nonce).is_err());
        // fresh ephemeral key every time
        let s2 = seal(&sec1(&ext), "acc-1", &nonce, b"account key bytes").unwrap();
        assert_ne!(s.eph_public_key, s2.eph_public_key);
        assert!(seal(&sec1(&ext), "acc-1", &[1u8; 4], b"x").is_err());
        assert!(seal(b"not a key", "acc-1", &nonce, b"x").is_err());
    }

    /// Fixed values shared with the extension's TypeScript test
    /// (chrome/src/lib/desktop-link.test.ts), so both sides agree byte for byte.
    #[test]
    fn cross_language_vector() {
        let ext = ext_key(0x11);
        let eph = ext_key(0x22);
        let s = seal_with(
            &eph,
            &[0x33; 12],
            &sec1(&ext),
            "0190d5a4-0000-7000-8000-000000000001",
            &[0x44; 32],
            &[0x55; 32],
        )
        .unwrap();
        assert_eq!(B64.encode(sec1(&ext)), "BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q=");
        assert_eq!(s.eph_public_key, "BNZak5d8qj0bCBhS/1ennkZfFmBXcwS66tUF3TpIWJzzUBheiVNy32Ih6joTdVfkc/3bZ1XwW9UHw8Uz/OnJEoU=");
        assert_eq!(
            s.ciphertext,
            "JixJdUj5r48Fx+YDC1Ib9KrF2mco+vG4OuilmrOift7VWe8h4qRqshq047wJrhaX"
        );
        assert_eq!(pairing_code(&sec1(&ext)), "562741");
    }

    struct FakeHost {
        st: Mutex<LockState>,
        pairings: Mutex<Vec<Pairing>>,
        allow: bool,
        asked: Mutex<Vec<String>>,
        wait: UnlockWait,
        /// (browser, active) of every `show_unlock`.
        shown: Mutex<Vec<(String, bool)>>,
        timeout: Duration,
    }

    impl FakeHost {
        /// The user unlocks the app (what `AppState::notify_unlocked` does).
        fn unlock_now(&self) {
            self.st.lock().unwrap().unlocked = true;
            self.wait.notify();
        }
    }

    impl Host for FakeHost {
        fn lock_state(&self) -> LockState {
            self.st.lock().unwrap().clone()
        }
        fn account_key(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.st
                .lock()
                .unwrap()
                .unlocked
                .then(|| Zeroizing::new(vec![0xAB; 32]))
        }
        fn allowed_extension(&self, id: &str) -> bool {
            id == EXT
        }
        fn pairings(&self) -> Vec<Pairing> {
            self.pairings.lock().unwrap().clone()
        }
        fn save_pairing(&self, p: Pairing) {
            self.pairings.lock().unwrap().push(p);
        }
        fn remove_pairing(&self, id: &str) {
            self.pairings.lock().unwrap().retain(|p| p.id != id);
        }
        fn touch_pairing(&self, _: &str) {}
        fn confirm_pairing(&self, _: &str, _: &str, code: &str) -> bool {
            self.asked.lock().unwrap().push(code.into());
            self.allow
        }
        fn show_unlock(&self, browser: &str, active: bool) {
            self.shown.lock().unwrap().push((browser.into(), active));
        }
        fn unlock_wait(&self) -> &UnlockWait {
            &self.wait
        }
        fn unlock_timeout(&self) -> Duration {
            self.timeout
        }
    }

    fn host(allow: bool, unlocked: bool) -> FakeHost {
        FakeHost {
            st: Mutex::new(LockState {
                signed_in: true,
                unlocked,
                login: "test@example.com".into(),
                server_url: "https://vault.example.com".into(),
                account_id: "acc-1".into(),
                device_id: "d".into(),
                last_sync_at: 0,
            }),
            pairings: Mutex::new(vec![]),
            allow,
            asked: Mutex::new(vec![]),
            wait: UnlockWait::default(),
            shown: Mutex::new(vec![]),
            timeout: Duration::from_secs(10),
        }
    }

    fn sealed_of(r: &Value) -> Sealed {
        Sealed {
            eph_public_key: r["eph_public_key"].as_str().unwrap().into(),
            iv: r["iv"].as_str().unwrap().into(),
            ciphertext: r["ciphertext"].as_str().unwrap().into(),
        }
    }

    fn interactive(nonce: &[u8]) -> Value {
        let mut r = unlock_req(nonce);
        r["interactive"] = true.into();
        r
    }

    /// Polls until `f` holds (the waiting request runs on another thread).
    fn eventually(f: impl Fn() -> bool) {
        let start = Instant::now();
        while !f() {
            assert!(start.elapsed() < Duration::from_secs(5), "timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The desktop app is locked: an interactive request shows the app's
    /// unlock screen, waits, and is answered once the user unlocks; other
    /// requests meanwhile are `busy` (interactive) or `locked` (not).
    #[test]
    fn locked_desktop_waits_for_an_interactive_unlock() {
        let ext = ext_key(3);
        let h = Arc::new(host(true, false));
        assert_eq!(handle_request(&*h, EXT, &pair_req(&ext))["type"], "paired");
        let nonce = [7u8; 32];
        let waiting = {
            let h = h.clone();
            std::thread::spawn(move || handle_request(&*h, EXT, &interactive(&nonce)))
        };
        eventually(|| h.wait.is_pending());
        assert_eq!(
            h.shown.lock().unwrap().as_slice(),
            [("Chrome".to_string(), true)]
        );
        // one at a time
        assert_eq!(
            handle_request(&*h, EXT, &interactive(&[8u8; 32]))["code"],
            "busy"
        );
        // automatic requests never wait or show anything
        assert_eq!(
            handle_request(&*h, EXT, &unlock_req(&[9u8; 32]))["code"],
            "locked"
        );
        assert_eq!(h.shown.lock().unwrap().len(), 1);

        // the user unlocks the app (password, Windows Hello or PIN)
        h.unlock_now();
        let r = waiting.join().unwrap();
        assert_eq!(r["type"], "unlock", "{r}");
        assert_eq!(r["rid"], 2);
        assert_eq!(
            open(&ext, &sealed_of(&r), "acc-1", &nonce).unwrap(),
            vec![0xAB; 32]
        );
        assert!(!h.wait.is_pending());
        assert_eq!(
            h.shown.lock().unwrap().last().unwrap(),
            &("Chrome".to_string(), false)
        );
        // unlocked now: answered at once, nothing shown
        assert_eq!(
            handle_request(&*h, EXT, &interactive(&nonce))["type"],
            "unlock"
        );
        assert_eq!(h.shown.lock().unwrap().len(), 2);
    }

    #[test]
    fn waiting_times_out_and_frees_the_slot() {
        let ext = ext_key(3);
        let mut fake = host(true, false);
        fake.timeout = Duration::from_millis(300);
        let h = Arc::new(fake);
        handle_request(&*h, EXT, &pair_req(&ext));
        let r = handle_request(&*h, EXT, &interactive(&[1u8; 32]));
        assert_eq!(r["code"], "timeout");
        assert!(!h.wait.is_pending());
        assert_eq!(h.shown.lock().unwrap().len(), 2, "shown, then ended");
        // a later request may wait again
        let again = {
            let h = h.clone();
            std::thread::spawn(move || handle_request(&*h, EXT, &interactive(&[2u8; 32])))
        };
        eventually(|| h.wait.is_pending());
        h.unlock_now();
        assert_eq!(again.join().unwrap()["type"], "unlock");
    }

    #[test]
    fn only_paired_extensions_of_this_account_can_bring_the_app_forward() {
        let h = host(true, false);
        // not paired: refused at once, no window
        assert_eq!(
            handle_request(&h, EXT, &interactive(&[1u8; 32]))["code"],
            "not_paired"
        );
        handle_request(&h, EXT, &pair_req(&ext_key(3)));
        let mut wrong = interactive(&[1u8; 32]);
        wrong["account_id"] = "acc-2".into();
        assert_eq!(handle_request(&h, EXT, &wrong)["code"], "account_mismatch");
        let mut bad_nonce = interactive(&[1u8; 32]);
        bad_nonce["nonce"] = B64.encode([1u8; 4]).into();
        assert_eq!(handle_request(&h, EXT, &bad_nonce)["code"], "invalid");
        assert!(h.shown.lock().unwrap().is_empty());
        assert!(!h.wait.is_pending());
    }

    #[test]
    fn another_account_after_the_wait_gets_nothing() {
        let h = Arc::new(host(true, false));
        handle_request(&*h, EXT, &pair_req(&ext_key(3)));
        let waiting = {
            let h = h.clone();
            std::thread::spawn(move || handle_request(&*h, EXT, &interactive(&[5u8; 32])))
        };
        eventually(|| h.wait.is_pending());
        {
            // the user signed out and into another account meanwhile
            let mut st = h.st.lock().unwrap();
            st.account_id = "acc-2".into();
        }
        h.unlock_now();
        assert_eq!(waiting.join().unwrap()["code"], "account_mismatch");
    }

    #[test]
    fn interactive_requests_are_recognized() {
        assert!(is_interactive_unlock(&interactive(&[1u8; 32])));
        assert!(!is_interactive_unlock(&unlock_req(&[1u8; 32])));
        let mut s = interactive(&[1u8; 32]);
        s["interactive"] = "true".into();
        assert!(!is_interactive_unlock(&s), "only a JSON true");
        assert!(!is_interactive_unlock(
            &json!({"type": "hello", "interactive": true})
        ));
    }

    fn pair_req(ext: &p256::SecretKey) -> Value {
        json!({"type": "pair", "rid": 1, "id": "p1", "public_key": B64.encode(sec1(ext)),
               "account_id": "acc-1", "server_url": "https://vault.example.com/", "browser": "Chrome"})
    }

    fn unlock_req(nonce: &[u8]) -> Value {
        json!({"type": "unlock", "rid": 2, "pairing_id": "p1", "account_id": "acc-1",
               "server_url": "https://vault.example.com", "nonce": B64.encode(nonce)})
    }

    #[test]
    fn pairing_and_unlock() {
        let ext = ext_key(3);
        let h = host(true, true);
        // not paired yet
        assert_eq!(
            handle_request(&h, EXT, &unlock_req(&[1; 32]))["code"],
            "not_paired"
        );
        let r = handle_request(&h, EXT, &pair_req(&ext));
        assert_eq!(r["type"], "paired");
        assert_eq!(r["rid"], 1);
        assert_eq!(
            h.asked.lock().unwrap().as_slice(),
            [pairing_code(&sec1(&ext))]
        );
        // the same pairing again does not ask again
        handle_request(&h, EXT, &pair_req(&ext));
        assert_eq!(h.asked.lock().unwrap().len(), 1);

        let nonce = [5u8; 32];
        let r = handle_request(&h, EXT, &unlock_req(&nonce));
        assert_eq!(r["type"], "unlock", "{r}");
        assert_eq!(
            open(&ext, &sealed_of(&r), "acc-1", &nonce).unwrap(),
            vec![0xAB; 32]
        );

        // another extension cannot use this pairing
        let other = "pppppppppppppppppppppppppppppppp";
        assert_eq!(
            handle_request(&h, other, &unlock_req(&nonce))["code"],
            "not_paired"
        );
        // another account
        let mut wrong = unlock_req(&nonce);
        wrong["account_id"] = "acc-2".into();
        assert_eq!(handle_request(&h, EXT, &wrong)["code"], "account_mismatch");
        let mut wrong = unlock_req(&nonce);
        wrong["server_url"] = "https://evil.example.com".into();
        assert_eq!(handle_request(&h, EXT, &wrong)["code"], "account_mismatch");
        // locked desktop
        h.st.lock().unwrap().unlocked = false;
        assert_eq!(
            handle_request(&h, EXT, &unlock_req(&nonce))["code"],
            "locked"
        );
        // unpair
        handle_request(&h, EXT, &json!({"type": "unpair", "pairing_id": "p1"}));
        assert!(h.pairings().is_empty());
    }

    #[test]
    fn pairing_denied_or_wrong_account() {
        let ext = ext_key(3);
        let h = host(false, true);
        assert_eq!(handle_request(&h, EXT, &pair_req(&ext))["code"], "denied");
        assert!(h.pairings().is_empty());
        let h = host(true, true);
        let mut r = pair_req(&ext);
        r["account_id"] = "someone-else".into();
        assert_eq!(handle_request(&h, EXT, &r)["code"], "account_mismatch");
        assert!(h.asked.lock().unwrap().is_empty());
        let mut r = pair_req(&ext);
        r["public_key"] = "AAAA".into();
        assert_eq!(handle_request(&h, EXT, &r)["code"], "invalid");
    }

    #[test]
    fn extension_ids() {
        assert_eq!(
            extension_id(&format!("chrome-extension://{EXT}/")).as_deref(),
            Some(EXT)
        );
        assert_eq!(extension_id("chrome-extension://short/"), None);
        assert_eq!(extension_id("https://example.com/"), None);
        assert!(!valid_extension_id("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"));
        assert!(STORE_EXTENSION_IDS.iter().all(|i| valid_extension_id(i)));
        let ids = allowed_extension_ids(&[EXT.into(), STORE_EXTENSION_IDS[1].into()]);
        assert_eq!(ids.len(), STORE_EXTENSION_IDS.len() + 1);
        assert_eq!(ids[..STORE_EXTENSION_IDS.len()], *STORE_EXTENSION_IDS);
        assert_eq!(ids.last().map(String::as_str), Some(EXT));
    }

    /// The host process relays both ways through a real pipe to a server that
    /// runs the protocol, and pushed events reach the browser side.
    #[test]
    fn host_relay_end_to_end() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let name = {
                let n = format!(
                    "npw-test-bridge-{}-{}",
                    std::process::id(),
                    npw_model::new_id()
                );
                if cfg!(windows) {
                    n
                } else {
                    // /tmp, not $TMPDIR: macOS temp paths are too long for a socket (SUN_LEN)
                    std::path::Path::new("/tmp").join(n).display().to_string()
                }
            };
            let listener = Listener::bind(&name).unwrap();
            let h = Arc::new(host(true, true));
            let (events, _) = broadcast::channel(4);
            let server = tokio::spawn(serve(listener, h.clone(), events.clone()));

            // the browser side of the host's stdio
            let (mut browser, host_stdio) = tokio::io::duplex(1 << 16);
            let (host_in, host_out) = tokio::io::split(host_stdio);
            let conn = ipc::connect(&name).await.unwrap();
            let relay_task = tokio::spawn(async move {
                relay(
                    host_in,
                    host_out,
                    conn,
                    &format!("chrome-extension://{EXT}/"),
                )
                .await
            });

            let ext = ext_key(4);
            write_native(
                &mut browser,
                json!({"type": "hello", "rid": "a"}).to_string().as_bytes(),
            )
            .await
            .unwrap();
            let r: Value =
                serde_json::from_slice(&read_native(&mut browser).await.unwrap().unwrap()).unwrap();
            assert_eq!(
                (
                    r["type"].as_str(),
                    r["rid"].as_str(),
                    r["unlocked"].as_bool()
                ),
                (Some("hello"), Some("a"), Some(true))
            );
            write_native(&mut browser, pair_req(&ext).to_string().as_bytes())
                .await
                .unwrap();
            let r: Value =
                serde_json::from_slice(&read_native(&mut browser).await.unwrap().unwrap()).unwrap();
            assert_eq!(r["type"], "paired");
            write_native(&mut browser, unlock_req(&[6; 32]).to_string().as_bytes())
                .await
                .unwrap();
            let r: Value =
                serde_json::from_slice(&read_native(&mut browser).await.unwrap().unwrap()).unwrap();
            assert_eq!(r["type"], "unlock");

            // the app locks: the extension hears about it
            events.send("locked".into()).unwrap();
            let r: Value =
                serde_json::from_slice(&read_native(&mut browser).await.unwrap().unwrap()).unwrap();
            assert_eq!(r["type"], "locked");

            // the browser closes the port: the relay ends
            drop(browser);
            relay_task.await.unwrap().unwrap();

            // a host claiming an extension that is not allowed is turned away
            let (mut b2, s2) = tokio::io::duplex(1 << 16);
            let (i2, o2) = tokio::io::split(s2);
            let conn = ipc::connect(&name).await.unwrap();
            tokio::spawn(async move {
                relay(
                    i2,
                    o2,
                    conn,
                    "chrome-extension://pppppppppppppppppppppppppppppppp/",
                )
                .await
            });
            let r: Value =
                serde_json::from_slice(&read_native(&mut b2).await.unwrap().unwrap()).unwrap();
            assert_eq!(r["code"], "forbidden");
            server.abort();
        });
    }

    fn pipe_name(tag: &str) -> String {
        let n = format!(
            "npw-test-{tag}-{}-{}",
            std::process::id(),
            npw_model::new_id()
        );
        if cfg!(windows) {
            n
        } else {
            std::path::Path::new("/tmp").join(n).display().to_string()
        }
    }

    async fn ask(browser: &mut tokio::io::DuplexStream, req: Value) -> Value {
        write_native(browser, req.to_string().as_bytes())
            .await
            .unwrap();
        serde_json::from_slice(&read_native(browser).await.unwrap().unwrap()).unwrap()
    }

    /// The app is not running: the host answers `app_not_running`, except to
    /// an interactive unlock, for which it starts the app and relays the
    /// request once the app listens.
    #[test]
    fn host_starts_the_app_for_an_interactive_unlock() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let name = pipe_name("launch");
            let h = Arc::new(host(true, true));
            let ext = ext_key(4);
            handle_request(&*h, EXT, &pair_req(&ext));
            let (events, _) = broadcast::channel(4);
            let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let launch = {
                let (name, h, events, launches) =
                    (name.clone(), h.clone(), events.clone(), launches.clone());
                move || {
                    launches.fetch_add(1, Ordering::SeqCst);
                    // "the app starts": it listens a moment later
                    let (name, h, events) = (name.clone(), h.clone(), events.clone());
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        let l = Listener::bind(&name).unwrap();
                        serve(l, h, events).await;
                    });
                    Ok(())
                }
            };
            let connect = {
                let name = name.clone();
                move || {
                    let name = name.clone();
                    async move { ipc::connect(&name).await }
                }
            };
            let (mut browser, stdio) = tokio::io::duplex(1 << 16);
            let (host_in, host_out) = tokio::io::split(stdio);
            let origin = format!("chrome-extension://{EXT}/");
            let task = tokio::spawn(async move {
                host_without_app(
                    host_in,
                    host_out,
                    &origin,
                    launch,
                    connect,
                    Duration::from_secs(10),
                    || {},
                )
                .await
            });

            // automatic requests do not start the app
            let r = ask(&mut browser, json!({"type": "hello", "rid": "a"})).await;
            assert_eq!(
                (r["code"].as_str(), r["rid"].as_str()),
                (Some("app_not_running"), Some("a"))
            );
            let r = ask(&mut browser, unlock_req(&[1; 32])).await;
            assert_eq!(r["code"], "app_not_running");
            assert_eq!(launches.load(Ordering::SeqCst), 0);

            // an explicit unlock starts it and is answered by it
            let nonce = [6u8; 32];
            let r = ask(&mut browser, interactive(&nonce)).await;
            assert_eq!(r["type"], "unlock", "{r}");
            assert_eq!(r["rid"], 2);
            assert_eq!(
                open(&ext, &sealed_of(&r), "acc-1", &nonce).unwrap(),
                vec![0xAB; 32]
            );
            assert_eq!(launches.load(Ordering::SeqCst), 1);
            // from now on it is a normal relay: requests and pushed events
            let r = ask(&mut browser, json!({"type": "hello", "rid": "b"})).await;
            assert_eq!(r["type"], "hello");
            events.send("locked".into()).unwrap();
            let r: Value =
                serde_json::from_slice(&read_native(&mut browser).await.unwrap().unwrap()).unwrap();
            assert_eq!(r["type"], "locked");
            drop(browser);
            task.await.unwrap().unwrap();
        });
    }

    #[test]
    fn host_reports_an_app_that_cannot_start() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let name = pipe_name("nostart");
            let (mut browser, stdio) = tokio::io::duplex(1 << 16);
            let (host_in, host_out) = tokio::io::split(stdio);
            let task = tokio::spawn(async move {
                host_without_app(
                    host_in,
                    host_out,
                    "chrome-extension://x/",
                    || Err("not installed".to_string()),
                    move || {
                        let name = name.clone();
                        async move { ipc::connect(&name).await }
                    },
                    Duration::from_millis(200),
                    || {},
                )
                .await
            });
            let r = ask(&mut browser, interactive(&[1; 32])).await;
            assert_eq!(r["code"], "app_not_running");
            assert_eq!(r["rid"], 2);
            assert!(r["message"].as_str().unwrap().contains("not installed"));
            // the host keeps answering
            let r = ask(&mut browser, json!({"type": "hello", "rid": 9})).await;
            assert_eq!(r["rid"], 9);
            drop(browser);
            task.await.unwrap().unwrap();
        });
    }

    #[test]
    fn manifest_shape() {
        let m: Value = serde_json::from_str(&manifest(
            std::path::Path::new("/opt/npw/nyapassword"),
            &[EXT.into()],
        ))
        .unwrap();
        assert_eq!(m["name"], NATIVE_HOST_NAME);
        assert_eq!(m["type"], "stdio");
        assert_eq!(
            m["allowed_origins"][0],
            format!("chrome-extension://{EXT}/")
        );
    }
}
