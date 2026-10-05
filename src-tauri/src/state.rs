//! The app's state: one client core over the SQLite replica, plus the
//! desktop-only pieces (settings, parsed imports, clipboard, quick unlock rules).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use npw_core::{Client, ClientConfig};
use npw_store_sqlite::SqliteStore;
use tauri::{AppHandle, Emitter, Manager};

use crate::browser_bridge::BrowserBridge;
use crate::clipboard::Clipboard;
use crate::device_key::{self, KeyStorage};
use crate::error::{BridgeError, CmdResult};
use crate::platform::{self, Platform, TargetWindow};
use crate::prompts::Prompts;
use crate::settings::Settings;
use crate::ssh_agent::SshAgent;

pub const REPLICA: &str = "replica.sqlite3";

/// Events for the UI (bridge-tauri.ts listens).
pub const EVENT_LOCKED: &str = "npw:locked";
pub const EVENT_SYNC: &str = "npw:sync";
pub const EVENT_EXPORT: &str = "npw:export";
pub const EVENT_UPDATE: &str = "npw:update";
/// A message for the main window (shown as a toast).
pub const EVENT_NOTICE: &str = "npw:notice";

pub struct AppState {
    pub dir: PathBuf,
    pub platform: &'static dyn Platform,
    client: Result<Arc<Client>, String>,
    pub key_storage: Option<KeyStorage>,
    /// Parsed imports waiting for the user's confirmation, by token (plaintext: dropped on lock).
    pub imports: Mutex<HashMap<String, (String, npw_import::ImportResult)>>,
    settings: Mutex<Settings>,
    /// The master password was entered in this run of the app (quick unlock needs it).
    pub password_this_run: AtomicBool,
    pub exporting: AtomicBool,
    pub clipboard: Clipboard,
    pub ssh: SshAgent,
    pub prompts: Prompts,
    pub bridge: BrowserBridge,
    /// The window Quick Access types into (captured when it opens).
    pub quick_target: Mutex<Option<TargetWindow>>,
    /// Why the Quick Access shortcut could not be registered (empty = fine).
    pub quick_error: Mutex<String>,
}

impl AppState {
    pub fn init(dir: PathBuf) -> Self {
        let platform = platform::native();
        let settings = Settings::load(&dir);
        let (client, key_storage) = match open_client(&dir, platform) {
            Ok((c, s)) => (Ok(c), Some(s)),
            Err(e) => {
                log::error!("cannot open the local replica: {e}");
                (Err(e), None)
            }
        };
        Self {
            dir,
            platform,
            client,
            key_storage,
            imports: Mutex::new(HashMap::new()),
            settings: Mutex::new(settings),
            password_this_run: AtomicBool::new(false),
            exporting: AtomicBool::new(false),
            clipboard: Clipboard::default(),
            ssh: SshAgent::default(),
            prompts: Prompts::default(),
            bridge: BrowserBridge::default(),
            quick_target: Mutex::new(None),
            quick_error: Mutex::new(String::new()),
        }
    }

    pub fn client(&self) -> CmdResult<Arc<Client>> {
        self.client
            .clone()
            .map_err(|e| BridgeError::new("store", format!("无法打开本地数据：{e}")))
    }

    pub fn settings(&self) -> Settings {
        self.settings.lock().expect("settings").clone()
    }

    /// Changes and saves the settings; returns the new value.
    pub fn update_settings(&self, f: impl FnOnce(&mut Settings)) -> Settings {
        let mut g = self.settings.lock().expect("settings");
        f(&mut g);
        if let Err(e) = g.save(&self.dir) {
            log::warn!("could not save settings: {e}");
        }
        g.clone()
    }

    /// Forgets keys, decrypted items, parsed imports and the ssh-agent's
    /// "until locked" approvals; connected browser extensions lock too.
    pub fn lock(&self) {
        if let Ok(c) = &self.client {
            c.lock();
        }
        self.imports.lock().expect("imports").clear();
        self.ssh.on_lock();
        *self.quick_target.lock().expect("quick") = None;
        self.bridge.notify("locked");
    }

    /// After any unlock: connected extensions may unlock now.
    pub fn notify_unlocked(&self) {
        self.bridge.notify("unlocked");
    }
}

fn open_client(
    dir: &Path,
    platform: &'static dyn Platform,
) -> Result<(Arc<Client>, KeyStorage), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let replica = dir.join(REPLICA);
    let (key, storage) = device_key::load_or_create(platform, dir, &replica)?;
    let store = SqliteStore::open(&replica).map_err(|e| e.to_string())?;
    let os = match platform::os_name() {
        "windows" => "Windows",
        "macos" => "macOS",
        _ => "Linux",
    };
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let name = if host.is_empty() {
        format!("桌面端 · {os}")
    } else {
        format!("桌面端 · {os} · {host}")
    };
    let mut cfg = ClientConfig::new(&name, platform::os_name(), env!("CARGO_PKG_VERSION"));
    cfg.locale = "zh-CN".into();
    let client = Client::new(cfg, Arc::new(store), key).map_err(|e| e.to_string())?;
    Ok((Arc::new(client), storage))
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Shows, unminimizes and focuses the main window.
pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Locks the vault and tells the UI (tray "lock", session lock, sleep).
pub fn lock_all(app: &AppHandle, why: &str) {
    if let Some(st) = app.try_state::<AppState>() {
        let was = st.client.as_ref().map(|c| c.is_unlocked()).unwrap_or(false);
        st.lock();
        if was {
            log::info!("locked ({why})");
        }
    }
    let _ = app.emit(EVENT_LOCKED, why);
}

impl AppState {
    pub fn mark_password_unlock(&self) -> Settings {
        self.password_this_run.store(true, Ordering::SeqCst);
        let now = now_ms();
        self.update_settings(|s| s.last_password_unlock_at = now)
    }
}
