//! Desktop-only settings and bookkeeping, in `<app data>/settings.json`.
//! Nothing secret is stored here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const FILE: &str = "settings.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub export: ExportSettings,
    /// Unix ms of the last unlock with the master password (quick unlock expires 14 days after it).
    pub last_password_unlock_at: i64,
    /// Check GitHub Releases for a new version once a day.
    pub check_updates: bool,
    pub last_update_check_at: i64,
    pub ssh_agent: SshAgentSettings,
    pub quick_access: QuickAccessSettings,
    pub browser_bridge: BrowserBridgeSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            export: ExportSettings::default(),
            last_password_unlock_at: 0,
            check_updates: true,
            last_update_check_at: 0,
            ssh_agent: SshAgentSettings::default(),
            quick_access: QuickAccessSettings::default(),
            browser_bridge: BrowserBridgeSettings::default(),
        }
    }
}

/// The built-in ssh-agent (design doc §10.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct SshAgentSettings {
    pub enabled: bool,
    /// Windows: the pipe name under `\\.\pipe\` (empty = `openssh-ssh-agent`).
    /// macOS / Linux: the socket path (empty = `<app data>/ssh-agent.sock`).
    pub endpoint: String,
}

/// The global shortcut that opens Quick Access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct QuickAccessSettings {
    pub enabled: bool,
    pub shortcut: String,
}

pub const DEFAULT_SHORTCUT: &str = "Ctrl+Shift+Space";

impl Default for QuickAccessSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            shortcut: DEFAULT_SHORTCUT.into(),
        }
    }
}

/// Native messaging with the browser extension ("unlock the extension with the desktop app").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct BrowserBridgeSettings {
    pub enabled: bool,
    /// Extension IDs allowed to talk to the host (`allowed_origins` of the manifest).
    pub extension_ids: Vec<String>,
    /// Extensions the user paired with this app. Only public keys: nothing secret.
    pub pairings: Vec<Pairing>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Pairing {
    pub id: String,
    /// "Chrome" / "Edge", as the extension reports it.
    pub name: String,
    /// The extension's long-term P-256 public key (SEC1 uncompressed, base64).
    pub public_key: String,
    pub extension_id: String,
    pub account_id: String,
    pub created_at: i64,
    pub last_used_at: i64,
}

/// Scheduled offline export (design doc §8.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ExportSettings {
    pub enabled: bool,
    pub folder: String,
    pub interval_days: u32,
    /// Lossless native export (opens with master password + Secret Key).
    pub native: bool,
    /// KDBX 4 (KeePassXC; protected by the master password only).
    pub kdbx: bool,
    /// Exports of each format to keep in the folder.
    pub keep: u32,
    /// Unix ms of the last successful export.
    pub last_export_at: i64,
    /// Outcome of the last attempt (empty = success).
    pub last_error: String,
}

impl Default for ExportSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            folder: String::new(),
            interval_days: 7,
            native: true,
            kdbx: true,
            keep: 8,
            last_export_at: 0,
            last_error: String::new(),
        }
    }
}

impl Settings {
    pub fn load(dir: &Path) -> Self {
        match std::fs::read(dir.join(FILE)) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                log::warn!("settings.json is unreadable ({e}); using defaults");
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(self).expect("serializable");
        write_atomic(&dir.join(FILE), &json)
    }
}

/// Writes through a temporary file and a rename, so a crash never leaves half a file.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp: PathBuf = {
        let mut s = path.as_os_str().to_owned();
        s.push(".tmp");
        s.into()
    };
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Settings::load(dir.path()), Settings::default());
        let mut s = Settings::default();
        s.export.enabled = true;
        s.export.folder = "D:\\Backup".into();
        s.last_password_unlock_at = 42;
        s.save(dir.path()).unwrap();
        assert_eq!(Settings::load(dir.path()), s);
        // unknown / missing keys
        std::fs::write(
            dir.path().join(FILE),
            br#"{"export":{"keep":3},"future":1}"#,
        )
        .unwrap();
        let l = Settings::load(dir.path());
        assert_eq!(l.export.keep, 3);
        assert_eq!(l.export.interval_days, 7);
        assert!(l.check_updates);
        // settings files written before M5 get the new sections' defaults
        assert!(!l.ssh_agent.enabled);
        assert!(l.quick_access.enabled);
        assert_eq!(l.quick_access.shortcut, DEFAULT_SHORTCUT);
        assert!(!l.browser_bridge.enabled && l.browser_bridge.pairings.is_empty());
    }
}
