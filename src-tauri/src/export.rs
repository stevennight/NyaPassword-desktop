//! Scheduled offline export (design doc §8.6): `NyaPassword-<date>.npwexport`
//! (native, lossless) and / or `NyaPassword-<date>.kdbx` (KeePassXC) in a
//! folder the user picks, keeping the newest N of each.
//!
//! Exports need the master password, which the app never stores. So the
//! export runs right after the user unlocks with the master password, while
//! that password is in memory for the unlock call anyway, when the last export
//! is older than the interval; "export now" in the settings asks for it.

use std::path::{Path, PathBuf};

use npw_core::Client;
use serde::Serialize;

use crate::settings::ExportSettings;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const PREFIX: &str = "NyaPassword-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Native,
    Kdbx,
}

impl Format {
    pub fn core_name(self) -> &'static str {
        match self {
            Format::Native => "native",
            Format::Kdbx => "kdbx",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Native => "npwexport",
            Format::Kdbx => "kdbx",
        }
    }
}

pub fn formats(s: &ExportSettings) -> Vec<Format> {
    let mut v = vec![];
    if s.native {
        v.push(Format::Native);
    }
    if s.kdbx {
        v.push(Format::Kdbx);
    }
    v
}

/// Configured and older than the interval?
pub fn is_due(s: &ExportSettings, now_ms: i64) -> bool {
    s.enabled
        && !s.folder.trim().is_empty()
        && !formats(s).is_empty()
        && now_ms - s.last_export_at >= i64::from(s.interval_days.max(1)) * DAY_MS
}

pub fn file_name(date: chrono::NaiveDate, f: Format) -> String {
    format!("{PREFIX}{}.{}", date.format("%Y-%m-%d"), f.extension())
}

/// `NyaPassword-YYYY-MM-DD.<ext>` exactly; other files in the folder are never touched.
fn is_export_name(name: &str, ext: &str) -> bool {
    let Some(rest) = name.strip_prefix(PREFIX) else {
        return false;
    };
    let Some(date) = rest.strip_suffix(ext).and_then(|r| r.strip_suffix('.')) else {
        return false;
    };
    chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok() && date.len() == 10
}

/// Of the files `names` in the folder, the exports of `f` beyond the newest `keep`.
pub fn files_to_prune<'a>(
    names: impl IntoIterator<Item = &'a str>,
    f: Format,
    keep: usize,
) -> Vec<String> {
    let mut ours: Vec<&str> = names
        .into_iter()
        .filter(|n| is_export_name(n, f.extension()))
        .collect();
    // the date sorts lexicographically
    ours.sort_unstable_by(|a, b| b.cmp(a));
    ours.into_iter()
        .skip(keep.max(1))
        .map(String::from)
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub files: Vec<String>,
    pub pruned: Vec<String>,
}

/// Exports every selected format into the folder and prunes old exports.
pub async fn run(client: &Client, s: &ExportSettings, password: &str) -> Result<Outcome, String> {
    let folder = PathBuf::from(s.folder.trim());
    if !folder.is_dir() {
        return Err(format!("导出文件夹不存在：{}", folder.display()));
    }
    let fmts = formats(s);
    if fmts.is_empty() {
        return Err("没有选择导出格式".into());
    }
    let today = chrono::Local::now().date_naive();
    let mut out = Outcome {
        files: vec![],
        pruned: vec![],
    };
    for f in fmts {
        let data = client
            .export_vault(f.core_name(), password)
            .await
            .map_err(|e| match e {
                npw_core::CoreError::WrongPassword => "主密码不正确".to_string(),
                other => other.to_string(),
            })?;
        let path = folder.join(file_name(today, f));
        crate::settings::write_atomic(&path, &data)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        out.files.push(path.display().to_string());
        out.pruned.extend(prune(&folder, f, s.keep as usize));
    }
    Ok(out)
}

fn prune(folder: &Path, f: Format, keep: usize) -> Vec<String> {
    let names: Vec<String> = match std::fs::read_dir(folder) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(_) => return vec![],
    };
    let mut removed = vec![];
    for n in files_to_prune(names.iter().map(String::as_str), f, keep) {
        match std::fs::remove_file(folder.join(&n)) {
            Ok(()) => removed.push(n),
            Err(e) => log::warn!("could not remove old export {n}: {e}"),
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> ExportSettings {
        ExportSettings {
            enabled: true,
            folder: "x".into(),
            ..Default::default()
        }
    }

    #[test]
    fn due() {
        let now = 1_000 * DAY_MS;
        let mut s = settings();
        assert!(is_due(&s, now), "never exported");
        s.last_export_at = now - 6 * DAY_MS;
        assert!(!is_due(&s, now));
        s.last_export_at = now - 7 * DAY_MS;
        assert!(is_due(&s, now));
        s.native = false;
        s.kdbx = false;
        assert!(!is_due(&s, now), "no format");
        let mut s = settings();
        s.folder = " ".into();
        assert!(!is_due(&s, now), "no folder");
        let mut s = settings();
        s.enabled = false;
        assert!(!is_due(&s, now));
    }

    #[test]
    fn names() {
        let d = chrono::NaiveDate::from_ymd_opt(2026, 3, 9).unwrap();
        assert_eq!(
            file_name(d, Format::Native),
            "NyaPassword-2026-03-09.npwexport"
        );
        assert_eq!(file_name(d, Format::Kdbx), "NyaPassword-2026-03-09.kdbx");
    }

    #[test]
    fn prune_keeps_newest_and_ignores_other_files() {
        let mut names: Vec<String> = (1..=12)
            .map(|d| format!("NyaPassword-2026-01-{d:02}.npwexport"))
            .collect();
        names.extend([
            "NyaPassword-2025-12-31.kdbx".to_string(),
            "NyaPassword-2025-12-30.npwexport.tmp".into(),
            "NyaPassword-latest.npwexport".into(),
            "NyaPassword-2025-13-40.npwexport".into(),
            "notes.npwexport".into(),
            "NyaPassword-2025-1-1.npwexport".into(),
        ]);
        let p = files_to_prune(names.iter().map(String::as_str), Format::Native, 8);
        assert_eq!(
            p,
            vec![
                "NyaPassword-2026-01-04.npwexport",
                "NyaPassword-2026-01-03.npwexport",
                "NyaPassword-2026-01-02.npwexport",
                "NyaPassword-2026-01-01.npwexport",
            ]
        );
        assert!(files_to_prune(names.iter().map(String::as_str), Format::Kdbx, 8).is_empty());
        // keep at least one
        assert_eq!(
            files_to_prune(names.iter().map(String::as_str), Format::Native, 0).len(),
            11
        );
    }

    #[test]
    fn prune_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        for d in 1..=4 {
            std::fs::write(
                dir.path().join(format!("NyaPassword-2026-02-0{d}.kdbx")),
                b"x",
            )
            .unwrap();
        }
        std::fs::write(dir.path().join("keep-me.kdbx"), b"x").unwrap();
        let removed = prune(dir.path(), Format::Kdbx, 2);
        assert_eq!(removed.len(), 2);
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "NyaPassword-2026-02-03.kdbx",
                "NyaPassword-2026-02-04.kdbx",
                "keep-me.kdbx"
            ]
        );
    }
}
