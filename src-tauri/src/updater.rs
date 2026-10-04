//! Self-update from GitHub Releases (design doc §3.4). A release carries the
//! installers, `SHA256SUMS` and `SHA256SUMS.minisig`; the minisign public key
//! is compiled in (env `NPW_UPDATE_PUBKEY` at build time). An update is only
//! installed when the signature over `SHA256SUMS` is valid *and* the
//! installer's SHA-256 matches its signed line: a hijacked GitHub account
//! alone cannot push a malicious build.
//!
//! Windows (NSIS install): download, verify, run the installer silently, quit.
//! Elsewhere (and for the portable zip): report the new version and open the
//! release page.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `owner/repo`, from the release build (`github.repository`).
pub const REPO: &str = match option_env!("NPW_UPDATE_REPO") {
    Some(r) => r,
    None => "example/NyaPassword-desktop",
};

/// Base64 minisign public key (second line of the .pub file).
pub const PUBKEY: Option<&str> = option_env!("NPW_UPDATE_PUBKEY");

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

const MAX_METADATA: u64 = 2 * 1024 * 1024;
const MAX_SUMS: u64 = 256 * 1024;
const MAX_INSTALLER: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UpdateCheck {
    pub current: String,
    /// Newest release, when newer than this build.
    pub latest: Option<String>,
    pub notes: String,
    pub url: String,
    /// This build can download and install it by itself.
    pub can_install: bool,
    /// Why it cannot (empty when it can, or when there is nothing to install).
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

/// The installer asset this build updates itself with.
pub fn installer_name(version: &str) -> Option<String> {
    if cfg!(windows) && std::env::consts::ARCH == "x86_64" {
        Some(format!("NyaPassword_{version}_x64-setup.exe"))
    } else {
        None
    }
}

/// Why this build cannot install updates by itself (`None`: it can).
fn install_blocker() -> Option<String> {
    if cfg!(debug_assertions) {
        return Some("开发版本不自动更新".into());
    }
    if PUBKEY.is_none_or(|k| k.trim().is_empty()) {
        return Some("此版本没有内置更新签名公钥，请到发布页手动下载".into());
    }
    if !cfg!(windows) {
        return Some("此平台请到发布页下载新版本".into());
    }
    // the NSIS installer puts its uninstaller next to the app; the portable zip has none
    let installed = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("uninstall.exe").exists()))
        .unwrap_or(false);
    if !installed {
        return Some("便携版不自动更新，请到发布页下载".into());
    }
    None
}

fn http() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(concat!("NyaPassword-desktop/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(15 * 60))
        .build()
        .map_err(|e| e.to_string())
}

async fn get_limited(
    client: &reqwest::Client,
    url: &str,
    accept: &str,
    max: u64,
) -> Result<Vec<u8>, String> {
    let mut resp = client
        .get(url)
        .header(reqwest::header::ACCEPT, accept)
        .send()
        .await
        .map_err(|e| format!("无法连接 GitHub：{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GitHub 返回 HTTP {}", resp.status()));
    }
    if resp.content_length().is_some_and(|l| l > max) {
        return Err("下载内容过大".into());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if out.len() as u64 + chunk.len() as u64 > max {
            return Err("下载内容过大".into());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn latest_release(client: &reqwest::Client) -> Result<Release, String> {
    if !valid_repo(REPO) {
        return Err("更新仓库配置无效".into());
    }
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = get_limited(client, &url, "application/vnd.github+json", MAX_METADATA).await?;
    let r: Release = serde_json::from_slice(&body).map_err(|e| format!("发布信息无效：{e}"))?;
    if r.draft || r.prerelease {
        return Err("最新发布是预发布版本".into());
    }
    Ok(r)
}

fn release_version(r: &Release) -> Result<Version, String> {
    let v = r
        .tag_name
        .strip_prefix('v')
        .ok_or_else(|| "发布标签不是 v<版本>".to_string())?;
    Version::parse(v).map_err(|e| format!("发布版本无效：{e}"))
}

fn is_newer(latest: &Version, current: &str) -> bool {
    Version::parse(current)
        .map(|c| *latest > c)
        .unwrap_or(false)
}

pub async fn check() -> Result<UpdateCheck, String> {
    let client = http()?;
    let r = latest_release(&client).await?;
    let v = release_version(&r)?;
    let newer = is_newer(&v, CURRENT);
    let blocker = install_blocker();
    Ok(UpdateCheck {
        current: CURRENT.into(),
        latest: newer.then(|| v.to_string()),
        notes: r.body.unwrap_or_default().chars().take(4000).collect(),
        url: r.html_url,
        can_install: newer && blocker.is_none(),
        reason: if newer {
            blocker.unwrap_or_default()
        } else {
            String::new()
        },
    })
}

/// Downloads and verifies the installer of `version` (must still be the latest
/// release) into `dir`; returns its path.
pub async fn download(version: &str, dir: &Path) -> Result<PathBuf, String> {
    if let Some(b) = install_blocker() {
        return Err(b);
    }
    let pubkey = PUBKEY.unwrap_or_default();
    let client = http()?;
    let r = latest_release(&client).await?;
    let v = release_version(&r)?;
    if v.to_string() != version || !is_newer(&v, CURRENT) {
        return Err("最新版本已变化，请重新检查更新".into());
    }
    let name = installer_name(version).ok_or("此平台不支持自动更新")?;
    let asset = |n: &str| {
        r.assets
            .iter()
            .find(|a| a.name == n)
            .ok_or_else(|| format!("发布缺少 {n}"))
    };
    let (inst, sums, sig) = (
        asset(&name)?,
        asset("SHA256SUMS")?,
        asset("SHA256SUMS.minisig")?,
    );
    for a in [inst, sums, sig] {
        let prefix = format!("https://github.com/{REPO}/releases/download/");
        if !a.browser_download_url.starts_with(&prefix) {
            return Err(format!("{} 的下载地址不属于更新仓库", a.name));
        }
    }
    let sums_bytes = get_limited(
        &client,
        &sums.browser_download_url,
        "application/octet-stream",
        MAX_SUMS,
    )
    .await?;
    let sig_bytes = get_limited(
        &client,
        &sig.browser_download_url,
        "application/octet-stream",
        MAX_SUMS,
    )
    .await?;
    let expected = verified_checksum(
        &sums_bytes,
        &String::from_utf8_lossy(&sig_bytes),
        pubkey,
        &name,
    )?;

    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(&name);
    let tmp = dir.join(format!("{name}.part"));
    let res = async {
        let mut resp = client
            .get(&inst.browser_download_url)
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .send()
            .await
            .map_err(|e| format!("下载失败：{e}"))?;
        if !resp.status().is_success() {
            return Err(format!("下载失败：HTTP {}", resp.status()));
        }
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("下载失败：{e}"))? {
            total += chunk.len() as u64;
            if total > MAX_INSTALLER {
                return Err("安装包过大".into());
            }
            hasher.update(&chunk);
            f.write_all(&chunk).map_err(|e| e.to_string())?;
        }
        f.sync_all().map_err(|e| e.to_string())?;
        if inst.size != 0 && total != inst.size {
            return Err("安装包大小与发布信息不符".into());
        }
        let actual = hex(&hasher.finalize());
        if actual != expected {
            return Err("安装包的 SHA-256 与签名的 SHA256SUMS 不符，已拒绝更新".into());
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Starts the downloaded installer: silent, in-place update, restart the app afterwards.
#[cfg(windows)]
pub fn launch_installer(path: &Path) -> Result<(), String> {
    std::process::Command::new(path)
        .args(["/S", "/UPDATE", "/R"])
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("无法启动安装程序：{e}"))
}

#[cfg(not(windows))]
pub fn launch_installer(_path: &Path) -> Result<(), String> {
    Err("此平台不支持自动更新".into())
}

/// Checks the minisign signature of `SHA256SUMS` with `pubkey` (base64) and
/// returns the signed SHA-256 (lowercase hex) of `file`.
pub fn verified_checksum(
    sums: &[u8],
    minisig: &str,
    pubkey: &str,
    file: &str,
) -> Result<String, String> {
    let pk = minisign_verify::PublicKey::from_base64(pubkey.trim())
        .map_err(|_| "内置的更新公钥无效".to_string())?;
    let sig =
        minisign_verify::Signature::decode(minisig).map_err(|_| "更新签名格式无效".to_string())?;
    pk.verify(sums, &sig, false)
        .map_err(|_| "更新签名校验失败，已拒绝更新".to_string())?;
    let text = std::str::from_utf8(sums).map_err(|_| "SHA256SUMS 不是文本".to_string())?;
    checksum_for(text, file).ok_or_else(|| format!("SHA256SUMS 中没有 {file}"))
}

/// The SHA-256 of `file` in `sha256sum` output (`<hex>  <name>` or `<hex> *<name>`).
pub fn checksum_for(sums: &str, file: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let line = line.trim_end_matches('\r');
        let (hash, rest) = line.split_at_checked(64)?;
        if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let name = rest
            .strip_prefix("  ")
            .or_else(|| rest.strip_prefix(" *"))?;
        (name == file).then(|| hash.to_ascii_lowercase())
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn valid_repo(r: &str) -> bool {
    let parts: Vec<&str> = r.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn signed(sums: &str) -> (String, String) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let sig = minisign::sign(
            None,
            &kp.sk,
            Cursor::new(sums.as_bytes()),
            Some("file:SHA256SUMS"),
            None,
        )
        .unwrap()
        .into_string();
        (kp.pk.to_base64(), sig)
    }

    const INSTALLER: &str = "NyaPassword_0.2.0_x64-setup.exe";

    fn sums() -> String {
        format!(
            "{}  NyaPassword_0.2.0_windows_x64.zip\n{} *{INSTALLER}\n",
            "a".repeat(64),
            "0123456789ABCDEF".repeat(4)
        )
    }

    #[test]
    fn valid_signature_gives_the_checksum() {
        let s = sums();
        let (pk, sig) = signed(&s);
        assert_eq!(
            verified_checksum(s.as_bytes(), &sig, &pk, INSTALLER).unwrap(),
            "0123456789abcdef".repeat(4)
        );
        assert!(verified_checksum(s.as_bytes(), &sig, &pk, "other.exe").is_err());
    }

    #[test]
    fn tampered_or_foreign_signatures_are_refused() {
        let s = sums();
        let (pk, sig) = signed(&s);
        // a changed checksum file
        let evil = s.replace("0123", "9999");
        assert!(verified_checksum(evil.as_bytes(), &sig, &pk, INSTALLER).is_err());
        // signed by another key
        let (other_pk, _) = signed(&s);
        assert!(verified_checksum(s.as_bytes(), &sig, &other_pk, INSTALLER).is_err());
        // a changed trusted comment
        let lines: Vec<&str> = sig.lines().collect();
        let forged = format!(
            "{}\n{}\ntrusted comment: file:other\n{}\n",
            lines[0], lines[1], lines[3]
        );
        assert!(verified_checksum(s.as_bytes(), &forged, &pk, INSTALLER).is_err());
        // garbage
        assert!(verified_checksum(s.as_bytes(), "nope", &pk, INSTALLER).is_err());
        assert!(verified_checksum(s.as_bytes(), &sig, "nope", INSTALLER).is_err());
    }

    #[test]
    fn checksum_lines() {
        let h = "b".repeat(64);
        assert_eq!(
            checksum_for(&format!("{h}  a.exe\r\n"), "a.exe"),
            Some(h.clone())
        );
        assert_eq!(checksum_for(&format!("{h}  a.exe"), "b.exe"), None);
        assert_eq!(checksum_for(&format!("{h} a.exe"), "a.exe"), None);
        assert_eq!(checksum_for("short  a.exe", "a.exe"), None);
        assert_eq!(
            checksum_for(&format!("{}  a.exe", "z".repeat(64)), "a.exe"),
            None
        );
    }

    #[test]
    fn versions_and_names() {
        let v = Version::parse("0.2.0").unwrap();
        assert!(is_newer(&v, "0.1.9"));
        assert!(!is_newer(&v, "0.2.0"));
        assert!(!is_newer(&v, "0.3.0-beta.1"));
        assert!(valid_repo("example/NyaPassword-desktop"));
        assert!(!valid_repo("example/../x"));
        assert!(!valid_repo("example"));
        if cfg!(all(windows, target_arch = "x86_64")) {
            assert_eq!(
                installer_name("1.2.3").unwrap(),
                "NyaPassword_1.2.3_x64-setup.exe"
            );
        }
    }
}
