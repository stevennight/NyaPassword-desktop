//! The device key: 32 random bytes that seal the Secret Key and the session
//! in the local replica (design doc §4.5). Kept in the OS credential store;
//! if that is unavailable, in a file next to the replica (with a warning: the
//! file is only protected by the user account's file permissions).

use std::path::Path;

use npw_crypto::Key32;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::platform::Platform;

pub const FALLBACK_FILE: &str = "device-key.bin";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyStorage {
    /// Windows Credential Manager / macOS Keychain / Secret Service.
    Os,
    /// `device-key.bin` in the app data folder.
    File,
}

/// Loads the device key, creating it on first start. `replica` is the replica
/// file sealed with it: when the key is gone for good, that replica is
/// unreadable and is moved aside (it holds only ciphertext; the server has the data).
pub fn load_or_create(
    platform: &dyn Platform,
    dir: &Path,
    replica: &Path,
) -> Result<(Key32, KeyStorage), String> {
    let file = dir.join(FALLBACK_FILE);
    match platform.load_device_key() {
        Ok(Some(k)) => {
            let k = Zeroizing::new(k);
            Key32::from_slice(&k)
                .map(|k| (k, KeyStorage::Os))
                .map_err(|_| "系统凭据存储中的设备密钥长度不对".to_string())
        }
        Ok(None) => {
            if let Some(k) = read_file(&file)? {
                return Ok((k, KeyStorage::File));
            }
            orphan_replica(replica);
            let key = Key32::generate();
            match platform.store_device_key(key.as_bytes()) {
                Ok(()) => Ok((key, KeyStorage::Os)),
                Err(e) => {
                    log::warn!("cannot store the device key in the OS credential store ({e}); using {FALLBACK_FILE}");
                    write_file(&file, &key)?;
                    Ok((key, KeyStorage::File))
                }
            }
        }
        Err(e) => {
            if let Some(k) = read_file(&file)? {
                return Ok((k, KeyStorage::File));
            }
            if replica.exists() {
                // the key may be in the store; a new one would make the replica unreadable
                return Err(format!(
                    "无法访问系统凭据存储（{}）：{e}。请解锁系统钥匙串后重启 NyaPassword",
                    platform.key_store_name()
                ));
            }
            log::warn!(
                "OS credential store unavailable ({e}); keeping the device key in {FALLBACK_FILE}"
            );
            let key = Key32::generate();
            write_file(&file, &key)?;
            Ok((key, KeyStorage::File))
        }
    }
}

fn read_file(path: &Path) -> Result<Option<Key32>, String> {
    match std::fs::read(path) {
        Ok(b) => {
            let b = Zeroizing::new(b);
            Key32::from_slice(&b)
                .map(Some)
                .map_err(|_| format!("{} 已损坏", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn write_file(path: &Path, key: &Key32) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, key.as_bytes()))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn orphan_replica(replica: &Path) {
    if !replica.exists() {
        return;
    }
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let to = replica.with_extension(format!("sqlite3.orphaned-{ts}"));
    log::warn!(
        "the device key is missing; moving the unreadable replica to {}",
        to.display()
    );
    let _ = std::fs::rename(replica, &to);
    for ext in ["sqlite3-wal", "sqlite3-shm"] {
        let _ = std::fs::remove_file(replica.with_extension(ext));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::LockCallback;
    use std::sync::Mutex;

    /// A credential store that can be broken on purpose.
    struct Fake {
        stored: Mutex<Option<Vec<u8>>>,
        broken: bool,
    }

    impl Platform for Fake {
        fn key_store_name(&self) -> &'static str {
            "fake"
        }
        fn load_device_key(&self) -> Result<Option<Vec<u8>>, String> {
            if self.broken {
                return Err("unavailable".into());
            }
            Ok(self.stored.lock().unwrap().clone())
        }
        fn store_device_key(&self, key: &[u8]) -> Result<(), String> {
            if self.broken {
                return Err("unavailable".into());
            }
            *self.stored.lock().unwrap() = Some(key.to_vec());
            Ok(())
        }
        fn quick_unlock_label(&self) -> &'static str {
            ""
        }
        fn clipboard_set(&self, _: &str, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn clipboard_get(&self) -> Option<String> {
            None
        }
        fn clipboard_clear(&self) {}
        fn watch_session_lock(&self, _: LockCallback) {}
    }

    fn fake(broken: bool) -> Fake {
        Fake {
            stored: Mutex::new(None),
            broken,
        }
    }

    #[test]
    fn os_store_keeps_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let replica = dir.path().join("replica.sqlite3");
        let p = fake(false);
        let (k1, s1) = load_or_create(&p, dir.path(), &replica).unwrap();
        assert_eq!(s1, KeyStorage::Os);
        std::fs::write(&replica, b"db").unwrap();
        let (k2, _) = load_or_create(&p, dir.path(), &replica).unwrap();
        assert_eq!(k1, k2);
        assert!(replica.exists());
        assert!(!dir.path().join(FALLBACK_FILE).exists());
    }

    #[test]
    fn broken_store_falls_back_to_a_file_only_for_a_new_replica() {
        let dir = tempfile::tempdir().unwrap();
        let replica = dir.path().join("replica.sqlite3");
        let p = fake(true);
        let (k1, s1) = load_or_create(&p, dir.path(), &replica).unwrap();
        assert_eq!(s1, KeyStorage::File);
        let (k2, s2) = load_or_create(&p, dir.path(), &replica).unwrap();
        assert_eq!((k1, s1), (k2, s2));

        // an existing replica but neither store nor file: refuse instead of orphaning it
        let dir2 = tempfile::tempdir().unwrap();
        let replica2 = dir2.path().join("replica.sqlite3");
        std::fs::write(&replica2, b"db").unwrap();
        assert!(load_or_create(&p, dir2.path(), &replica2).is_err());
        assert!(replica2.exists());
    }

    #[test]
    fn lost_key_moves_the_replica_aside() {
        let dir = tempfile::tempdir().unwrap();
        let replica = dir.path().join("replica.sqlite3");
        std::fs::write(&replica, b"db").unwrap();
        let p = fake(false);
        load_or_create(&p, dir.path(), &replica).unwrap();
        assert!(!replica.exists());
        let moved = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains("orphaned"));
        assert!(moved);
    }
}
