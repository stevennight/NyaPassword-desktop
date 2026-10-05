//! The built-in ssh-agent (design doc §10.3): the OpenSSH agent protocol
//! (npw-ssh) on the named pipe `\\.\pipe\openssh-ssh-agent` (Windows; another
//! name when the Windows OpenSSH Authentication Agent service owns it) or a
//! Unix socket (macOS / Linux).
//!
//! - Identities: the `ssh_key` items of the unlocked vaults, except items
//!   whose `ssh` object has `"agent": false` (a key the item format keeps for
//!   us, 条目格式 §5). Nothing can be added over the protocol.
//! - Every signature needs the user's confirmation in a small window
//!   (allow once / allow until the vault locks / deny). Items with
//!   `ssh.confirm_each_use = false` are confirmed once per unlock.
//! - A request while the vault is locked shows the main window and waits up
//!   to a minute for the user to unlock.
//! - Git SSH signing works through the same path: `ssh-keygen -Y sign`
//!   (`gpg.format = ssh`) sends SSHSIG data with the `rsa-sha2-512` flag.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use npw_core::ItemFilter;
use npw_model::ItemContent;
use npw_ssh::agent::{SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST};
use npw_ssh::{Agent, Identity, KeySource, PrivateKeyText, SignPurpose, SignRequest};
use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::ipc::{self, Listener, Peer};
use crate::platform::SystemAgent;
use crate::prompts::{Decision, PromptInfo};
use crate::state::{show_main, AppState, EVENT_NOTICE};

const UNLOCK_WAIT: Duration = Duration::from_secs(60);
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// One key the agent offers.
pub struct KeyEntry {
    pub blob: Vec<u8>,
    pub title: String,
    pub confirm_each_use: bool,
    private_key: Zeroizing<String>,
    passphrase: Option<Zeroizing<String>>,
}

fn field_text<'a>(c: &'a ItemContent, purpose: &str, id: &str) -> Option<&'a str> {
    c.by_purpose(purpose)
        .or_else(|| c.field(id))
        .and_then(|f| f.value.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// The item opted out of the agent (`ssh.agent = false`).
fn excluded(c: &ItemContent) -> bool {
    c.ssh
        .as_ref()
        .is_some_and(|s| s.extra.get("agent") == Some(&Value::Bool(false)))
}

/// Public key blob of a private key text (for items without a public key field).
pub type DeriveBlob<'a> = &'a dyn Fn(&str, &str, i64, &str, Option<&str>) -> Option<Vec<u8>>;

/// The keys of `items` (`(vault, item, content)`), in order, without duplicates.
pub fn keys_from_items(
    items: &[(String, String, ItemContent)],
    derive: DeriveBlob<'_>,
) -> Vec<KeyEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (vault_id, item_id, c) in items {
        if c.template != "ssh_key" || excluded(c) {
            continue;
        }
        let Some(private) = field_text(c, "ssh-private-key", "private_key") else {
            continue;
        };
        let passphrase = c
            .field("passphrase")
            .and_then(|f| f.value.as_str())
            .filter(|s| !s.is_empty());
        let blob = field_text(c, "ssh-public-key", "public_key")
            .and_then(|p| npw_ssh::parse_public_key(p).ok())
            .map(|p| p.blob)
            .or_else(|| derive(vault_id, item_id, c.updated_at, private, passphrase));
        let Some(blob) = blob else {
            continue;
        };
        if !seen.insert(blob.clone()) {
            continue;
        }
        out.push(KeyEntry {
            blob,
            title: if c.title.is_empty() {
                "SSH key".into()
            } else {
                c.title.clone()
            },
            confirm_each_use: c.ssh.as_ref().is_none_or(|s| s.confirm_each_use),
            private_key: Zeroizing::new(private.to_string()),
            passphrase: passphrase.map(|p| Zeroizing::new(p.to_string())),
        });
    }
    out
}

fn derive_blob(private: &str, passphrase: Option<&str>) -> Option<Vec<u8>> {
    let info = npw_ssh::parse_private_key(private, passphrase).ok()?;
    npw_ssh::parse_public_key(&info.public_openssh)
        .ok()
        .map(|p| p.blob)
}

/// The keys of one request; dropped (and zeroized) right after it.
struct Snapshot(Vec<KeyEntry>);

impl Snapshot {
    fn find(&self, blob: &[u8]) -> Option<&KeyEntry> {
        self.0.iter().find(|k| k.blob == blob)
    }
}

impl KeySource for Snapshot {
    fn identities(&self) -> Vec<Identity> {
        self.0
            .iter()
            .map(|k| Identity {
                key_blob: k.blob.clone(),
                comment: k.title.clone(),
            })
            .collect()
    }

    fn private_key(&self, key_blob: &[u8]) -> Option<PrivateKeyText> {
        self.find(key_blob).map(|k| PrivateKeyText {
            private_key: k.private_key.clone(),
            passphrase: k.passphrase.clone(),
        })
    }
}

/// "Allow until the vault locks" decisions, by public key blob.
#[derive(Default)]
pub struct Grants(Mutex<HashSet<Vec<u8>>>);

impl Grants {
    /// Whether to sign: remembered, or asks (`ask`) and remembers as the answer says.
    pub fn check(
        &self,
        blob: &[u8],
        confirm_each_use: bool,
        ask: impl FnOnce() -> Decision,
    ) -> bool {
        if self.0.lock().expect("grants").contains(blob) {
            return true;
        }
        let remember = match ask() {
            Decision::Deny => return false,
            Decision::Session => true,
            Decision::Once => !confirm_each_use,
        };
        if remember {
            self.0.lock().expect("grants").insert(blob.to_vec());
        }
        true
    }

    pub fn clear(&self) {
        self.0.lock().expect("grants").clear();
    }
}

/// Human-readable purpose for the prompt.
pub fn describe(p: &SignPurpose) -> String {
    match p {
        SignPurpose::UserAuth {
            user,
            host_key_fingerprint,
            ..
        } => match host_key_fingerprint {
            Some(fp) => format!("SSH 登录（用户 {user}，服务器主机密钥 {fp}）"),
            None => format!("SSH 登录（用户 {user}）"),
        },
        SignPurpose::SshSig { namespace } if namespace == "git" => {
            "Git 提交 / 标签签名（SSHSIG，命名空间 git）".into()
        }
        SignPurpose::SshSig { namespace } => format!("SSHSIG 签名（命名空间 {namespace}）"),
        SignPurpose::Unknown => "未知用途的签名".into(),
    }
}

/// What the agent needs from the app (a trait so tests run without a vault UI).
pub trait Backend: Send + Sync + 'static {
    /// Waits until the vault is unlocked (asking the user); `false` if it stays locked.
    fn ensure_unlocked(&self) -> bool;
    fn keys(&self) -> Vec<KeyEntry>;
    fn approve(&self, req: &SignRequest, key: &KeyEntry, peer: &Peer) -> bool;
}

/// Answers one agent message (blocking: may wait for the user).
pub fn handle_message<B: Backend + ?Sized>(backend: &B, msg: &[u8], peer: &Peer) -> Vec<u8> {
    let needs_keys = matches!(
        msg.first(),
        Some(&SSH_AGENTC_REQUEST_IDENTITIES) | Some(&SSH_AGENTC_SIGN_REQUEST)
    );
    let snapshot = if needs_keys && backend.ensure_unlocked() {
        Snapshot(backend.keys())
    } else {
        Snapshot(Vec::new())
    };
    Agent::new().handle(msg, &snapshot, &mut |req| {
        snapshot
            .find(&req.key_blob)
            .is_some_and(|k| backend.approve(req, k, peer))
    })
}

/// Accepts connections until the task is aborted; aborting also ends every
/// connection (they live in the `JoinSet`).
pub async fn serve<B: Backend>(mut listener: Listener, backend: Arc<B>) {
    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((conn, peer)) => {
                    let b = backend.clone();
                    conns.spawn(connection(conn, peer, b));
                }
                Err(e) => {
                    log::warn!("ssh-agent: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

async fn connection<B: Backend>(mut conn: ipc::Conn, peer: Peer, backend: Arc<B>) {
    let peer = Arc::new(peer);
    loop {
        let msg = match ipc::read_frame(&mut conn, npw_ssh::agent::MAX_MESSAGE_LEN).await {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(e) => {
                log::info!("ssh-agent: closing a connection: {e}");
                return;
            }
        };
        let (b, p) = (backend.clone(), peer.clone());
        let reply = match tokio::task::spawn_blocking(move || handle_message(&*b, &msg, &p)).await {
            Ok(r) => r,
            Err(_) => return,
        };
        if ipc::write_frame(&mut conn, &reply).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------- the app's agent

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct AgentStatus {
    pub enabled: bool,
    pub running: bool,
    /// The pipe name / socket path in use (or tried).
    pub endpoint: String,
    pub default_endpoint: String,
    /// The value for `SSH_AUTH_SOCK` / `IdentityAgent`.
    pub auth_sock: String,
    pub error: String,
    /// Windows: the OpenSSH Authentication Agent service.
    pub system_agent: SystemAgent,
}

/// (vault, item, updated_at) of an item whose public key was derived.
type BlobKey = (String, String, i64);

#[derive(Default)]
pub struct SshAgent {
    pub grants: Grants,
    /// Derived public keys of items without a public key field, by (vault, item, updated_at).
    blobs: Mutex<HashMap<BlobKey, Option<Vec<u8>>>>,
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    status: Mutex<AgentStatus>,
}

impl SshAgent {
    pub fn status(&self) -> AgentStatus {
        self.status.lock().expect("status").clone()
    }

    /// Forgets the "until locked" approvals (called on every lock).
    pub fn on_lock(&self) {
        self.grants.clear();
    }

    fn stop(&self) {
        if let Some(t) = self.task.lock().expect("task").take() {
            t.abort();
        }
    }
}

struct AppBackend {
    app: AppHandle,
}

impl Backend for AppBackend {
    fn ensure_unlocked(&self) -> bool {
        let st = self.app.state::<AppState>();
        let Ok(c) = st.client() else { return false };
        if c.is_unlocked() {
            return true;
        }
        if !c.lock_state().signed_in {
            return false;
        }
        let _ = self
            .app
            .emit(EVENT_NOTICE, "SSH 客户端正在请求密钥，请先解锁 NyaPassword");
        show_main(&self.app);
        let start = Instant::now();
        while start.elapsed() < UNLOCK_WAIT {
            std::thread::sleep(Duration::from_millis(250));
            if c.is_unlocked() {
                return true;
            }
        }
        false
    }

    fn keys(&self) -> Vec<KeyEntry> {
        let st = self.app.state::<AppState>();
        let Ok(c) = st.client() else { return vec![] };
        let mut items = Vec::new();
        for archived in [false, true] {
            let filter = ItemFilter {
                template: Some("ssh_key".into()),
                archived,
                ..Default::default()
            };
            for v in c.list_items(&filter).unwrap_or_default() {
                if let Ok(Some(content)) = c.item(&v.vault_id, &v.item_id).map(|f| f.content) {
                    items.push((v.vault_id, v.item_id, content));
                }
            }
        }
        let cache = &st.ssh.blobs;
        let derive = |vault: &str, item: &str, updated: i64, private: &str, pass: Option<&str>| {
            let key = (vault.to_string(), item.to_string(), updated);
            if let Some(b) = cache.lock().expect("blobs").get(&key) {
                return b.clone();
            }
            let b = derive_blob(private, pass);
            cache.lock().expect("blobs").insert(key, b.clone());
            b
        };
        keys_from_items(&items, &derive)
    }

    fn approve(&self, req: &SignRequest, key: &KeyEntry, peer: &Peer) -> bool {
        let st = self.app.state::<AppState>();
        let info = PromptInfo::SshSign {
            key: key.title.clone(),
            fingerprint: req.fingerprint.clone(),
            algorithm: req.algorithm.clone(),
            purpose: describe(&req.purpose),
            process: peer.describe(),
            confirm_each_use: key.confirm_each_use,
        };
        let ok = st
            .ssh
            .grants
            .check(&req.key_blob, key.confirm_each_use, || {
                st.prompts.ask(&self.app, info, PROMPT_TIMEOUT)
            });
        log::info!(
            "ssh-agent: signature with \"{}\" for {} {}",
            key.title,
            peer.describe(),
            if ok { "approved" } else { "denied" }
        );
        ok
    }
}

/// The endpoint from the settings, or the platform default.
fn endpoint(st: &AppState) -> (String, String) {
    let default = st.platform.ssh_agent_default_endpoint(&st.dir);
    let configured = st.settings().ssh_agent.endpoint.trim().to_string();
    let ep = if configured.is_empty() {
        default.clone()
    } else {
        configured
    };
    (ep, default)
}

fn explain(
    e: &std::io::Error,
    display: &str,
    system: &SystemAgent,
    owner: Option<String>,
) -> String {
    // Windows: access denied / pipe busy (another first instance exists)
    let taken = (cfg!(windows) && matches!(e.raw_os_error(), Some(5) | Some(231)))
        || e.kind() == std::io::ErrorKind::AddrInUse
        || e.kind() == std::io::ErrorKind::PermissionDenied;
    if !taken {
        return format!("无法监听 {display}：{e}");
    }
    let mut m = match &owner {
        Some(o) => format!("{display} 已被 {o} 占用。"),
        None => format!("{display} 已被其他程序占用。"),
    };
    if owner.is_some() && system.state != "running" {
        m.push_str("可以关闭那个程序的 SSH agent 功能，或在下面改用其他管道名，并把 SSH_AUTH_SOCK 指向它。");
    } else if system.state == "running" {
        m.push_str("Windows 的 OpenSSH Authentication Agent 服务（ssh-agent）正在运行并占用了它：可以停用该服务（管理员 PowerShell：Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled），或在下面改用其他管道名，并把 SSH_AUTH_SOCK 指向它。");
    } else {
        m.push_str("可以关闭占用它的程序，或改用其他名称。");
    }
    m
}

/// Starts, restarts or stops the agent to match the settings.
pub async fn apply(app: &AppHandle) -> AgentStatus {
    let st = app.state::<AppState>();
    st.ssh.stop();
    let enabled = st.settings().ssh_agent.enabled;
    let (ep, default) = endpoint(&st);
    let platform = st.platform;
    let mut status = AgentStatus {
        enabled,
        running: false,
        endpoint: ep.clone(),
        default_endpoint: default,
        auth_sock: platform.ssh_auth_sock(&ep),
        error: String::new(),
        system_agent: tauri::async_runtime::spawn_blocking(move || platform.system_ssh_agent())
            .await
            .unwrap_or_default(),
    };
    if enabled {
        // the previous listener is gone once its task has been dropped
        tokio::time::sleep(Duration::from_millis(50)).await;
        match Listener::bind(&ep) {
            Ok(l) => {
                let backend = Arc::new(AppBackend { app: app.clone() });
                let task = tauri::async_runtime::spawn(serve(l, backend));
                *st.ssh.task.lock().expect("task") = Some(task);
                status.running = true;
                log::info!("ssh-agent listening on {}", status.auth_sock);
            }
            Err(e) => {
                let ep2 = ep.clone();
                let owner =
                    tauri::async_runtime::spawn_blocking(move || platform.endpoint_owner(&ep2))
                        .await
                        .ok()
                        .flatten();
                status.error = explain(&e, &status.auth_sock, &status.system_agent, owner);
                log::warn!("ssh-agent: {}", status.error);
            }
        }
    }
    *st.ssh.status.lock().expect("status") = status.clone();
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use npw_ssh::agent::{
        SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512,
    };
    use npw_ssh::ssh_key::{self, HashAlg};
    use npw_ssh::KeyKind;

    fn item(kind: KeyKind, title: &str, with_public: bool) -> (ItemContent, String) {
        let g = npw_ssh::generate(kind, "test@example.com").unwrap();
        let mut c = npw_model::template("ssh_key").unwrap().new_item("zh-CN");
        c.title = title.into();
        c.field_mut("private_key").unwrap().value = g.private_openssh.clone().into();
        if with_public {
            c.field_mut("public_key").unwrap().value = g.public_openssh.clone().into();
        }
        (c, g.public_openssh)
    }

    struct TestBackend {
        keys: Vec<(String, String, ItemContent)>,
        unlocked: bool,
        answer: Mutex<Decision>,
        asked: AtomicUsize,
        grants: Grants,
        peers: Mutex<Vec<Peer>>,
    }

    impl Backend for TestBackend {
        fn ensure_unlocked(&self) -> bool {
            self.unlocked
        }
        fn keys(&self) -> Vec<KeyEntry> {
            keys_from_items(&self.keys, &|_, _, _, p, pass| derive_blob(p, pass))
        }
        fn approve(&self, req: &SignRequest, key: &KeyEntry, peer: &Peer) -> bool {
            self.peers.lock().unwrap().push(peer.clone());
            self.grants.check(&req.key_blob, key.confirm_each_use, || {
                self.asked.fetch_add(1, Ordering::SeqCst);
                *self.answer.lock().unwrap()
            })
        }
    }

    fn put_string(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }

    fn take_string(b: &mut &[u8]) -> Vec<u8> {
        let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
        let s = b[4..4 + n].to_vec();
        *b = &b[4 + n..];
        s
    }

    async fn request(conn: &mut ipc::Conn, body: &[u8]) -> Vec<u8> {
        ipc::write_frame(conn, body).await.unwrap();
        ipc::read_frame(conn, 1 << 20).await.unwrap().unwrap()
    }

    async fn identities(conn: &mut ipc::Conn) -> Vec<(Vec<u8>, String)> {
        let r = request(conn, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
        assert_eq!(r[0], SSH_AGENT_IDENTITIES_ANSWER);
        let n = u32::from_be_bytes(r[1..5].try_into().unwrap());
        let mut rest = &r[5..];
        (0..n)
            .map(|_| {
                let blob = take_string(&mut rest);
                let comment = String::from_utf8(take_string(&mut rest)).unwrap();
                (blob, comment)
            })
            .collect()
    }

    /// Signs SSHSIG data the way `ssh-keygen -Y sign` does over the agent and
    /// returns the armored signature (`None` if the agent refused).
    async fn sshsig_over_agent(
        conn: &mut ipc::Conn,
        public: &str,
        msg: &[u8],
        flags: u32,
    ) -> Option<String> {
        let pk = ssh_key::PublicKey::from_openssh(public).unwrap();
        let blob = pk.to_bytes().unwrap();
        let data = ssh_key::SshSig::signed_data("git", HashAlg::Sha512, msg).unwrap();
        let mut req = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut req, &blob);
        put_string(&mut req, &data);
        req.extend_from_slice(&flags.to_be_bytes());
        let r = request(conn, &req).await;
        if r == [npw_ssh::agent::SSH_AGENT_FAILURE] {
            return None;
        }
        assert_eq!(r[0], npw_ssh::agent::SSH_AGENT_SIGN_RESPONSE);
        let mut rest = &r[1..];
        let sig_blob = take_string(&mut rest);
        let mut s = sig_blob.as_slice();
        let alg = String::from_utf8(take_string(&mut s)).unwrap();
        let raw = take_string(&mut s);
        let sig = ssh_key::Signature::new(ssh_key::Algorithm::new(&alg).unwrap(), raw).unwrap();
        let sshsig =
            ssh_key::SshSig::new(pk.key_data().clone(), "git", HashAlg::Sha512, sig).unwrap();
        Some(sshsig.to_pem(ssh_key::LineEnding::LF).unwrap())
    }

    fn pipe_name() -> String {
        let n = format!(
            "npw-test-agent-{}-{}",
            std::process::id(),
            npw_model::new_id()
        );
        if cfg!(windows) {
            n
        } else {
            std::env::temp_dir().join(n).display().to_string()
        }
    }

    #[test]
    fn agent_over_a_real_pipe() {
        let (ed, ed_pub) = item(KeyKind::Ed25519, "Ed25519 key", true);
        let (ec, ec_pub) = item(KeyKind::EcdsaP256, "ECDSA key", false); // public key derived
        let (rsa, rsa_pub) = item(KeyKind::Rsa3072, "RSA key", true);
        let (mut off, _) = item(KeyKind::Ed25519, "Not for the agent", true);
        off.ssh
            .as_mut()
            .unwrap()
            .extra
            .insert("agent".into(), false.into());
        let mut ec = ec;
        ec.ssh.as_mut().unwrap().confirm_each_use = false;
        let keys: Vec<_> = [ed, ec, rsa, off]
            .into_iter()
            .enumerate()
            .map(|(i, c)| ("v".to_string(), format!("i{i}"), c))
            .collect();
        let backend = Arc::new(TestBackend {
            keys,
            unlocked: true,
            answer: Mutex::new(Decision::Once),
            asked: AtomicUsize::new(0),
            grants: Grants::default(),
            peers: Mutex::new(vec![]),
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let name = pipe_name();
            let listener = Listener::bind(&name).unwrap();
            let server = tokio::spawn(serve(listener, backend.clone()));
            let mut conn = ipc::connect(&name).await.unwrap();

            // identities: three keys, the opted-out one is not offered
            let ids = identities(&mut conn).await;
            let titles: Vec<_> = ids.iter().map(|i| i.1.as_str()).collect();
            assert_eq!(titles, ["Ed25519 key", "ECDSA key", "RSA key"]);

            // SSHSIG ("git") with each algorithm; RSA with rsa-sha2-512 (ssh-keygen) and -256
            let msg = b"tree 0123\nauthor Test <test@example.com>\n\ncommit message\n";
            for (public, flags) in [
                (&ed_pub, 0),
                (&ec_pub, 0),
                (&rsa_pub, SSH_AGENT_RSA_SHA2_512),
                (&rsa_pub, SSH_AGENT_RSA_SHA2_256),
            ] {
                let armored = sshsig_over_agent(&mut conn, public, msg, flags)
                    .await
                    .expect("signed");
                npw_ssh::sshsig_verify(public, "git", msg, &armored).unwrap();
                assert!(npw_ssh::sshsig_verify(public, "git", b"other", &armored).is_err());
            }
            // legacy ssh-rsa (SHA-1) is refused
            assert!(sshsig_over_agent(&mut conn, &rsa_pub, msg, 0)
                .await
                .is_none());
            // every signature was confirmed, except the ECDSA key after its first one
            // (confirm_each_use = false remembers "allow once" until the vault locks)
            assert_eq!(backend.asked.load(Ordering::SeqCst), 4);
            assert!(sshsig_over_agent(&mut conn, &ec_pub, msg, 0)
                .await
                .is_some());
            assert_eq!(backend.asked.load(Ordering::SeqCst), 4);

            // deny
            *backend.answer.lock().unwrap() = Decision::Deny;
            assert!(sshsig_over_agent(&mut conn, &ed_pub, msg, 0)
                .await
                .is_none());
            // allow until locked: asked once, then remembered; cleared on lock
            *backend.answer.lock().unwrap() = Decision::Session;
            let before = backend.asked.load(Ordering::SeqCst);
            assert!(sshsig_over_agent(&mut conn, &ed_pub, msg, 0)
                .await
                .is_some());
            assert!(sshsig_over_agent(&mut conn, &ed_pub, msg, 0)
                .await
                .is_some());
            assert_eq!(backend.asked.load(Ordering::SeqCst), before + 1);
            backend.grants.clear();
            *backend.answer.lock().unwrap() = Decision::Deny;
            assert!(sshsig_over_agent(&mut conn, &ed_pub, msg, 0)
                .await
                .is_none());

            // adding keys / unknown messages: failure, connection stays usable
            assert_eq!(
                request(&mut conn, &[17, 0, 0, 0, 0]).await,
                [npw_ssh::agent::SSH_AGENT_FAILURE]
            );
            assert_eq!(identities(&mut conn).await.len(), 3);

            // the agent sees which process asks
            let peers = backend.peers.lock().unwrap().clone();
            if cfg!(windows) {
                assert_eq!(peers[0].pid, Some(std::process::id()));
            }
            server.abort();
        });
    }

    #[test]
    fn locked_vault_offers_nothing() {
        let (ed, _) = item(KeyKind::Ed25519, "k", true);
        let b = TestBackend {
            keys: vec![("v".into(), "i".into(), ed)],
            unlocked: false,
            answer: Mutex::new(Decision::Once),
            asked: AtomicUsize::new(0),
            grants: Grants::default(),
            peers: Mutex::new(vec![]),
        };
        let r = handle_message(&b, &[SSH_AGENTC_REQUEST_IDENTITIES], &Peer::default());
        assert_eq!(r, [SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]);
    }

    #[test]
    fn taken_endpoint_messages() {
        let taken = if cfg!(windows) {
            std::io::Error::from_raw_os_error(5)
        } else {
            std::io::Error::from(std::io::ErrorKind::AddrInUse)
        };
        let stopped = SystemAgent {
            state: "stopped".into(),
            start_type: "disabled".into(),
        };
        let m = explain(&taken, "P", &stopped, Some("Bitwarden.exe".into()));
        assert!(
            m.contains("Bitwarden.exe") && m.contains("SSH_AUTH_SOCK"),
            "{m}"
        );
        let running = SystemAgent {
            state: "running".into(),
            start_type: "auto".into(),
        };
        let m = explain(&taken, "P", &running, Some("ssh-agent.exe".into()));
        assert!(m.contains("Stop-Service ssh-agent"), "{m}");
        let other = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        assert!(explain(&other, "P", &stopped, None).starts_with("无法监听"));
    }

    #[test]
    fn purposes() {
        assert!(describe(&SignPurpose::SshSig {
            namespace: "git".into()
        })
        .contains("Git"));
        assert!(describe(&SignPurpose::UserAuth {
            user: "git".into(),
            service: "ssh-connection".into(),
            method: "publickey".into(),
            host_key_fingerprint: None
        })
        .contains("git"));
    }
}
