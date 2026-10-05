//! Small always-on-top confirmation windows: an SSH signature, pairing a
//! browser extension. The caller blocks (on a worker thread) until the user
//! answers, closes the window, or the request times out (= deny).
//!
//! A signature with a key whose item is marked "使用前需要验证" can only be
//! approved after the window verified the user (`mark_verified`: master
//! password or Windows Hello), and only once: there is no "until locked".

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

/// Label prefix of prompt windows (the capability file allows `prompt-*`).
pub const LABEL_PREFIX: &str = "prompt-";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Allow this request.
    Once,
    /// Allow this and later requests until the vault locks.
    Session,
    Deny,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PromptInfo {
    SshSign {
        /// Item title.
        key: String,
        fingerprint: String,
        algorithm: String,
        /// What the signature is for, in words ("登录 git@203.0.113.7", "Git 提交签名" ...).
        purpose: String,
        /// The requesting program, if known.
        process: String,
        /// `false`: the item asks only once per unlock (any "allow" remembers it).
        confirm_each_use: bool,
        /// The item is marked "使用前需要验证": approving needs the user
        /// verified, every time.
        reprompt: bool,
    },
    Pair {
        browser: String,
        extension_id: String,
        /// Six digits the extension shows too.
        code: String,
    },
}

impl PromptInfo {
    /// Approving needs the user verified first.
    pub fn needs_verify(&self) -> bool {
        matches!(self, PromptInfo::SshSign { reprompt: true, .. })
    }

    fn title(&self) -> &'static str {
        match self {
            PromptInfo::SshSign { .. } => "NyaPassword · SSH 签名请求",
            PromptInfo::Pair { .. } => "NyaPassword · 浏览器扩展配对",
        }
    }
}

struct Open {
    info: PromptInfo,
    tx: mpsc::SyncSender<Decision>,
    /// The user verified in this window (see [`PromptInfo::needs_verify`]).
    verified: bool,
}

type Pending = HashMap<String, Open>;

#[derive(Default)]
pub struct Prompts {
    next: AtomicU64,
    pending: Mutex<Pending>,
}

/// Debug builds only: extra WebView2 arguments from `NPW_TEST_WEBVIEW_ARGS`
/// (e.g. `--remote-debugging-port=9222`, so a test can drive the windows over
/// CDP). Every window must get the same arguments: WebView2 refuses windows
/// whose options differ within one app. `None` in release builds.
pub fn test_webview_args() -> Option<String> {
    #[cfg(debug_assertions)]
    {
        if let Ok(a) = std::env::var("NPW_TEST_WEBVIEW_ARGS") {
            // keep wry's defaults, add the test's
            return Some(format!(
                "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection {a}"
            ));
        }
    }
    None
}

/// Debug builds only: `NPW_TEST_AUTO_APPROVE=1` answers every prompt with
/// "allow once" (automated tests of the agent with real OpenSSH tools).
/// Compiled out of release builds.
fn test_auto_approve() -> bool {
    #[cfg(debug_assertions)]
    {
        if std::env::var("NPW_TEST_AUTO_APPROVE").as_deref() == Ok("1") {
            log::warn!("NPW_TEST_AUTO_APPROVE is set: approving without asking (debug build)");
            return true;
        }
    }
    false
}

impl Prompts {
    /// Shows the prompt and waits for the answer. Must not run on the main
    /// thread (it blocks while the window is open).
    pub fn ask(&self, app: &AppHandle, info: PromptInfo, timeout: Duration) -> Decision {
        if test_auto_approve() {
            return Decision::Once;
        }
        let id = format!(
            "{LABEL_PREFIX}{}",
            self.next.fetch_add(1, Ordering::SeqCst) + 1
        );
        let (tx, rx) = mpsc::sync_channel(1);
        let title = info.title();
        let tall = info.needs_verify();
        self.pending.lock().expect("prompts").insert(
            id.clone(),
            Open {
                info,
                tx,
                verified: false,
            },
        );
        let mut builder = WebviewWindowBuilder::new(
            app,
            &id,
            WebviewUrl::App(format!("desktop.html#prompt={id}").into()),
        );
        if let Some(a) = test_webview_args() {
            builder = builder.additional_browser_args(&a);
        }
        let built = builder
            .title(title)
            .inner_size(460.0, if tall { 460.0 } else { 360.0 })
            .resizable(false)
            .minimizable(false)
            .maximizable(false)
            .always_on_top(true)
            .center()
            .focused(true)
            .build();
        let decision = match built {
            Ok(_) => rx.recv_timeout(timeout).unwrap_or(Decision::Deny),
            Err(e) => {
                log::error!("cannot open the confirmation window: {e}");
                Decision::Deny
            }
        };
        self.pending.lock().expect("prompts").remove(&id);
        if let Some(w) = app.get_webview_window(&id) {
            let _ = w.destroy();
        }
        decision
    }

    pub fn info(&self, id: &str) -> Option<PromptInfo> {
        self.pending
            .lock()
            .expect("prompts")
            .get(id)
            .map(|o| o.info.clone())
    }

    /// The window verified the user (master password / Windows Hello).
    pub fn mark_verified(&self, id: &str) -> bool {
        match self.pending.lock().expect("prompts").get_mut(id) {
            Some(o) => {
                o.verified = true;
                true
            }
            None => false,
        }
    }

    /// The window answered (or was closed: `Deny`). Returns whether the
    /// answer was taken: approving a prompt that needs verification is
    /// refused (the prompt stays open) until the window verified the user,
    /// and "until locked" counts as "once" there.
    pub fn respond(&self, id: &str, d: Decision) -> bool {
        let mut pending = self.pending.lock().expect("prompts");
        let Some(o) = pending.get(id) else {
            return false;
        };
        let d = match (d, o.info.needs_verify()) {
            (Decision::Deny, _) | (_, false) => d,
            (_, true) if !o.verified => return false,
            (_, true) => Decision::Once,
        };
        let o = pending.remove(id).expect("checked above");
        let _ = o.tx.try_send(d);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respond_once_and_serialization() {
        let p = Prompts::default();
        let (tx, rx) = mpsc::sync_channel(1);
        let info = PromptInfo::Pair {
            browser: "Chrome".into(),
            extension_id: "a".repeat(32),
            code: "123456".into(),
        };
        p.pending.lock().unwrap().insert(
            "prompt-1".into(),
            Open {
                info: info.clone(),
                tx,
                verified: false,
            },
        );
        assert_eq!(p.info("prompt-1"), Some(info));
        assert!(p.respond("prompt-1", Decision::Session));
        assert!(!p.respond("prompt-1", Decision::Deny));
        assert_eq!(rx.recv().unwrap(), Decision::Session);
        let v = serde_json::to_value(PromptInfo::SshSign {
            key: "k".into(),
            fingerprint: "SHA256:x".into(),
            algorithm: "ssh-ed25519".into(),
            purpose: "p".into(),
            process: String::new(),
            confirm_each_use: true,
            reprompt: false,
        })
        .unwrap();
        assert_eq!(v["kind"], "ssh_sign");
        assert_eq!(v["reprompt"], false);
        let d: Decision = serde_json::from_str("\"session\"").unwrap();
        assert_eq!(d, Decision::Session);
    }

    fn reprompt_sign() -> PromptInfo {
        PromptInfo::SshSign {
            key: "k".into(),
            fingerprint: "SHA256:x".into(),
            algorithm: "ssh-ed25519".into(),
            purpose: "p".into(),
            process: String::new(),
            confirm_each_use: true,
            reprompt: true,
        }
    }

    fn open(p: &Prompts, id: &str, info: PromptInfo) -> mpsc::Receiver<Decision> {
        let (tx, rx) = mpsc::sync_channel(1);
        p.pending.lock().unwrap().insert(
            id.into(),
            Open {
                info,
                tx,
                verified: false,
            },
        );
        rx
    }

    #[test]
    fn reprompt_needs_verification_before_approval() {
        let p = Prompts::default();
        let rx = open(&p, "prompt-2", reprompt_sign());
        assert!(reprompt_sign().needs_verify());
        // approving without verifying is refused and the prompt stays open
        assert!(!p.respond("prompt-2", Decision::Once));
        assert!(!p.respond("prompt-2", Decision::Session));
        assert!(p.info("prompt-2").is_some());
        assert!(rx.try_recv().is_err());
        // verified: "until locked" is only "once" for such a key
        assert!(p.mark_verified("prompt-2"));
        assert!(p.respond("prompt-2", Decision::Session));
        assert_eq!(rx.recv().unwrap(), Decision::Once);
        assert!(!p.mark_verified("prompt-2"), "closed");

        // denying (or closing the window) always works
        let rx = open(&p, "prompt-3", reprompt_sign());
        assert!(p.respond("prompt-3", Decision::Deny));
        assert_eq!(rx.recv().unwrap(), Decision::Deny);

        // a verification belongs to its own window
        let rx4 = open(&p, "prompt-4", reprompt_sign());
        let _rx5 = open(&p, "prompt-5", reprompt_sign());
        assert!(p.mark_verified("prompt-5"));
        assert!(!p.respond("prompt-4", Decision::Once));
        assert!(rx4.try_recv().is_err());
    }
}
