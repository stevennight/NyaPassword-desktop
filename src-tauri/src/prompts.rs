//! Small always-on-top confirmation windows: an SSH signature, pairing a
//! browser extension. The caller blocks (on a worker thread) until the user
//! answers, closes the window, or the request times out (= deny).

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
    },
    Pair {
        browser: String,
        extension_id: String,
        /// Six digits the extension shows too.
        code: String,
    },
}

impl PromptInfo {
    fn title(&self) -> &'static str {
        match self {
            PromptInfo::SshSign { .. } => "NyaPassword · SSH 签名请求",
            PromptInfo::Pair { .. } => "NyaPassword · 浏览器扩展配对",
        }
    }
}

type Pending = HashMap<String, (PromptInfo, mpsc::SyncSender<Decision>)>;

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
        self.pending
            .lock()
            .expect("prompts")
            .insert(id.clone(), (info, tx));
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
            .inner_size(460.0, 360.0)
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
            .map(|(i, _)| i.clone())
    }

    /// The window answered (or was closed: `Deny`). Returns whether the prompt was still open.
    pub fn respond(&self, id: &str, d: Decision) -> bool {
        match self.pending.lock().expect("prompts").remove(id) {
            Some((_, tx)) => {
                let _ = tx.try_send(d);
                true
            }
            None => false,
        }
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
        p.pending
            .lock()
            .unwrap()
            .insert("prompt-1".into(), (info.clone(), tx));
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
        })
        .unwrap();
        assert_eq!(v["kind"], "ssh_sign");
        let d: Decision = serde_json::from_str("\"session\"").unwrap();
        assert_eq!(d, Decision::Session);
    }
}
