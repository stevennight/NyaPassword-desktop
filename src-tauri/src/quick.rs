//! Quick Access (design doc §10.3): a global shortcut (default
//! Ctrl+Shift+Alt+Space) remembers the focused window of another program and
//! opens a small search window (`desktop.html#quick`). Enter auto-types the
//! chosen login into the remembered window; buttons copy the username,
//! password or one-time code.

use npw_core::{ItemFilter, ItemView};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};

use crate::autotype;
use crate::platform::TargetWindow;
use crate::state::AppState;

pub const LABEL: &str = "quick";
pub const EVENT_OPEN: &str = "npw:quick-open";

/// Parses a shortcut such as `Ctrl+Shift+Space` / `Alt+K`.
pub fn parse_shortcut(s: &str) -> Result<Shortcut, String> {
    s.trim()
        .parse::<Shortcut>()
        .map_err(|e| format!("快捷键 “{s}” 无效：{e}"))
}

/// Registers (or removes) the global shortcut per the settings. The error
/// (e.g. another program owns the shortcut) is also kept for the settings page.
pub fn apply_shortcut(app: &AppHandle) -> Result<(), String> {
    let st = app.state::<AppState>();
    let s = st.settings().quick_access;
    let gs = app.global_shortcut();
    let _ = gs.unregister_all();
    let result = if s.enabled {
        parse_shortcut(&s.shortcut).and_then(|sc| {
            gs.on_shortcut(sc, |app, _sc, ev| {
                if ev.state() == ShortcutState::Pressed {
                    toggle(app);
                }
            })
            .map_err(|e| format!("无法注册快捷键 {}（可能已被其他程序占用）：{e}", s.shortcut))
        })
    } else {
        Ok(())
    };
    *st.quick_error.lock().expect("quick") = result.clone().err().unwrap_or_default();
    if let Err(e) = &result {
        log::warn!("quick access: {e}");
    }
    result
}

fn toggle(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(LABEL) {
        if w.is_visible().unwrap_or(false) && w.is_focused().unwrap_or(false) {
            let _ = w.hide();
            return;
        }
    }
    open(app);
}

fn build_window(app: &AppHandle) -> tauri::Result<tauri::WebviewWindow> {
    let mut b = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("desktop.html#quick".into()))
        .title("NyaPassword 快捷搜索")
        .inner_size(640.0, 460.0)
        .resizable(false)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .center()
        .visible(false);
    if let Some(a) = crate::prompts::test_webview_args() {
        b = b.additional_browser_args(&a);
    }
    b.build()
}

/// Remembers the focused window, then shows Quick Access.
pub fn open(app: &AppHandle) {
    let st = app.state::<AppState>();
    let target = st.platform.foreground_window();
    *st.quick_target.lock().expect("quick") = target;
    st.quick_grant.clear();
    let w = match app.get_webview_window(LABEL) {
        Some(w) => w,
        None => match build_window(app) {
            Ok(w) => w,
            Err(e) => {
                log::error!("cannot open Quick Access: {e}");
                return;
            }
        },
    };
    let _ = app.emit_to(LABEL, EVENT_OPEN, ());
    let _ = w.center();
    let _ = w.show();
    let _ = w.unminimize();
    let _ = w.set_focus();
}

/// Shows Quick Access again without changing the target window.
pub fn reshow(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(LABEL) {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn hide(app: &AppHandle) {
    app.state::<AppState>().quick_grant.clear();
    if let Some(w) = app.get_webview_window(LABEL) {
        let _ = w.hide();
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QuickContext {
    pub signed_in: bool,
    pub unlocked: bool,
    pub target: Option<TargetWindow>,
    /// Items that fit the target window, best first.
    pub matches: Vec<ItemView>,
    pub can_type: bool,
    pub shortcut: String,
}

/// Non-trashed items (archived ones too: they still take part in filling).
fn all_items(c: &npw_core::Client, query: &str) -> Vec<ItemView> {
    let mut out = Vec::new();
    for archived in [false, true] {
        let f = ItemFilter {
            archived,
            query: query.to_string(),
            ..Default::default()
        };
        out.extend(c.list_items(&f).unwrap_or_default());
    }
    out
}

pub fn context(st: &AppState) -> QuickContext {
    let target = st.quick_target.lock().expect("quick").clone();
    let mut ctx = QuickContext {
        signed_in: false,
        unlocked: false,
        target: target.clone(),
        matches: vec![],
        can_type: target.is_some() && st.platform.auto_type_supported(),
        shortcut: st.settings().quick_access.shortcut,
    };
    let Ok(c) = st.client() else { return ctx };
    let ls = c.lock_state();
    ctx.signed_in = ls.signed_in;
    ctx.unlocked = ls.unlocked;
    let Some(t) = target.filter(|_| ls.unlocked) else {
        return ctx;
    };
    let mut scored: Vec<(i64, ItemView)> = all_items(&c, "")
        .into_iter()
        .filter_map(|v| {
            let content = c.item(&v.vault_id, &v.item_id).ok()?.content?;
            if content.autofill.never {
                return None;
            }
            let s = autotype::window_score(&content, &t.title, &t.process)?;
            Some((s, v))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.updated_at.cmp(&a.1.updated_at)));
    ctx.matches = scored.into_iter().take(20).map(|(_, v)| v).collect();
    ctx
}

pub fn search(st: &AppState, query: &str) -> Vec<ItemView> {
    let Ok(c) = st.client() else { return vec![] };
    let mut v = all_items(&c, query);
    v.truncate(50);
    v
}
