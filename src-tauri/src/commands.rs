//! Tauri commands: one per method of the UI's `Bridge` interface
//! (common/web/src/lib/bridge.ts), with the same semantics as the WASM bridge
//! (npw-wasm), plus a few desktop-only ones (settings, export, update).
//!
//! Binary arguments travel as the raw request body with the other arguments
//! as percent-encoded JSON in the `npw-args` header; binary results as raw
//! responses.

use npw_core::{EmergencyKit, ItemFilter, LockState};
use npw_model::ItemContent;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::Ordering;
use tauri::ipc::{InvokeBody, Request, Response};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::error::{BridgeError, CmdResult};
use crate::export;
use crate::local_unlock::{self, Stale};
use crate::platform::QuickError;
use crate::quick_unlock;
use crate::settings::{ExportSettings, Pairing};
use crate::state::{now_ms, AppState, EVENT_EXPORT};
use crate::updater;
use crate::verify::{Verifier, VerifyOptions};
use crate::{autotype, browser_bridge, prompts, quick, ssh_agent};

type St<'a> = State<'a, AppState>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(BridgeError::invalid)
}

fn percent_decode(s: &str) -> CmdResult<String> {
    let bad = || BridgeError::invalid("bad npw-args header");
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3).ok_or_else(bad)?;
            let v = std::str::from_utf8(hex)
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(bad)?;
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| bad())
}

/// The JSON arguments (header) and the binary body of a raw request.
fn raw_args<'r, T: DeserializeOwned>(req: &'r Request<'_>) -> CmdResult<(T, &'r [u8])> {
    let body = match req.body() {
        InvokeBody::Raw(b) => b.as_slice(),
        InvokeBody::Json(_) => return Err(BridgeError::invalid("expected a binary body")),
    };
    let header = req
        .headers()
        .get("npw-args")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("{}");
    let args = serde_json::from_str(&percent_decode(header)?).map_err(BridgeError::invalid)?;
    Ok((args, body))
}

// ---------------------------------------------------------------- account

#[tauri::command]
pub fn lock_state(state: St<'_>) -> CmdResult<LockState> {
    Ok(state.client()?.lock_state())
}

#[tauri::command]
pub async fn register(
    state: St<'_>,
    server: String,
    login: String,
    password: String,
    invite: Option<String>,
) -> CmdResult<EmergencyKit> {
    let password = Zeroizing::new(password);
    let c = state.client()?;
    let kit = c
        .register(
            &server,
            &login,
            &password,
            invite.as_deref().filter(|s| !s.is_empty()),
        )
        .await?;
    state.mark_password_unlock();
    state.notify_unlocked();
    Ok(kit)
}

#[tauri::command]
pub async fn sign_in(
    app: AppHandle,
    state: St<'_>,
    server: String,
    login: String,
    password: String,
    secret_key: String,
) -> CmdResult<()> {
    let password = Zeroizing::new(password);
    let secret_key = Zeroizing::new(secret_key);
    let c = state.client()?;
    c.sign_in(&server, &login, &password, &secret_key).await?;
    after_password_unlock(&app, &state, password);
    Ok(())
}

#[tauri::command]
pub async fn unlock(app: AppHandle, state: St<'_>, password: String) -> CmdResult<()> {
    let password = Zeroizing::new(password);
    let c = state.client()?;
    let pw = password.clone();
    blocking(move || c.unlock(&pw)).await??;
    after_password_unlock(&app, &state, password);
    Ok(())
}

/// Records the password unlock (quick unlock rules) and runs the scheduled
/// export when it is due, with the password the user just typed. The password
/// lives only as long as that export; it is never written anywhere.
fn after_password_unlock(app: &AppHandle, state: &AppState, password: Zeroizing<String>) {
    let s = state.mark_password_unlock();
    state.notify_unlocked();
    if !export::is_due(&s.export, now_ms()) || state.exporting.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let st = app.state::<AppState>();
        let result = run_export(&st, &password).await;
        drop(password);
        st.exporting.store(false, Ordering::SeqCst);
        let _ = app.emit(EVENT_EXPORT, ExportEvent::from(&result));
    });
}

#[derive(Debug, Clone, Serialize)]
struct ExportEvent {
    ok: bool,
    message: String,
    files: Vec<String>,
}

impl From<&Result<export::Outcome, String>> for ExportEvent {
    fn from(r: &Result<export::Outcome, String>) -> Self {
        match r {
            Ok(o) => Self {
                ok: true,
                message: String::new(),
                files: o.files.clone(),
            },
            Err(e) => Self {
                ok: false,
                message: e.clone(),
                files: vec![],
            },
        }
    }
}

async fn run_export(state: &AppState, password: &str) -> Result<export::Outcome, String> {
    let c = state.client().map_err(|e| e.message)?;
    let s = state.settings().export;
    let result = export::run(&c, &s, password).await;
    let now = now_ms();
    state.update_settings(|st| match &result {
        Ok(_) => {
            st.export.last_export_at = now;
            st.export.last_error.clear();
        }
        Err(e) => st.export.last_error = e.clone(),
    });
    match &result {
        Ok(o) => log::info!(
            "offline export written: {:?} (pruned {:?})",
            o.files,
            o.pruned
        ),
        Err(e) => log::warn!("offline export failed: {e}"),
    }
    result
}

#[tauri::command]
pub fn lock(state: St<'_>) -> CmdResult<()> {
    state.lock();
    Ok(())
}

// ---------------------------------------------------------------- verify again ("使用前需要验证")

/// Whether Windows Hello can verify the user (items marked "使用前需要验证").
#[tauri::command]
pub async fn verify_user_options(state: St<'_>) -> CmdResult<VerifyOptions> {
    let v = Verifier::new(&state)?;
    blocking(move || v.options()).await
}

/// Verifies the user without changing the lock state: the master password,
/// else the PIN, else Windows Hello (both empty).
#[tauri::command]
pub async fn verify_user(
    state: St<'_>,
    password: Option<String>,
    pin: Option<String>,
) -> CmdResult<()> {
    let password = password.map(Zeroizing::new);
    let pin = pin.map(Zeroizing::new);
    let v = Verifier::new(&state)?;
    blocking(move || v.verify(secret(&password), secret(&pin))).await?
}

fn secret(s: &Option<Zeroizing<String>>) -> Option<&str> {
    s.as_deref().map(|p| p.as_str())
}

#[tauri::command]
pub async fn sign_out(state: St<'_>, force: bool) -> CmdResult<()> {
    let c = state.client()?;
    let account = c.lock_state().account_id;
    c.sign_out(force).await?;
    state.lock();
    disable_quick_unlock(&state, &account).await;
    state.password_this_run.store(false, Ordering::SeqCst);
    state.guards.forget();
    Ok(())
}

#[tauri::command]
pub fn emergency_kit(state: St<'_>) -> CmdResult<EmergencyKit> {
    Ok(state.client()?.emergency_kit()?)
}

// ---------------------------------------------------------------- quick unlock

/// What the lock screen and the settings can offer (bridge.ts `QuickUnlockStatus`).
#[derive(Debug, Clone, Serialize)]
pub struct QuickStatus {
    /// The OS offers Windows Hello.
    available: bool,
    /// Windows Hello can unlock right now.
    enabled: bool,
    label: String,
    /// Windows Hello unlock is set up (it may be suspended right now).
    quick_set: bool,
    /// "启动时可直接用生物识别解锁".
    biometric_at_start: bool,
    /// The PIN can be set up here (the OS credential store works).
    pin_supported: bool,
    pin_set: bool,
    /// The PIN can unlock right now.
    pin: bool,
    pin_tries_left: u32,
    /// Why biometrics and the PIN need the master password now (empty: they do not).
    password_reason: String,
}

fn quick_allowed(state: &AppState, account: &str) -> Result<(), Stale> {
    state.guards.quick_allowed(
        account,
        now_ms(),
        state.password_this_run.load(Ordering::SeqCst),
        state.settings().unlock.biometric_at_start,
    )
}

#[tauri::command]
pub async fn quick_unlock_status(state: St<'_>) -> CmdResult<QuickStatus> {
    let c = state.client()?;
    let lock = c.lock_state();
    let platform = state.platform;
    let supported = lock.signed_in && blocking(move || platform.quick_unlock_supported()).await?;
    let quick_set = quick_unlock::load(&state.dir)
        .filter(|s| s.account_id == lock.account_id)
        .is_some();
    let allowed = quick_allowed(&state, &lock.account_id);
    let pin = state.guards.pin_status(&lock.account_id, now_ms());
    let reason = match allowed {
        Ok(()) => String::new(),
        // a restart only stops biometrics; the PIN still works
        Err(Stale::Restarted) if pin.usable => String::new(),
        Err(s) => s.message().into(),
    };
    Ok(QuickStatus {
        available: supported,
        enabled: supported && quick_set && allowed.is_ok(),
        label: platform.quick_unlock_label().into(),
        quick_set: supported && quick_set,
        biometric_at_start: state.settings().unlock.biometric_at_start,
        pin_supported: lock.signed_in && pin.supported,
        pin_set: pin.set,
        pin: lock.signed_in && pin.usable,
        pin_tries_left: pin.tries_left,
        password_reason: if quick_set || pin.set {
            reason
        } else {
            String::new()
        },
    })
}

async fn disable_quick_unlock(state: &AppState, account_id: &str) {
    quick_unlock::remove(&state.dir);
    if account_id.is_empty() {
        return;
    }
    let platform = state.platform;
    let name = quick_unlock::credential_name(account_id);
    let _ = blocking(move || platform.quick_unlock_delete(&name)).await;
}

#[tauri::command]
pub async fn set_quick_unlock(state: St<'_>, enabled: bool) -> CmdResult<()> {
    let c = state.client()?;
    let account = c.lock_state().account_id;
    if !enabled {
        disable_quick_unlock(&state, &account).await;
        return Ok(());
    }
    // within 14 days of a master-password unlock on this device
    if let Err(s) = local_unlock::fresh(&state.guards.get(&account), now_ms()) {
        return Err(BridgeError::new("password_required", s.message()));
    }
    let ak = Zeroizing::new(c.quick_unlock_key()?);
    let challenge = npw_crypto::random_bytes::<32>();
    let platform = state.platform;
    let name = quick_unlock::credential_name(&account);
    let signature = Zeroizing::new(
        blocking(move || platform.quick_unlock_create(&name, &challenge))
            .await?
            .map_err(BridgeError::invalid)?,
    );
    let stored = quick_unlock::wrap(&ak, &signature, &challenge, &account, now_ms())
        .map_err(BridgeError::invalid)?;
    quick_unlock::save(&state.dir, &stored).map_err(BridgeError::invalid)?;
    Ok(())
}

#[tauri::command]
pub async fn quick_unlock(state: St<'_>) -> CmdResult<()> {
    let c = state.client()?;
    let account = c.lock_state().account_id;
    let label = state.platform.quick_unlock_label();
    if let Err(s) = quick_allowed(&state, &account) {
        return Err(BridgeError::new("password_required", s.message()));
    }
    let stored = quick_unlock::load(&state.dir)
        .filter(|s| s.account_id == account)
        .ok_or_else(|| BridgeError::invalid(format!("没有开启 {label} 解锁")))?;
    let challenge = quick_unlock::challenge(&stored).map_err(BridgeError::invalid)?;
    let platform = state.platform;
    let name = quick_unlock::credential_name(&account);
    let signed = blocking(move || platform.quick_unlock_sign(&name, &challenge)).await?;
    let signature = match signed {
        Ok(s) => Zeroizing::new(s),
        Err(e) => {
            // the Hello key is gone (Windows Hello reset): off, the password is needed
            if let QuickError::Invalidated(_) = e {
                disable_quick_unlock(&state, &account).await;
            }
            return Err(BridgeError::invalid(e));
        }
    };
    let ak = match quick_unlock::unwrap(&stored, &signature) {
        Ok(k) => k,
        Err(e) => {
            disable_quick_unlock(&state, &account).await;
            return Err(BridgeError::invalid(e));
        }
    };
    if let Err(e) = c.unlock_with_key(&ak) {
        if matches!(e, npw_core::CoreError::WrongPassword) {
            disable_quick_unlock(&state, &account).await;
        }
        return Err(e.into());
    }
    state.notify_unlocked();
    Ok(())
}

// ---------------------------------------------------------------- PIN (desktop and Android only)

/// Unlocks with the PIN (14-day rule; five wrong tries delete it).
#[tauri::command]
pub async fn pin_unlock(state: St<'_>, pin: String) -> CmdResult<()> {
    let pin = Zeroizing::new(pin);
    let c = state.client()?;
    let account = c.lock_state().account_id;
    let guards = state.guards.clone();
    blocking(move || guards.try_pin(&account, now_ms(), |blob| c.unlock_with_pin(blob, &pin)))
        .await??;
    state.notify_unlocked();
    Ok(())
}

/// Sets (or changes) the PIN: wraps the account key under it and stores the
/// blob in the OS credential store. Only while unlocked, within 14 days of a
/// master-password unlock.
#[tauri::command]
pub async fn set_pin(state: St<'_>, pin: String) -> CmdResult<()> {
    let pin = Zeroizing::new(pin);
    if pin.chars().count() < npw_core::pin::MIN_PIN_CHARS {
        return Err(BridgeError::invalid("PIN 至少 4 个字符"));
    }
    let c = state.client()?;
    let account = c.lock_state().account_id;
    if !state.guards.persistent() {
        return Err(BridgeError::invalid(
            "设备密钥没有存在系统凭据存储中，这台设备不能设置 PIN",
        ));
    }
    if let Err(s) = local_unlock::fresh(&state.guards.get(&account), now_ms()) {
        return Err(BridgeError::new("password_required", s.message()));
    }
    let blob = blocking(move || c.pin_wrap(&pin)).await??;
    state
        .guards
        .set_pin(&account, blob, now_ms())
        .map_err(BridgeError::invalid)
}

#[tauri::command]
pub fn remove_pin(state: St<'_>) -> CmdResult<()> {
    state.guards.remove_pin().map_err(BridgeError::invalid)
}

#[tauri::command]
pub fn set_biometric_at_start(state: St<'_>, enabled: bool) {
    state.update_settings(|s| s.unlock.biometric_at_start = enabled);
}

// ---------------------------------------------------------------- sync, vaults, items

#[tauri::command]
pub async fn sync(state: St<'_>) -> CmdResult<npw_core::SyncReport> {
    Ok(state.client()?.sync().await?)
}

#[tauri::command]
pub async fn events_token(state: St<'_>) -> CmdResult<String> {
    Ok(state.client()?.events_token().await?)
}

#[tauri::command]
pub fn vaults(state: St<'_>) -> CmdResult<Vec<npw_core::VaultView>> {
    Ok(state.client()?.vaults()?)
}

#[tauri::command]
pub async fn create_vault(state: St<'_>, name: String) -> CmdResult<String> {
    Ok(state.client()?.create_vault(&name).await?)
}

#[tauri::command]
pub async fn rename_vault(state: St<'_>, id: String, name: String) -> CmdResult<()> {
    Ok(state.client()?.rename_vault(&id, &name).await?)
}

#[tauri::command]
pub fn list_items(state: St<'_>, filter: Option<ItemFilter>) -> CmdResult<Vec<npw_core::ItemView>> {
    Ok(state.client()?.list_items(&filter.unwrap_or_default())?)
}

#[tauri::command]
pub fn item(state: St<'_>, vault_id: String, item_id: String) -> CmdResult<npw_core::ItemView> {
    Ok(state.client()?.item(&vault_id, &item_id)?)
}

#[tauri::command]
pub fn tags(state: St<'_>) -> CmdResult<Vec<String>> {
    Ok(state.client()?.tags()?)
}

#[tauri::command]
pub fn new_item(template: String, locale: Option<String>) -> CmdResult<ItemContent> {
    let t =
        npw_model::template(&template).ok_or_else(|| BridgeError::invalid("unknown template"))?;
    Ok(t.new_item(locale.as_deref().unwrap_or("zh-CN")))
}

#[tauri::command]
pub fn save_item(
    state: St<'_>,
    vault_id: String,
    item_id: Option<String>,
    content: ItemContent,
) -> CmdResult<String> {
    Ok(state
        .client()?
        .save_item(&vault_id, item_id.as_deref(), content)?)
}

#[tauri::command]
pub fn delete_item(state: St<'_>, vault_id: String, item_id: String) -> CmdResult<()> {
    Ok(state.client()?.delete_item(&vault_id, &item_id)?)
}

#[tauri::command]
pub fn restore_item(state: St<'_>, vault_id: String, item_id: String) -> CmdResult<()> {
    Ok(state.client()?.restore_item(&vault_id, &item_id)?)
}

#[tauri::command]
pub fn resolve_conflict(
    state: St<'_>,
    vault_id: String,
    item_id: String,
    conflict_id: String,
    use_conflict_value: bool,
) -> CmdResult<()> {
    Ok(state
        .client()?
        .resolve_conflict(&vault_id, &item_id, &conflict_id, use_conflict_value)?)
}

#[tauri::command]
pub fn attention(state: St<'_>) -> CmdResult<(usize, usize, usize)> {
    Ok(state.client()?.attention()?)
}

#[tauri::command]
pub async fn item_history(state: St<'_>, vault_id: String, item_id: String) -> CmdResult<Value> {
    let h = state.client()?.item_history(&vault_id, &item_id).await?;
    serde_json::to_value(h).map_err(BridgeError::invalid)
}

#[tauri::command]
pub async fn item_revision(
    state: St<'_>,
    vault_id: String,
    item_id: String,
    revision: i64,
) -> CmdResult<ItemContent> {
    Ok(state
        .client()?
        .item_revision(&vault_id, &item_id, revision)
        .await?)
}

#[tauri::command]
pub async fn restore_revision(
    state: St<'_>,
    vault_id: String,
    item_id: String,
    revision: i64,
) -> CmdResult<()> {
    Ok(state
        .client()?
        .restore_revision(&vault_id, &item_id, revision)
        .await?)
}

#[tauri::command]
pub async fn purge(
    state: St<'_>,
    vault_id: String,
    item_ids: Vec<String>,
) -> CmdResult<Vec<String>> {
    Ok(state.client()?.purge(&vault_id, &item_ids).await?)
}

// ---------------------------------------------------------------- attachments

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddAttachmentArgs {
    vault_id: String,
    item_id: String,
    name: String,
    mime: String,
}

#[tauri::command]
pub async fn add_attachment(state: St<'_>, request: Request<'_>) -> CmdResult<String> {
    let (a, data): (AddAttachmentArgs, &[u8]) = raw_args(&request)?;
    Ok(state
        .client()?
        .add_attachment(&a.vault_id, &a.item_id, &a.name, &a.mime, data)
        .await?)
}

#[tauri::command]
pub async fn attachment(
    state: St<'_>,
    vault_id: String,
    item_id: String,
    attachment_id: String,
) -> CmdResult<Response> {
    let data = state
        .client()?
        .attachment(&vault_id, &item_id, &attachment_id)
        .await?;
    Ok(Response::new(data))
}

#[tauri::command]
pub fn remove_attachment(
    state: St<'_>,
    vault_id: String,
    item_id: String,
    attachment_id: String,
) -> CmdResult<()> {
    Ok(state
        .client()?
        .remove_attachment(&vault_id, &item_id, &attachment_id)?)
}

// ---------------------------------------------------------------- import / export

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportArgs {
    file_name: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    locale: Option<String>,
}

#[tauri::command]
pub async fn import_preview(state: St<'_>, request: Request<'_>) -> CmdResult<Value> {
    let (a, data): (ImportArgs, &[u8]) = raw_args(&request)?;
    let password = a.password.filter(|p| !p.is_empty()).map(Zeroizing::new);
    let data = data.to_vec();
    let locale = a.locale.unwrap_or_else(|| "zh-CN".into());
    let (source, parsed) = blocking(move || {
        npw_core::transfer::parse_import(
            &a.file_name,
            &data,
            password.as_deref().map(|p| p.as_str()),
            &locale,
        )
    })
    .await??;
    let preview = npw_core::transfer::preview(&source, &parsed);
    let token = npw_model::new_id();
    state
        .imports
        .lock()
        .expect("imports")
        .insert(token.clone(), (source, parsed));
    let mut v = serde_json::to_value(&preview).map_err(BridgeError::invalid)?;
    v["token"] = token.into();
    Ok(v)
}

#[tauri::command]
pub async fn import_commit(
    state: St<'_>,
    token: String,
    vault_id: String,
) -> CmdResult<npw_core::ImportCommitReport> {
    let (source, parsed) = state
        .imports
        .lock()
        .expect("imports")
        .remove(&token)
        .ok_or_else(|| BridgeError::invalid("this import expired; choose the file again"))?;
    Ok(state
        .client()?
        .import_parsed(&vault_id, parsed, &source.to_lowercase())
        .await?)
}

#[tauri::command]
pub fn import_batches(state: St<'_>) -> CmdResult<Vec<(String, String, i64, usize)>> {
    Ok(state.client()?.import_batches()?)
}

#[tauri::command]
pub fn undo_import(state: St<'_>, batch_id: String) -> CmdResult<usize> {
    Ok(state.client()?.undo_import(&batch_id)?)
}

#[tauri::command]
pub async fn export_vault(state: St<'_>, format: String, password: String) -> CmdResult<Response> {
    let password = Zeroizing::new(password);
    let data = state.client()?.export_vault(&format, &password).await?;
    Ok(Response::new(data))
}

// ---------------------------------------------------------------- account management

#[tauri::command]
pub fn security_report(state: St<'_>) -> CmdResult<npw_core::SecurityReport> {
    Ok(state.client()?.security_report()?)
}

#[tauri::command]
pub fn health_check(state: St<'_>) -> CmdResult<npw_core::HealthReport> {
    Ok(state.client()?.health_check()?)
}

#[tauri::command]
pub async fn change_password(state: St<'_>, current: String, next: String) -> CmdResult<()> {
    let current = Zeroizing::new(current);
    let next = Zeroizing::new(next);
    let c = state.client()?;
    c.change_password(&current, &next).await?;
    // a new master password: biometrics and the PIN are set up again (design doc §4.5)
    let account = c.lock_state().account_id;
    disable_quick_unlock(&state, &account).await;
    if let Err(e) = state.guards.remove_pin() {
        log::warn!("could not delete the PIN after a password change: {e}");
    }
    state.mark_password_unlock();
    Ok(())
}

#[tauri::command]
pub async fn devices(state: St<'_>) -> CmdResult<Value> {
    let d = state.client()?.devices().await?;
    serde_json::to_value(d).map_err(BridgeError::invalid)
}

#[tauri::command]
pub async fn revoke_device(state: St<'_>, id: String) -> CmdResult<()> {
    Ok(state.client()?.revoke_device(&id).await?)
}

#[tauri::command]
pub async fn audit_log(state: St<'_>) -> CmdResult<Value> {
    let a = state.client()?.audit_log().await?;
    serde_json::to_value(a).map_err(BridgeError::invalid)
}

// ---------------------------------------------------------------- static data, clipboard, files

#[tauri::command]
pub fn templates(locale: Option<String>) -> Value {
    crate::pure::templates(locale.as_deref().unwrap_or("zh-CN"))
}

#[tauri::command]
pub fn field_presets(locale: Option<String>) -> Value {
    crate::pure::field_presets(locale.as_deref().unwrap_or("zh-CN"))
}

#[tauri::command]
pub async fn copy(state: St<'_>, text: String, secret: bool) -> CmdResult<()> {
    state
        .clipboard
        .copy(state.platform, text, secret)
        .map_err(BridgeError::invalid)
}

#[derive(Deserialize)]
struct SaveFileArgs {
    name: String,
}

/// Native save dialog, then write. Cancelling is not an error.
#[tauri::command]
pub async fn save_file(app: AppHandle, request: Request<'_>) -> CmdResult<()> {
    let (a, data): (SaveFileArgs, &[u8]) = raw_args(&request)?;
    let data = data.to_vec();
    let name = sanitize_file_name(&a.name);
    let ext = std::path::Path::new(&name)
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();
    let path = blocking(move || {
        let mut d = app.dialog().file().set_file_name(&name);
        if !ext.is_empty() {
            d = d.add_filter(ext.to_uppercase(), &[ext.as_str()]);
        }
        d.blocking_save_file()
    })
    .await?;
    let Some(path) = path else { return Ok(()) };
    let path = path.into_path().map_err(BridgeError::invalid)?;
    std::fs::write(&path, &data)
        .map_err(|e| BridgeError::invalid(format!("{}: {e}", path.display())))
}

/// Attachment names are stored as they came; clean them for this file system (design doc §10.7).
fn sanitize_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || r#"<>:"/\|?*"#.contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim().trim_end_matches(['.', ' ']).to_string();
    if trimmed.is_empty() {
        "file".into()
    } else {
        trimmed
    }
}

// ---------------------------------------------------------------- desktop only

#[derive(Debug, Clone, Serialize)]
pub struct DesktopInfo {
    version: String,
    platform: String,
    key_storage: Option<crate::device_key::KeyStorage>,
    key_store_name: String,
    data_dir: String,
    update_repo: String,
    update_signed: bool,
}

#[tauri::command]
pub fn desktop_info(state: St<'_>) -> DesktopInfo {
    DesktopInfo {
        version: updater::CURRENT.into(),
        platform: crate::platform::os_name().into(),
        key_storage: state.key_storage,
        key_store_name: state.platform.key_store_name().into(),
        data_dir: state.dir.display().to_string(),
        update_repo: updater::REPO.into(),
        update_signed: updater::PUBKEY.is_some_and(|k| !k.trim().is_empty()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DesktopSettingsView {
    export: ExportSettings,
    exporting: bool,
    autostart: bool,
    check_updates: bool,
    ssh_agent: SshAgentView,
    quick_access: QuickAccessView,
    browser_bridge: BrowserBridgeView,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshAgentView {
    /// The configured endpoint (empty = default).
    endpoint_setting: String,
    #[serde(flatten)]
    status: ssh_agent::AgentStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuickAccessView {
    enabled: bool,
    shortcut: String,
    error: String,
    auto_type_supported: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserBridgeView {
    /// Allowed without being in settings (the published extension).
    store_extension_ids: Vec<String>,
    /// Other IDs from settings (an unpacked or self-built extension).
    extension_ids: Vec<String>,
    pairings: Vec<Pairing>,
    #[serde(flatten)]
    status: browser_bridge::BridgeStatus,
}

fn settings_view(app: &AppHandle, state: &AppState) -> DesktopSettingsView {
    let s = state.settings();
    DesktopSettingsView {
        export: s.export,
        exporting: state.exporting.load(Ordering::SeqCst),
        autostart: state.platform.autostart_enabled(app),
        check_updates: s.check_updates,
        ssh_agent: SshAgentView {
            endpoint_setting: s.ssh_agent.endpoint,
            status: state.ssh.status(),
        },
        quick_access: QuickAccessView {
            enabled: s.quick_access.enabled,
            shortcut: s.quick_access.shortcut,
            error: state.quick_error.lock().expect("quick").clone(),
            auto_type_supported: state.platform.auto_type_supported(),
        },
        browser_bridge: BrowserBridgeView {
            store_extension_ids: browser_bridge::STORE_EXTENSION_IDS
                .iter()
                .map(|i| i.to_string())
                .collect(),
            extension_ids: s
                .browser_bridge
                .extension_ids
                .into_iter()
                .filter(|i| !browser_bridge::STORE_EXTENSION_IDS.contains(&i.as_str()))
                .collect(),
            pairings: s.browser_bridge.pairings,
            status: state.bridge.status(),
        },
    }
}

#[tauri::command]
pub fn desktop_settings(app: AppHandle, state: St<'_>) -> DesktopSettingsView {
    settings_view(&app, &state)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportSettingsInput {
    enabled: bool,
    folder: String,
    interval_days: u32,
    native: bool,
    kdbx: bool,
    keep: u32,
}

#[tauri::command]
pub fn set_desktop_settings(
    app: AppHandle,
    state: St<'_>,
    export: ExportSettingsInput,
    check_updates: bool,
) -> CmdResult<DesktopSettingsView> {
    if export.enabled && export.folder.trim().is_empty() {
        return Err(BridgeError::invalid("请先选择导出文件夹"));
    }
    state.update_settings(|s| {
        s.export.enabled = export.enabled;
        s.export.folder = export.folder.trim().to_string();
        s.export.interval_days = export.interval_days.clamp(1, 365);
        s.export.native = export.native;
        s.export.kdbx = export.kdbx;
        s.export.keep = export.keep.clamp(1, 100);
        s.check_updates = check_updates;
    });
    Ok(settings_view(&app, &state))
}

/// Pipe name (Windows; a `\\.\pipe\` prefix is accepted) or socket path.
fn clean_endpoint(endpoint: &str) -> CmdResult<String> {
    let e = endpoint.trim();
    if cfg!(windows) {
        let name = e
            .strip_prefix(r"\\.\pipe\")
            .or_else(|| e.strip_prefix("//./pipe/"))
            .unwrap_or(e);
        if name.len() > 200
            || name
                .chars()
                .any(|c| c == '\\' || c == '/' || c.is_control())
        {
            return Err(BridgeError::invalid("管道名不能包含 \\ 或 /"));
        }
        Ok(name.to_string())
    } else {
        if !e.is_empty() && !e.starts_with('/') {
            return Err(BridgeError::invalid("请填写 socket 的绝对路径"));
        }
        Ok(e.to_string())
    }
}

#[tauri::command]
pub async fn set_ssh_agent(
    app: AppHandle,
    state: St<'_>,
    enabled: bool,
    endpoint: String,
) -> CmdResult<DesktopSettingsView> {
    let endpoint = clean_endpoint(&endpoint)?;
    state.update_settings(|s| {
        s.ssh_agent.enabled = enabled;
        s.ssh_agent.endpoint = endpoint;
    });
    ssh_agent::apply(&app).await;
    Ok(settings_view(&app, &state))
}

#[tauri::command]
pub fn set_quick_access(
    app: AppHandle,
    state: St<'_>,
    enabled: bool,
    shortcut: String,
) -> CmdResult<DesktopSettingsView> {
    let shortcut = shortcut.trim().to_string();
    if enabled {
        quick::parse_shortcut(&shortcut).map_err(BridgeError::invalid)?;
    }
    state.update_settings(|s| {
        s.quick_access.enabled = enabled;
        if !shortcut.is_empty() {
            s.quick_access.shortcut = shortcut;
        }
    });
    // a failure is reported in the view (`quick_access.error`)
    let _ = quick::apply_shortcut(&app);
    Ok(settings_view(&app, &state))
}

#[tauri::command]
pub async fn set_browser_bridge(
    app: AppHandle,
    state: St<'_>,
    enabled: bool,
    extension_ids: Vec<String>,
) -> CmdResult<DesktopSettingsView> {
    let mut ids: Vec<String> = extension_ids
        .iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && !browser_bridge::STORE_EXTENSION_IDS.contains(&s.as_str()))
        .collect();
    ids.dedup();
    if let Some(bad) = ids.iter().find(|i| !browser_bridge::valid_extension_id(i)) {
        return Err(BridgeError::invalid(format!(
            "“{bad}” 不是扩展 ID（32 个 a–p 的小写字母，见扩展弹窗 ⚙）"
        )));
    }
    state.update_settings(|s| {
        s.browser_bridge.enabled = enabled;
        s.browser_bridge.extension_ids = ids;
    });
    browser_bridge::apply(&app, true).await;
    Ok(settings_view(&app, &state))
}

#[tauri::command]
pub fn remove_pairing(app: AppHandle, state: St<'_>, id: String) -> DesktopSettingsView {
    state.update_settings(|s| s.browser_bridge.pairings.retain(|p| p.id != id));
    settings_view(&app, &state)
}

// ---------------------------------------------------------------- quick access window

#[tauri::command]
pub fn quick_context(state: St<'_>) -> quick::QuickContext {
    quick::context(&state)
}

#[tauri::command]
pub fn quick_search(state: St<'_>, query: String) -> Vec<npw_core::ItemView> {
    quick::search(&state, &query)
}

#[tauri::command]
pub fn quick_hide(app: AppHandle) {
    quick::hide(&app);
}

#[tauri::command]
pub fn quick_show_main(app: AppHandle) {
    quick::hide(&app);
    crate::state::show_main(&app);
}

fn item_content(state: &AppState, vault_id: &str, item_id: &str) -> CmdResult<ItemContent> {
    state
        .client()?
        .item(vault_id, item_id)?
        .content
        .ok_or_else(|| BridgeError::from(npw_core::CoreError::NotFound))
}

/// The item asks for verification and Quick Access has not verified it (`quick_verify`).
fn quick_needs_verify(
    state: &AppState,
    c: &ItemContent,
    vault_id: &str,
    item_id: &str,
) -> CmdResult<()> {
    if c.reprompt && !state.quick_grant.take(vault_id, item_id) {
        return Err(BridgeError::new("reprompt", "这个条目需要先验证身份"));
    }
    Ok(())
}

/// Quick Access: verifies the user for one item ("使用前需要验证"); the next
/// auto-type or copy of a secret of that item may go ahead (once).
#[tauri::command]
pub async fn quick_verify(
    state: St<'_>,
    vault_id: String,
    item_id: String,
    password: Option<String>,
    pin: Option<String>,
) -> CmdResult<()> {
    let password = password.map(Zeroizing::new);
    let pin = pin.map(Zeroizing::new);
    // the item must exist
    item_content(&state, &vault_id, &item_id)?;
    let v = Verifier::new(&state)?;
    blocking(move || v.verify(secret(&password), secret(&pin))).await??;
    state.quick_grant.grant(&vault_id, &item_id);
    Ok(())
}

/// Types the item's auto-type sequence into the window Quick Access was opened over.
#[tauri::command]
pub async fn quick_autotype(
    app: AppHandle,
    state: St<'_>,
    vault_id: String,
    item_id: String,
) -> CmdResult<()> {
    let platform = state.platform;
    if !platform.auto_type_supported() {
        return Err(BridgeError::invalid(crate::platform::UNSUPPORTED_AUTOTYPE));
    }
    let target = state
        .quick_target
        .lock()
        .expect("quick")
        .clone()
        .ok_or_else(|| {
            BridgeError::invalid("没有可以输入的目标窗口：请先切换到要登录的窗口，再按快捷键")
        })?;
    let content = item_content(&state, &vault_id, &item_id)?;
    quick_needs_verify(&state, &content, &vault_id, &item_id)?;
    let steps =
        autotype::steps_for(&content, (now_ms() / 1000) as u64).map_err(BridgeError::invalid)?;
    drop(content);
    quick::hide(&app);
    let r = blocking(move || platform.auto_type(&target, &steps)).await?;
    if r.is_err() {
        // tell the user in Quick Access why nothing (or not everything) was typed
        quick::reshow(&app);
    }
    r.map_err(BridgeError::invalid)
}

#[tauri::command]
pub async fn quick_copy(
    state: St<'_>,
    vault_id: String,
    item_id: String,
    what: String,
) -> CmdResult<()> {
    let c = item_content(&state, &vault_id, &item_id)?;
    let field = |p: &str| c.by_purpose(p).map(|f| f.text()).filter(|s| !s.is_empty());
    let (text, secret) = match what.as_str() {
        "username" => (field("username").or_else(|| field("email")), false),
        "password" => (field("password"), true),
        "totp" => (
            c.totp()
                .and_then(|u| npw_otp::OtpSpec::parse(&u).ok())
                .map(|s| s.code((now_ms() / 1000) as u64)),
            true,
        ),
        _ => return Err(BridgeError::invalid("unknown field")),
    };
    if secret {
        quick_needs_verify(&state, &c, &vault_id, &item_id)?;
    }
    let text = text.ok_or_else(|| BridgeError::invalid("这个条目没有这个字段"))?;
    state
        .clipboard
        .copy(state.platform, text, secret)
        .map_err(BridgeError::invalid)
}

/// Checks an auto-type sequence typed in the item editor.
#[tauri::command]
pub fn check_auto_type(sequence: String) -> CmdResult<()> {
    autotype::validate(&sequence).map_err(BridgeError::invalid)
}

// ---------------------------------------------------------------- confirmation windows

/// The prompt shown in the calling window (its label is the prompt's id, so
/// a window can only see and answer its own prompt).
#[tauri::command]
pub fn prompt_info(window: tauri::WebviewWindow, state: St<'_>) -> Option<prompts::PromptInfo> {
    state.prompts.info(window.label())
}

#[tauri::command]
pub fn prompt_respond(
    window: tauri::WebviewWindow,
    state: St<'_>,
    decision: prompts::Decision,
) -> bool {
    state.prompts.respond(window.label(), decision)
}

/// A prompt for an item marked "使用前需要验证": verify the user before it
/// can be approved (the master password, or Windows Hello when empty).
#[tauri::command]
pub async fn prompt_verify(
    window: tauri::WebviewWindow,
    state: St<'_>,
    password: Option<String>,
    pin: Option<String>,
) -> CmdResult<()> {
    let password = password.map(Zeroizing::new);
    let pin = pin.map(Zeroizing::new);
    let id = window.label().to_string();
    if state.prompts.info(&id).is_none() {
        return Err(BridgeError::invalid("这个请求已经结束"));
    }
    let v = Verifier::new(&state)?;
    blocking(move || v.verify(secret(&password), secret(&pin))).await??;
    state.prompts.mark_verified(&id);
    Ok(())
}

#[tauri::command]
pub fn set_autostart(app: AppHandle, state: St<'_>, enabled: bool) -> CmdResult<()> {
    state
        .platform
        .set_autostart(&app, enabled)
        .map_err(BridgeError::invalid)
}

#[tauri::command]
pub async fn pick_export_folder(app: AppHandle) -> CmdResult<Option<String>> {
    let picked = blocking(move || app.dialog().file().blocking_pick_folder()).await?;
    Ok(picked
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string()))
}

/// "Export now" in the settings: the user types the master password for it.
#[tauri::command]
pub async fn export_now(state: St<'_>, password: String) -> CmdResult<export::Outcome> {
    let password = Zeroizing::new(password);
    if state.exporting.swap(true, Ordering::SeqCst) {
        return Err(BridgeError::invalid("正在导出，请稍候"));
    }
    let r = run_export(&state, &password).await;
    state.exporting.store(false, Ordering::SeqCst);
    r.map_err(BridgeError::invalid)
}

#[tauri::command]
pub async fn update_check(state: St<'_>) -> CmdResult<updater::UpdateCheck> {
    let r = updater::check().await.map_err(BridgeError::invalid)?;
    state.update_settings(|s| s.last_update_check_at = now_ms());
    Ok(r)
}

#[tauri::command]
pub async fn update_install(app: AppHandle, version: String) -> CmdResult<()> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(BridgeError::invalid)?
        .join("updates");
    let path = updater::download(&version, &dir)
        .await
        .map_err(BridgeError::invalid)?;
    updater::launch_installer(&path).map_err(BridgeError::invalid)?;
    log::info!("starting the installer of {version} and quitting");
    crate::quit(&app);
    Ok(())
}

#[tauri::command]
pub fn open_release_page(app: AppHandle, url: String) -> CmdResult<()> {
    use tauri_plugin_opener::OpenerExt;
    let prefix = format!("https://github.com/{}/releases", updater::REPO);
    if !url.starts_with(&prefix) {
        return Err(BridgeError::invalid("not a release page"));
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(BridgeError::invalid)
}

/// A link in the vault (an item's website, a link field): the window cannot
/// open one itself, it goes to the default browser. Only http(s) addresses.
#[tauri::command]
pub fn open_url(app: AppHandle, url: String) -> CmdResult<()> {
    use tauri_plugin_opener::OpenerExt;
    let url = web_url(&url).ok_or_else(|| BridgeError::invalid("not a web address"))?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(BridgeError::invalid)
}

fn web_url(url: &str) -> Option<String> {
    let u = tauri::Url::parse(url.trim()).ok()?;
    (matches!(u.scheme(), "http" | "https") && u.host_str().is_some()).then(|| u.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_urls() {
        assert_eq!(
            web_url("https://example.com").as_deref(),
            Some("https://example.com/")
        );
        assert_eq!(
            web_url(" http://example.com/a?b=1 ").as_deref(),
            Some("http://example.com/a?b=1")
        );
        assert!(web_url("file:///C:/Windows/System32/calc.exe").is_none());
        assert!(web_url("ms-settings:").is_none());
        assert!(web_url("javascript:alert(1)").is_none());
        assert!(web_url("example.com").is_none());
        assert!(web_url("").is_none());
    }

    #[test]
    fn header_decoding() {
        assert_eq!(
            percent_decode("%7B%22a%22%3A%22%E4%BD%A0%22%7D").unwrap(),
            r#"{"a":"你"}"#
        );
        assert_eq!(percent_decode("abc").unwrap(), "abc");
        assert!(percent_decode("%zz").is_err());
    }

    #[test]
    fn endpoints() {
        if cfg!(windows) {
            assert_eq!(clean_endpoint(r"\\.\pipe\npw-agent").unwrap(), "npw-agent");
            assert_eq!(clean_endpoint(" npw-agent ").unwrap(), "npw-agent");
            assert_eq!(clean_endpoint("").unwrap(), "");
            assert!(clean_endpoint(r"..\evil").is_err());
        } else {
            assert_eq!(clean_endpoint("/tmp/a.sock").unwrap(), "/tmp/a.sock");
            assert!(clean_endpoint("relative.sock").is_err());
        }
    }

    #[test]
    fn file_names() {
        assert_eq!(sanitize_file_name("a/b:c?.txt"), "a_b_c_.txt");
        assert_eq!(sanitize_file_name("  .. "), "file");
        assert_eq!(sanitize_file_name("证件.pdf."), "证件.pdf");
    }
}
