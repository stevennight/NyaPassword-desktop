//! NyaPassword desktop: the shared vault UI (common/web, built with
//! `vite --mode desktop`) over the native client core (npw-core + SQLite).
//! See README.md and the design doc §10.3.

mod clipboard;
mod commands;
mod device_key;
mod error;
mod export;
mod platform;
mod pure;
mod quick_unlock;
mod settings;
mod state;
mod tray;
mod updater;

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

use crate::state::{lock_all, now_ms, show_main, AppState, EVENT_UPDATE};

use crate::platform::MINIMIZED_ARG;

pub fn run() {
    let app = tauri::Builder::default()
        // first: a second launch only focuses the running window
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main(app)
        }))
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .max_file_size(2 * 1024 * 1024)
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![MINIMIZED_ARG]),
        ))
        .register_uri_scheme_protocol(pure::SCHEME, |_ctx, req| pure::handle(req))
        .setup(|app| {
            let dir = app.path().app_local_data_dir()?;
            app.manage(AppState::init(dir));
            tray::create(app.handle())?;

            let handle = app.handle().clone();
            platform::native().watch_session_lock(Arc::new(move || lock_all(&handle, "session")));

            if !std::env::args().any(|a| a == MINIMIZED_ARG) {
                show_main(app.handle());
            }
            background_update_check(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // the close button keeps the app running in the tray
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::lock_state,
            commands::register,
            commands::sign_in,
            commands::unlock,
            commands::lock,
            commands::sign_out,
            commands::emergency_kit,
            commands::quick_unlock_status,
            commands::set_quick_unlock,
            commands::quick_unlock,
            commands::sync,
            commands::events_token,
            commands::vaults,
            commands::create_vault,
            commands::rename_vault,
            commands::list_items,
            commands::item,
            commands::tags,
            commands::new_item,
            commands::save_item,
            commands::delete_item,
            commands::restore_item,
            commands::resolve_conflict,
            commands::attention,
            commands::item_history,
            commands::item_revision,
            commands::restore_revision,
            commands::purge,
            commands::add_attachment,
            commands::attachment,
            commands::remove_attachment,
            commands::import_preview,
            commands::import_commit,
            commands::import_batches,
            commands::undo_import,
            commands::export_vault,
            commands::security_report,
            commands::health_check,
            commands::change_password,
            commands::devices,
            commands::revoke_device,
            commands::audit_log,
            commands::templates,
            commands::field_presets,
            commands::copy,
            commands::save_file,
            commands::desktop_info,
            commands::desktop_settings,
            commands::set_desktop_settings,
            commands::set_autostart,
            commands::pick_export_folder,
            commands::export_now,
            commands::update_check,
            commands::update_install,
            commands::open_release_page,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the NyaPassword app");

    app.run(|app, event| {
        if let RunEvent::Exit = event {
            if let Some(st) = app.try_state::<AppState>() {
                st.lock();
                st.clipboard.clear_pending(st.platform);
            }
        }
    });
}

/// Quits for real (tray "quit", before an update): the close button only hides.
pub(crate) fn quit(app: &AppHandle) {
    if let Some(st) = app.try_state::<AppState>() {
        st.lock();
        st.clipboard.clear_pending(st.platform);
    }
    app.exit(0);
}

/// Once a day (if enabled), a minute after start: tell the UI about a new version.
fn background_update_check(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio_sleep(Duration::from_secs(60)).await;
        let Some(st) = app.try_state::<AppState>() else {
            return;
        };
        let s = st.settings();
        if !s.check_updates || now_ms() - s.last_update_check_at < 24 * 60 * 60 * 1000 {
            return;
        }
        st.update_settings(|s| s.last_update_check_at = now_ms());
        match updater::check().await {
            Ok(c) if c.latest.is_some() => {
                let _ = app.emit(EVENT_UPDATE, c);
            }
            Ok(_) => {}
            Err(e) => log::info!("update check failed: {e}"),
        }
    });
}

async fn tokio_sleep(d: Duration) {
    // no direct tokio dependency: sleep on a blocking thread
    let _ = tauri::async_runtime::spawn_blocking(move || std::thread::sleep(d)).await;
}
