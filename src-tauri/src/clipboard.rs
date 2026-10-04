//! Copy with automatic clearing: secrets are removed from the clipboard after
//! 90 seconds (if it still holds them) and when the app quits.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::platform::Platform;

pub const CLEAR_AFTER: Duration = Duration::from_secs(90);

#[derive(Default)]
pub struct Clipboard {
    /// Secrets copied and not cleared yet.
    pending: Arc<Mutex<Vec<Zeroizing<String>>>>,
}

impl Clipboard {
    pub fn copy(
        &self,
        platform: &'static dyn Platform,
        text: String,
        secret: bool,
    ) -> Result<(), String> {
        let text = Zeroizing::new(text);
        platform.clipboard_set(&text, secret)?;
        if !secret {
            return Ok(());
        }
        self.pending.lock().expect("clipboard").push(text.clone());
        let pending = self.pending.clone();
        std::thread::Builder::new()
            .name("clipboard-clear".into())
            .spawn(move || {
                std::thread::sleep(CLEAR_AFTER);
                clear_if_unchanged(platform, &text);
                pending.lock().expect("clipboard").retain(|t| **t != *text);
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// On quit: clears the clipboard if it still holds a secret we put there.
    pub fn clear_pending(&self, platform: &dyn Platform) {
        let pending = std::mem::take(&mut *self.pending.lock().expect("clipboard"));
        if pending.is_empty() {
            return;
        }
        if let Some(cur) = platform.clipboard_get().map(Zeroizing::new) {
            if pending.iter().any(|t| **t == *cur) {
                platform.clipboard_clear();
            }
        }
    }
}

fn clear_if_unchanged(platform: &dyn Platform, text: &str) {
    if let Some(cur) = platform.clipboard_get().map(Zeroizing::new) {
        if *cur == text {
            platform.clipboard_clear();
        }
    }
}
