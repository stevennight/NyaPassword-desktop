//! Errors reach the UI as `{code, message}`, exactly like the WASM bridge:
//! `code` is `CoreError::code()` (the UI localizes known codes), `message`
//! is shown for the rest.

use npw_core::CoreError;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
}

impl BridgeError {
    pub fn new(code: &str, message: impl std::fmt::Display) -> Self {
        Self {
            code: code.into(),
            message: message.to_string(),
        }
    }

    /// `invalid`: the UI shows the message as is.
    pub fn invalid(message: impl std::fmt::Display) -> Self {
        Self::new("invalid", message)
    }
}

impl From<CoreError> for BridgeError {
    fn from(e: CoreError) -> Self {
        Self::new(e.code(), e)
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

pub type CmdResult<T> = Result<T, BridgeError>;
