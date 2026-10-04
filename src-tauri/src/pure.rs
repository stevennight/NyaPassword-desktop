//! The bridge's synchronous functions (one-time codes, the generator, strength,
//! host names, Secret Key parsing, short ids). The UI calls them synchronously,
//! but Tauri's `invoke` is asynchronous, so the page reaches them with a
//! synchronous XMLHttpRequest to the `npwsync:` scheme handled here. They are
//! pure: no account state, no secrets beyond the arguments.

use std::borrow::Cow;

use serde_json::{json, Value};
use tauri::http::{header, Method, Request, Response, StatusCode};

use crate::error::BridgeError;

pub const SCHEME: &str = "npwsync";

/// Origins of the app's own page (production on each platform, and the dev server).
fn allowed_origin(origin: &str) -> bool {
    matches!(
        origin,
        "http://tauri.localhost" | "https://tauri.localhost" | "tauri://localhost"
    ) || (cfg!(debug_assertions) && origin == "http://localhost:5180")
}

pub fn handle(req: Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if let Some(o) = &origin {
        if !allowed_origin(o) {
            return respond(StatusCode::FORBIDDEN, None, b"{}".to_vec());
        }
    }
    if req.method() == Method::OPTIONS {
        return respond(StatusCode::NO_CONTENT, origin.as_deref(), vec![]);
    }
    let name = req.uri().path().trim_start_matches('/').to_string();
    let args: Value = if req.body().is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(req.body()) {
            Ok(v) => v,
            Err(e) => return error(origin.as_deref(), BridgeError::invalid(e)),
        }
    };
    match call(&name, &args) {
        Ok(v) => respond(
            StatusCode::OK,
            origin.as_deref(),
            serde_json::to_vec(&v).expect("json"),
        ),
        Err(e) => error(origin.as_deref(), e),
    }
}

fn error(origin: Option<&str>, e: BridgeError) -> Response<Cow<'static, [u8]>> {
    respond(
        StatusCode::BAD_REQUEST,
        origin,
        serde_json::to_vec(&e).expect("json"),
    )
}

fn respond(
    status: StatusCode,
    origin: Option<&str>,
    body: Vec<u8>,
) -> Response<Cow<'static, [u8]>> {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type");
    if let Some(o) = origin {
        b = b.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
    }
    b.body(Cow::Owned(body)).expect("valid response")
}

fn str_arg<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// One synchronous bridge function; same results as the WASM bridge.
pub fn call(name: &str, args: &Value) -> Result<Value, BridgeError> {
    Ok(match name {
        "otpCode" => {
            let spec =
                npw_otp::OtpSpec::parse(str_arg(args, "uri")).map_err(BridgeError::invalid)?;
            let t = args.get("t").and_then(Value::as_f64).unwrap_or(0.0) as u64;
            json!({ "code": spec.code(t), "remaining": spec.remaining(t), "period": spec.period, "issuer": spec.issuer, "account": spec.account })
        }
        "generate" => {
            let recipe: npw_core::generator::Recipe = match args.get("recipe") {
                None | Some(Value::Null) => Default::default(),
                Some(r) => serde_json::from_value(r.clone()).map_err(BridgeError::invalid)?,
            };
            serde_json::to_value(npw_core::generator::generate(&recipe)).expect("json")
        }
        "passwordStrength" => json!(npw_core::generator::strength(str_arg(args, "password"))),
        "displayHost" => json!(npw_match::display_host(str_arg(args, "url"))),
        "normalizeSecretKey" => {
            let k = npw_crypto::SecretKey::parse(str_arg(args, "text"))
                .map_err(|e| BridgeError::from(npw_core::CoreError::from(e)))?;
            json!(k.to_text())
        }
        "newShortId" => json!(npw_model::new_short_id(str_arg(args, "prefix"))),
        _ => return Err(BridgeError::invalid(format!("unknown function {name}"))),
    })
}

/// All templates with their fields, labelled for `locale` (as the WASM bridge).
pub fn templates(locale: &str) -> Value {
    let list: Vec<Value> = npw_model::templates()
        .iter()
        .map(|t| {
            json!({
                "id": t.id,
                "label": t.label(locale),
                "icon": t.icon,
                "fields": t.fields.iter().map(|f| json!({"id": f.id, "kind": f.kind, "purpose": f.purpose, "multiline": f.multiline, "label": f.label(locale)})).collect::<Vec<_>>(),
            })
        })
        .collect();
    Value::Array(list)
}

pub fn field_presets(locale: &str) -> Value {
    let list: Vec<_> = npw_model::template::EXTRA_FIELD_PRESETS
        .iter()
        .map(|f| f.to_field(locale))
        .collect();
    serde_json::to_value(list).expect("json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn functions() {
        let v = call(
            "passwordStrength",
            &json!({"password": "correct horse battery staple 1997"}),
        )
        .unwrap();
        assert!(v.as_u64().unwrap() >= 3);
        let g = call("generate", &json!({"recipe": {"kind": "pin", "length": 6}})).unwrap();
        assert_eq!(g["password"].as_str().unwrap().len(), 6);
        let id = call("newShortId", &json!({"prefix": "f"})).unwrap();
        assert!(id.as_str().unwrap().starts_with("f_"));
        let otp = call(
            "otpCode",
            &json!({"uri": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "t": 59}),
        )
        .unwrap();
        assert_eq!(otp["code"], "287082");
        let e = call("normalizeSecretKey", &json!({"text": "nonsense"})).unwrap_err();
        assert!(!e.code.is_empty());
        assert!(call("nope", &Value::Null).is_err());
        assert!(templates("zh-CN").as_array().unwrap().len() > 3);
    }

    #[test]
    fn protocol() {
        let req = Request::builder()
            .method("POST")
            .uri("npwsync://localhost/displayHost")
            .header("Origin", "http://tauri.localhost")
            .body(br#"{"url":"https://www.example.com/login"}"#.to_vec())
            .unwrap();
        let resp = handle(req);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "http://tauri.localhost"
        );
        let v: Value = serde_json::from_slice(resp.body()).unwrap();
        assert!(v.as_str().unwrap().contains("example.com"));

        let evil = Request::builder()
            .method("POST")
            .uri("npwsync://localhost/generate")
            .header("Origin", "https://evil.example.com")
            .body(vec![])
            .unwrap();
        assert_eq!(handle(evil).status(), StatusCode::FORBIDDEN);
    }
}
