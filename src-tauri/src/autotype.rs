//! Auto-type sequences (KeePass style) and matching items to the window that
//! had the focus. Pure logic; the platform layer does the typing.
//!
//! A sequence is text with placeholders, case-insensitive:
//! `{USERNAME}` `{PASSWORD}` `{TOTP}` `{URL}` `{TITLE}` `{S:<field label or id>}`,
//! keys `{TAB}` `{ENTER}` `{SPACE}` `{BACKSPACE}`/`{BS}` `{DELETE}`/`{DEL}`
//! `{ESC}` `{UP}` `{DOWN}` `{LEFT}` `{RIGHT}` `{HOME}` `{END}`, `{DELAY 500}`
//! (milliseconds) and `{{}` / `{}}` for literal braces. Anything else is typed
//! as it is. The item's own sequence is `autofill.auto_type` (a key the item
//! format keeps for us although the core does not know it, 条目格式 §5);
//! without one, [`DEFAULT_SEQUENCE`].

use npw_model::ItemContent;
use serde_json::Value;
use zeroize::Zeroizing;

pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
/// Key of the sequence inside the item's `autofill` object.
pub const SEQUENCE_KEY: &str = "auto_type";
const MAX_DELAY_MS: u32 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Tab,
    Enter,
    Space,
    Backspace,
    Delete,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
}

/// One thing to type.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Text(Zeroizing<String>),
    Key(Key),
    Delay(u32),
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Literal(String),
    Field(FieldRef),
    Key(Key),
    Delay(u32),
}

#[derive(Debug, Clone, PartialEq)]
enum FieldRef {
    Username,
    Password,
    Totp,
    Url,
    Title,
    Custom(String),
}

fn key_named(name: &str) -> Option<Key> {
    Some(match name {
        "TAB" => Key::Tab,
        "ENTER" => Key::Enter,
        "SPACE" => Key::Space,
        "BACKSPACE" | "BS" | "BKSP" => Key::Backspace,
        "DELETE" | "DEL" => Key::Delete,
        "ESC" => Key::Escape,
        "UP" => Key::Up,
        "DOWN" => Key::Down,
        "LEFT" => Key::Left,
        "RIGHT" => Key::Right,
        "HOME" => Key::Home,
        "END" => Key::End,
        _ => return None,
    })
}

fn parse(seq: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut rest = seq;
    while let Some(c) = rest.chars().next() {
        if c == '}' {
            return Err(format!("自动输入序列有多余的 “}}”：{seq}"));
        }
        if c != '{' {
            lit.push(c);
            rest = &rest[c.len_utf8()..];
            continue;
        }
        // literal braces: {{} and {}}
        if let Some(r) = rest.strip_prefix("{{}") {
            lit.push('{');
            rest = r;
            continue;
        }
        if let Some(r) = rest.strip_prefix("{}}") {
            lit.push('}');
            rest = r;
            continue;
        }
        let end = rest
            .find('}')
            .ok_or_else(|| format!("自动输入序列缺少 “}}”：{seq}"))?;
        let inner = &rest[1..end];
        rest = &rest[end + 1..];
        if !lit.is_empty() {
            out.push(Token::Literal(std::mem::take(&mut lit)));
        }
        let upper = inner.trim().to_uppercase();
        let token = if let Some(k) = key_named(&upper) {
            Token::Key(k)
        } else if let Some(n) = upper
            .strip_prefix("DELAY")
            .map(|n| n.trim_start_matches([' ', '=']).trim())
            .filter(|n| !n.is_empty())
        {
            let ms: u32 = n
                .parse()
                .map_err(|_| format!("{{DELAY}} 需要毫秒数：{{{inner}}}"))?;
            Token::Delay(ms.min(MAX_DELAY_MS))
        } else if upper.starts_with("S:") {
            Token::Field(FieldRef::Custom(inner.trim()[2..].trim().to_string()))
        } else {
            Token::Field(match upper.as_str() {
                "USERNAME" | "USER" => FieldRef::Username,
                "PASSWORD" => FieldRef::Password,
                "TOTP" | "OTP" => FieldRef::Totp,
                "URL" => FieldRef::Url,
                "TITLE" => FieldRef::Title,
                _ => return Err(format!("不认识的自动输入占位符 {{{inner}}}")),
            })
        };
        out.push(token);
    }
    if !lit.is_empty() {
        out.push(Token::Literal(lit));
    }
    Ok(out)
}

/// Checks a sequence the user typed (the editor validates before saving).
pub fn validate(seq: &str) -> Result<(), String> {
    parse(seq).map(|_| ())
}

/// The item's own sequence, or the default.
pub fn sequence_of(c: &ItemContent) -> String {
    match c.autofill.extra.get(SEQUENCE_KEY) {
        Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
        _ => DEFAULT_SEQUENCE.to_string(),
    }
}

fn field_text(c: &ItemContent, r: &FieldRef, unix_secs: u64) -> Result<Zeroizing<String>, String> {
    let text = |f: &npw_model::Field| Zeroizing::new(f.text());
    Ok(match r {
        FieldRef::Username => c
            .by_purpose("username")
            .or_else(|| c.by_purpose("email"))
            .or_else(|| c.by_purpose("phone"))
            .map(text)
            .ok_or("这个条目没有用户名")?,
        FieldRef::Password => c
            .by_purpose("password")
            .map(text)
            .ok_or("这个条目没有密码")?,
        FieldRef::Totp => {
            let uri = Zeroizing::new(c.totp().ok_or("这个条目没有一次性密码")?);
            let spec = npw_otp::OtpSpec::parse(&uri).map_err(|e| e.to_string())?;
            Zeroizing::new(spec.code(unix_secs))
        }
        FieldRef::Url => Zeroizing::new(c.urls.first().map(|u| u.url.clone()).unwrap_or_default()),
        FieldRef::Title => Zeroizing::new(c.title.clone()),
        FieldRef::Custom(name) => c
            .fields
            .iter()
            .find(|f| f.label == *name)
            .or_else(|| c.fields.iter().find(|f| f.id == *name))
            .map(text)
            .ok_or_else(|| format!("这个条目没有字段 “{name}”"))?,
    })
}

/// Turns the item's sequence into steps with the values filled in.
pub fn steps_for(c: &ItemContent, unix_secs: u64) -> Result<Vec<Step>, String> {
    let mut out = Vec::new();
    for t in parse(&sequence_of(c))? {
        out.push(match t {
            Token::Literal(s) => Step::Text(Zeroizing::new(s)),
            Token::Key(k) => Step::Key(k),
            Token::Delay(ms) => Step::Delay(ms),
            Token::Field(r) => Step::Text(field_text(c, &r, unix_secs)?),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------- window matching

fn exe_stem(process: &str) -> String {
    let p = process.to_lowercase();
    p.strip_suffix(".exe").unwrap_or(&p).to_string()
}

/// How well an item fits the window (`None`: not at all). Window titles of
/// browsers carry the page title and often the host; desktop programs carry
/// their name. Compared: the item's URL hosts / registrable domains, its
/// title, and the program's executable name.
pub fn window_score(c: &ItemContent, title: &str, process: &str) -> Option<i64> {
    let wt = title.to_lowercase();
    let stem = exe_stem(process);
    let mut best: Option<i64> = None;
    let mut bump = |s: i64| best = Some(best.map_or(s, |b| b.max(s)));
    for u in &c.urls {
        if u.match_mode == "never" {
            continue;
        }
        if let Some(npw_match::Target::Web { host, domain, .. }) = npw_match::parse(&u.url) {
            if !host.is_empty() && wt.contains(&host) {
                bump(100);
            } else if !domain.is_empty() && wt.contains(&domain) {
                bump(90);
            } else if let Some(label) = domain.split('.').next().filter(|l| l.len() >= 4) {
                if contains_word(&wt, label) {
                    bump(50);
                }
            }
        }
    }
    let it = c.title.trim().to_lowercase();
    if it.chars().count() >= 3 && wt.contains(&it) {
        bump(80);
    }
    if stem.len() >= 3 && !it.is_empty() && (it == stem || contains_word(&it, &stem)) {
        bump(70);
    }
    best
}

/// `needle` as a whole word in `hay` (ASCII word boundaries).
fn contains_word(hay: &str, needle: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric();
    hay.match_indices(needle).any(|(i, _)| {
        let before = hay[..i].chars().next_back().is_none_or(|c| !is_word(c));
        let after = hay[i + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_word(c));
        before && after
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use npw_model::template;

    fn login(title: &str, user: &str, pw: &str, url: &str) -> ItemContent {
        let mut c = template("login").unwrap().new_item("zh-CN");
        c.title = title.into();
        c.field_mut("username").unwrap().value = user.into();
        c.field_mut("password").unwrap().value = pw.into();
        if !url.is_empty() {
            c.urls.push(
                serde_json::from_value(
                    serde_json::json!({"id": "u_1", "url": url, "match": "domain"}),
                )
                .unwrap(),
            );
        }
        c
    }

    fn texts(steps: &[Step]) -> Vec<String> {
        steps
            .iter()
            .map(|s| match s {
                Step::Text(t) => format!("T:{}", t.as_str()),
                Step::Key(k) => format!("K:{k:?}"),
                Step::Delay(d) => format!("D:{d}"),
            })
            .collect()
    }

    #[test]
    fn default_sequence() {
        let c = login("GitHub", "octocat", "密码 pass", "https://github.com");
        assert_eq!(
            texts(&steps_for(&c, 0).unwrap()),
            ["T:octocat", "K:Tab", "T:密码 pass", "K:Enter"]
        );
    }

    #[test]
    fn custom_sequence_with_fields_keys_delay_and_braces() {
        let mut c = login("Bank", "13800000000", "pw", "");
        c.fields.push(serde_json::from_value(serde_json::json!({"id": "f_1", "label": "验证码", "kind": "text", "value": "8888"})).unwrap());
        c.fields.push(serde_json::from_value(serde_json::json!({"id": "otp2", "label": "x", "kind": "totp", "value": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})).unwrap());
        c.field_mut("otp").unwrap().value =
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into();
        c.autofill.extra.insert(
            SEQUENCE_KEY.into(),
            "{user}{tab}{DELAY 200}{PASSWORD}{S:验证码}{s:f_1}{{}x{}}{totp}{Enter}".into(),
        );
        assert_eq!(
            texts(&steps_for(&c, 59).unwrap()),
            [
                "T:13800000000",
                "K:Tab",
                "D:200",
                "T:pw",
                "T:8888",
                "T:8888",
                "T:{x}",
                "T:287082",
                "K:Enter"
            ]
        );
    }

    #[test]
    fn bad_sequences() {
        assert!(validate("{USERNAME").is_err());
        assert!(validate("}").is_err());
        assert!(validate("{FOO}").is_err());
        assert!(validate("{DELAY x}").is_err());
        assert!(validate("{USERNAME}{TAB}{PASSWORD}{ENTER}").is_ok());
        assert_eq!(
            parse("{DELAY=99999}").unwrap(),
            [Token::Delay(MAX_DELAY_MS)]
        );
        // missing values are errors, not empty typing
        let mut c = login("x", "", "", "");
        c.fields.clear();
        assert!(steps_for(&c, 0).is_err());
    }

    #[test]
    fn empty_sequence_falls_back_to_default() {
        let mut c = login("x", "u", "p", "");
        c.autofill.extra.insert(SEQUENCE_KEY.into(), "  ".into());
        assert_eq!(sequence_of(&c), DEFAULT_SEQUENCE);
    }

    #[test]
    fn window_matching() {
        let gh = login("GitHub", "u", "p", "https://github.com/login");
        assert_eq!(
            window_score(
                &gh,
                "Sign in to GitHub · GitHub — Mozilla Firefox",
                "firefox.exe"
            ),
            Some(80)
        );
        assert_eq!(
            window_score(&gh, "github.com/login - Google Chrome", "chrome.exe"),
            Some(100)
        );
        assert_eq!(window_score(&gh, "Notepad", "notepad.exe"), None);
        let qq = login("QQ 邮箱", "u", "p", "https://mail.qq.com");
        assert_eq!(
            window_score(&qq, "QQ邮箱 - Microsoft Edge", "msedge.exe"),
            None
        );
        assert_eq!(window_score(&qq, "mail.qq.com", "msedge.exe"), Some(100));
        let wechat = login("WeChat", "u", "p", "");
        assert_eq!(window_score(&wechat, "微信", "WeChat.exe"), Some(70));
        let ali = login("阿里云", "u", "p", "https://signin.aliyun.com");
        assert_eq!(
            window_score(&ali, "阿里云登录 - aliyun.com", "chrome.exe"),
            Some(90)
        );
        assert_eq!(window_score(&ali, "Aliyun console", "chrome.exe"), Some(50));
        assert_eq!(window_score(&ali, "notaliyunx", "chrome.exe"), None);
    }
}
