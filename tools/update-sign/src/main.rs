//! Release signing for the desktop self-update (design doc §3.4), in the
//! standard minisign format so `minisign -V` can check it too.
//!
//!   npw-update-sign keygen <dir>          writes nyapassword-update.key / .pub into <dir>
//!   npw-update-sign sign <file>           writes <file>.minisig; the secret key comes from
//!                                         NPW_UPDATE_PRIVATE_KEY (the .key file's text) or --key <path>
//!   npw-update-sign verify <file> <pubkey-base64>
//!
//! The secret key is stored without a password: it lives offline in
//! ../signing and in one GitHub secret, never in a repository.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use minisign::{KeyPair, PublicKey, PublicKeyBox, SecretKeyBox, SignatureBox};

const KEY_FILE: &str = "nyapassword-update.key";
const PUB_FILE: &str = "nyapassword-update.pub";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 2 => keygen(Path::new(&args[1])),
        Some("sign") if args.len() == 2 => sign(Path::new(&args[1]), None),
        Some("sign") if args.len() == 4 && args[2] == "--key" => {
            sign(Path::new(&args[1]), Some(Path::new(&args[3])))
        }
        Some("verify") if args.len() == 3 => verify(Path::new(&args[1]), &args[2]),
        _ => Err("usage: npw-update-sign keygen <dir> | sign <file> [--key <path>] | verify <file> <pubkey-base64>".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let key_path = dir.join(KEY_FILE);
    let pub_path = dir.join(PUB_FILE);
    if key_path.exists() || pub_path.exists() {
        return Err(format!(
            "{} already has a key pair; move it away first (existing installs only trust the old key)",
            dir.display()
        ));
    }
    let kp = KeyPair::generate_unencrypted_keypair().map_err(|e| e.to_string())?;
    let sk = kp
        .sk
        .to_box(Some("NyaPassword desktop update signing key"))
        .map_err(|e| e.to_string())?
        .into_string();
    let pk = kp.pk.to_box().map_err(|e| e.to_string())?.into_string();
    write_new(&key_path, sk.as_bytes())?;
    write_new(&pub_path, pk.as_bytes())?;
    println!("secret key: {}", key_path.display());
    println!("public key: {}", pub_path.display());
    println!("NPW_UPDATE_PUBKEY={}", kp.pk.to_base64());
    Ok(())
}

fn write_new(path: &PathBuf, data: &[u8]) -> Result<(), String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, data))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn sign(file: &Path, key: Option<&Path>) -> Result<(), String> {
    let key_text = match key {
        Some(p) => fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?,
        None => std::env::var("NPW_UPDATE_PRIVATE_KEY")
            .map_err(|_| "NPW_UPDATE_PRIVATE_KEY is not set (or pass --key <path>)".to_string())?,
    };
    let sk = SecretKeyBox::from_string(key_text.trim())
        .and_then(SecretKeyBox::into_unencrypted_secret_key)
        .map_err(|e| format!("bad secret key: {e}"))?;
    let data = fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let trusted = format!("file:{name}");
    let sig = minisign::sign(None, &sk, Cursor::new(&data), Some(&trusted), None)
        .map_err(|e| e.to_string())?;
    let out = PathBuf::from(format!("{}.minisig", file.display()));
    fs::write(&out, sig.into_string()).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("signed {} -> {}", file.display(), out.display());
    Ok(())
}

fn verify(file: &Path, pubkey: &str) -> Result<(), String> {
    let pk = PublicKey::from_base64(pubkey.trim())
        .or_else(|_| PublicKeyBox::from_string(pubkey).and_then(PublicKeyBox::into_public_key))
        .map_err(|e| format!("bad public key: {e}"))?;
    let data = fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let sig_path = PathBuf::from(format!("{}.minisig", file.display()));
    let sig_text =
        fs::read_to_string(&sig_path).map_err(|e| format!("{}: {e}", sig_path.display()))?;
    let sig = SignatureBox::from_string(&sig_text).map_err(|e| e.to_string())?;
    minisign::verify(&pk, &sig, Cursor::new(&data), true, false, false)
        .map_err(|e| format!("signature check failed: {e}"))?;
    println!("ok: {} is signed by this key", file.display());
    Ok(())
}
