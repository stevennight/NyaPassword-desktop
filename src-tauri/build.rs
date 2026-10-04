fn main() {
    // Compiled into the binary by updater.rs (release builds set them in CI).
    println!("cargo:rerun-if-env-changed=NPW_UPDATE_REPO");
    println!("cargo:rerun-if-env-changed=NPW_UPDATE_PUBKEY");
    tauri_build::build()
}
