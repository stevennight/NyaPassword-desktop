fn main() {
    // Compiled into the binary by updater.rs (release builds set them in CI).
    println!("cargo:rerun-if-env-changed=NPW_UPDATE_REPO");
    println!("cargo:rerun-if-env-changed=NPW_UPDATE_PUBKEY");
    #[cfg(target_os = "macos")]
    {
        cc::Build::new()
            .file("macos_auth.m")
            .flag("-fobjc-arc")
            .compile("npw_macos_auth");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    }
    tauri_build::build()
}
