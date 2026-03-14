use std::path::Path;
use std::process::Command;

fn main() {
    let ui_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let dist_dir = ui_dir.join("dist");
    let src_dir = ui_dir.join("src");

    // Re-run this build script if any frontend source or dist file changes
    println!("cargo:rerun-if-changed={}", src_dir.display());
    println!("cargo:rerun-if-changed={}", dist_dir.display());
    println!("cargo:rerun-if-changed={}", ui_dir.join("index.html").display());
    println!("cargo:rerun-if-changed={}", ui_dir.join("package.json").display());

    if !dist_dir.join("index.html").exists() {
        println!("cargo:warning=Frontend dist/ not found, running npm build...");

        let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
        let status = Command::new(npm)
            .arg("run")
            .arg("build")
            .current_dir(ui_dir)
            .status()
            .expect("Failed to run npm build. Is npm installed?");

        if !status.success() {
            panic!("Frontend build failed (npm run build exited with {})", status);
        }
    }

    tauri_build::build();

    // Verify that Tauri will embed assets (custom-protocol feature).
    // Without this, the webview connects to devUrl (localhost:5173) and shows
    // ERR_CONNECTION_REFUSED. The `custom-protocol` feature is a default feature
    // in this crate, but this guard catches accidental --no-default-features in
    // release builds.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let has_custom_protocol = std::env::var("CARGO_FEATURE_CUSTOM_PROTOCOL").is_ok();
    if profile == "release" && !has_custom_protocol {
        panic!(
            "Release build without `custom-protocol` feature! \
             The Tauri webview will fail to load. \
             Use: cargo build --release  (default features include it) \
             Or:  cargo build --release --features custom-protocol"
        );
    }
}
