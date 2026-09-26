use std::{env, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Worktrees use a .git file. Watch the actual HEAD, index and branch ref so
    // freezing a candidate rebuilds metadata even when Rust source is unchanged.
    for name in ["HEAD", "index"] {
        if let Some(path) = git(&["rev-parse", "--git-path", name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(files) = git(&["ls-files"]) {
        for path in files.lines() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let sha = git(&["rev-parse", "HEAD"])
        .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".into());
    let state = git(&["status", "--porcelain"])
        .map(|s| if s.is_empty() { "clean" } else { "dirty" })
        .unwrap_or("unknown");
    println!("cargo:rustc-env=P2P_BUILD_SHA={sha}");
    println!("cargo:rustc-env=P2P_BUILD_STATE={state}");
    println!(
        "cargo:rustc-env=P2P_BUILD_TARGET={}",
        env::var("TARGET").unwrap()
    );
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
}
