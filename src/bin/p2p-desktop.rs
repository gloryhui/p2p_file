//! GPUI desktop shell entry point.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if !arguments.is_empty() {
        if arguments.len() != 1 {
            eprintln!("Use p2p-desktop --help");
            std::process::exit(2);
        }
        match arguments[0].as_str() {
            "--version" | "-V" => println!(
                "p2p-desktop {} ({}; {}; {})",
                env!("CARGO_PKG_VERSION"),
                env!("P2P_BUILD_SHA"),
                env!("P2P_BUILD_TARGET"),
                env!("P2P_BUILD_STATE")
            ),
            "--build-info" => println!(
                "{}",
                serde_json::json!({
                    "name": "p2p-desktop", "version": env!("CARGO_PKG_VERSION"),
                    "build_sha": env!("P2P_BUILD_SHA"), "target": env!("P2P_BUILD_TARGET"),
                    "source_state": env!("P2P_BUILD_STATE")
                })
            ),
            "--help" | "-h" => println!(
                "P2P File desktop\n\nRun without arguments to open the native window.\n  --version, -V  Version and source commit\n  --build-info   Machine-readable build metadata\n  --help, -h     This help\n\nConfigure your signaling server and receive folder in Settings."
            ),
            _ => {
                eprintln!("Unknown argument. Use p2p-desktop --help");
                std::process::exit(2);
            }
        }
        return;
    }
    p2p_file::desktop::run();
}
