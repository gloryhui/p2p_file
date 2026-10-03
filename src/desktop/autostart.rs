//! Current-user login startup. Never installs a service or stores credentials.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::fs;
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
const ENTRY_NAME: &str = "p2p-file.desktop";

pub(super) fn apply(enabled: bool) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    apply_executable(enabled, &executable)
}

fn apply_executable(enabled: bool, executable: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let directory = dirs::config_dir()
            .ok_or("无法定位用户配置目录")?
            .join("autostart");
        write_entry(
            &directory.join(ENTRY_NAME),
            enabled,
            &linux_entry(executable)?,
        )
    }
    #[cfg(target_os = "macos")]
    {
        let directory = dirs::home_dir()
            .ok_or("无法定位用户目录")?
            .join("Library/LaunchAgents");
        write_entry(
            &directory.join("io.github.gloryhui.p2p-file.plist"),
            enabled,
            &mac_entry(executable)?,
        )
    }
    #[cfg(target_os = "windows")]
    {
        use std::{os::windows::ffi::OsStrExt, ptr};
        use windows_sys::Win32::{Foundation::ERROR_FILE_NOT_FOUND, System::Registry::*};
        let key: Vec<_> = r"Software\Microsoft\Windows\CurrentVersion\Run"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let name: Vec<_> = "P2P File".encode_utf16().chain(Some(0)).collect();
        let data: Vec<u16> = std::iter::once('"' as u16)
            .chain(executable.as_os_str().encode_wide())
            .chain("\" --background\0".encode_utf16())
            .collect();
        let bytes = u32::try_from(data.len() * 2).map_err(|_| "登录启动路径过长")?;
        let mut handle = ptr::null_mut();
        // Current-user registry only; an absent value is disabled, while access
        // errors must not be mistaken for successful removal.
        let result = unsafe {
            if enabled {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    key.as_ptr(),
                    0,
                    ptr::null(),
                    0,
                    KEY_SET_VALUE,
                    ptr::null(),
                    &mut handle,
                    ptr::null_mut(),
                )
            } else {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    key.as_ptr(),
                    0,
                    KEY_SET_VALUE,
                    &mut handle,
                )
            }
        };
        if !enabled && result == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result as i32).to_string());
        }
        let result = unsafe {
            let result = if enabled {
                RegSetValueExW(
                    handle,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    data.as_ptr().cast(),
                    bytes,
                )
            } else {
                RegDeleteValueW(handle, name.as_ptr())
            };
            RegCloseKey(handle);
            result
        };
        if result == 0 || !enabled && result == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(result as i32).to_string())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn write_entry(path: &Path, enabled: bool, content: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err("登录启动项不是普通文件，拒绝修改".into());
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
        _ => {}
    }
    if !enabled {
        return match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        };
    }
    let parent = path.parent().ok_or("启动项缺少父目录")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temp = parent.join(format!(".p2p-login-{:032x}", rand::random::<u128>()));
    let result = (|| {
        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(|e| e.to_string())?;
        file.write_all(content.as_bytes())
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temp, path).map_err(|e| e.to_string())
    })();
    let _ = fs::remove_file(temp);
    result
}

#[cfg(any(target_os = "linux", test))]
fn linux_entry(executable: &Path) -> Result<String, String> {
    let path = executable.to_str().ok_or("程序路径不是有效 UTF-8")?;
    if path.contains(['\n', '\r', '\0']) {
        return Err("程序路径包含无效字符".into());
    }
    // Desktop Entry string escaping is applied *after* Exec quoting. Percent is
    // a field-code delimiter even inside double quotes, and must be doubled.
    let quoted = path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('%', "%%");
    let quoted = quoted.replace('\\', "\\\\");
    Ok(format!(
        "[Desktop Entry]\nType=Application\nName=P2P File\nExec=\"{quoted}\" --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    ))
}

#[cfg(any(target_os = "macos", test))]
fn mac_entry(executable: &Path) -> Result<String, String> {
    let path = executable.to_str().ok_or("程序路径不是有效 UTF-8")?;
    if path.chars().any(|c| c < ' ') {
        return Err("程序路径包含无效字符".into());
    }
    let path = path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>io.github.gloryhui.p2p-file</string><key>ProgramArguments</key><array><string>{path}</string><string>--background</string></array><key>RunAtLoad</key><true/></dict></plist>\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn login_entries_quote_paths_without_shell_or_field_code_expansion() {
        let path = Path::new("/Applications/P2P File & 100%/$name.app/p2p-desktop");
        let linux = linux_entry(path).unwrap();
        assert!(linux.contains("100%%/\\\\$name"));
        assert!(linux.contains(" --background\n"));
        let mac = mac_entry(path).unwrap();
        assert!(mac.contains("File &amp; 100%/$name"));
        assert!(!mac.contains("<key>KeepAlive</key>"));
        assert!(linux_entry(Path::new("/tmp/new\nline")).is_err());
    }
    #[test]
    fn startup_registration_can_be_replaced_and_removed_without_touching_other_entries() {
        let directory =
            std::env::temp_dir().join(format!("p2p-autostart-{:032x}", rand::random::<u128>()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(ENTRY_NAME);
        fs::write(directory.join("other.desktop"), "keep").unwrap();
        write_entry(&path, true, "first").unwrap();
        write_entry(&path, true, "second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        write_entry(&path, false, "").unwrap();
        write_entry(&path, false, "").unwrap();
        assert_eq!(
            fs::read_to_string(directory.join("other.desktop")).unwrap(),
            "keep"
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
