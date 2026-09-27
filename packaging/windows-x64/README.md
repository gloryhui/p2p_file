# Windows x64 GUI package

This directory diagnoses and builds a native Windows GUI package through the repository's existing package builder and verifier. It does not copy their packaging logic.

## Supported target

- Desktop support target: Windows 10 22H2 (build 19045+) and Windows 11, x64
- Rust target: `x86_64-pc-windows-msvc`
- Build chain: Visual Studio 2022 / Build Tools with MSVC v143 x64/x86 tools and a Windows 10/11 SDK
- 32-bit Windows, 32-bit PowerShell processes, and Windows ARM64 are not supported targets
- Windows Server may be useful for CI/development checks, but it is not a supported desktop-product environment

MSVC is required because the Rust target is `x86_64-pc-windows-msvc`. MinGW is not a substitute for this target.

## Prepare the machine

Run the doctor first. It only diagnoses and prints remediation steps; it does not install software, change PATH permanently, start Visual Studio Installer, or change ExecutionPolicy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\packaging\windows-x64\doctor.ps1
```

PowerShell 7 is also supported when installed. Use a 64-bit PowerShell process. The `-ExecutionPolicy Bypass` option applies only to this PowerShell launch and does not change the machine or user policy.

Required tools:

1. Git for Windows.
2. Python 3.11+ with `tomllib` (3.12 recommended). Install from [python.org](https://www.python.org/downloads/windows/); if you use `winget`, `winget install Python.Python.3.12` is an optional manual command. Do not select Microsoft Store execution aliases in **Manage app execution aliases**.
3. Rust stable from [rustup.rs](https://rustup.rs/), with minimum rustc/Cargo version **1.85.0**. The doctor parses both version outputs and rejects older or unparseable versions before Cargo build. For an existing installation, run rustup update stable and add the target:

   ```powershell
   rustup update stable
   rustup target add x86_64-pc-windows-msvc
   ```

4. In Visual Studio Installer, add **Desktop development with C++**, **MSVC v143 - VS 2022 C++ x64/x86 build tools**, and a **Windows 10 or Windows 11 SDK**. The doctor uses `vswhere` and then runs `VsDevCmd.bat` in a temporary child process to inspect the actual x64 compiler, linker, SDK headers, and compile/link a small `windows.h` probe.

## Build

The build script locates Visual Studio itself and imports its x64 environment into the current PowerShell process. You do not need to open an “x64 Native Tools Command Prompt”. The default output is a new directory under `%USERPROFILE%\p2p-file-builds`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\packaging\windows-x64\build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\packaging\windows-x64\build.ps1 -Output "$env:USERPROFILE\p2p-file-builds\acceptance win"
```

For a traditional CMD/double-click entry:

```bat
packaging\windows-x64\build.cmd -Output "%USERPROFILE%\p2p-file-builds\acceptance win"
```

The script requires a clean Git worktree, runs `scripts/package-desktop-tests.py`, performs the locked release GUI build, then calls `scripts/package-desktop.py` and `scripts/verify-desktop-package.py`. Output must be outside the repository. Existing non-empty output directories are rejected, never overwritten.

The output includes the ZIP, `candidate.json`, and its shared-core `.sha256` sidecar. The build summary reports build SHA, target, ZIP path and SHA256, executable path, and the package builder's actual Authenticode result.

## Signing

Candidates are currently **NotSigned**. They do not have an Authenticode certificate. The doctor checks that the PowerShell signature API used by the shared package builder works; the packager records the actual candidate status and refuses unexpected signing states.

## Common problems

- **Windows 10 build below 19045**: upgrade Windows 10 to 22H2 or later, or use Windows 11.
- **Python opens Microsoft Store**: install Python from python.org and turn off the Windows Store `python.exe`/`python3.exe` aliases. Doctor skips executables under `WindowsApps`.
- **`vswhere` is missing**: install/repair Visual Studio Installer with Visual Studio 2022 Build Tools.
- **`cl.exe` or `link.exe` is missing**: use Visual Studio Installer to add the C++ workload and MSVC v143 x64/x86 tools. A pre-existing `VSCMD_VER` variable alone does not count as a working toolchain.
- **Windows SDK header missing**: add a Windows 10/11 SDK component in Visual Studio Installer.
- **Rust target missing**: run `rustup target add x86_64-pc-windows-msvc`.
- **Dirty worktree**: commit or stash changes before building a complete candidate.
- **Output contains spaces**: quote the entire `-Output` path; paths are passed as arguments, not assembled into a shell command.
- **ExecutionPolicy warning**: use the per-process `-ExecutionPolicy Bypass` command above; no permanent policy change is needed.

`desktop-build-env.ps1` is an internal helper shared by the doctor and build entrypoint. It imports the Visual Studio environment only into the current process and uses temporary files that it removes after each probe. No package installation or permanent environment change is performed.
