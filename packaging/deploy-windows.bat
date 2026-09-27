@echo off
setlocal EnableExtensions

title P2P File Windows Build and Deploy

set "P2P_REPO=F:\git\p2p_file"
set "P2P_TARGET=x86_64-pc-windows-msvc"

if not exist "%P2P_REPO%\Cargo.toml" (
    echo ERROR: Source checkout was not found at %P2P_REPO%
    pause
    exit /b 1
)
if not exist "%P2P_REPO%\scripts\package-desktop-tests.py" goto :source_incomplete
if not exist "%P2P_REPO%\scripts\package-desktop.py" goto :source_incomplete
if not exist "%P2P_REPO%\scripts\verify-desktop-package.py" goto :source_incomplete

where cargo.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: Rust/Cargo was not found. Install rustup and restart this script.
    pause
    exit /b 1
)
where rustup.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: rustup.exe was not found on PATH.
    pause
    exit /b 1
)
where git.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: git.exe was not found on PATH.
    pause
    exit /b 1
)

where python.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: python.exe was not found on PATH.
    pause
    exit /b 1
)
python.exe -c "import sys, tomllib; print('Python', sys.version.split()[0]); sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
    echo ERROR: Python 3.11 or newer with tomllib is required.
    pause
    exit /b 1
)

if defined VSCMD_VER goto :msvc_ready
if not exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" goto :msvc_missing
for /f "usebackq tokens=*" %%I in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "P2P_VSINSTALL=%%I"
if not defined P2P_VSINSTALL goto :msvc_missing
if not exist "%P2P_VSINSTALL%\Common7\Tools\VsDevCmd.bat" goto :msvc_missing
call "%P2P_VSINSTALL%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 goto :msvc_missing
goto :msvc_ready

:msvc_missing
echo ERROR: Visual Studio C++ Build Tools with the MSVC x64 toolset were not found or could not be initialized.
echo Install MSVC x64 build tools and a Windows SDK, then retry.
pause
exit /b 1

:msvc_ready

goto :tools_ready

:source_incomplete
echo ERROR: Required packaging scripts are missing from %P2P_REPO%\scripts.
echo Update or restore the repository checkout before building the candidate.
pause
exit /b 1

:tools_ready

pushd "%P2P_REPO%"
if errorlevel 1 (
    echo ERROR: Could not enter %P2P_REPO%.
    pause
    exit /b 1
)

set "P2P_DIRTY="
for /f "delims=" %%L in ('git status --porcelain --untracked-files^=all') do set "P2P_DIRTY=1"
if defined P2P_DIRTY (
    echo ERROR: The source checkout must be clean to create a verified candidate.
    git status --short
    popd
    pause
    exit /b 1
)

echo Installing the Rust Windows target...
rustup target add %P2P_TARGET%
if errorlevel 1 goto :failed

echo Running package boundary checks...
python.exe scripts\package-desktop-tests.py
if errorlevel 1 goto :failed

echo Building the Windows x64 desktop app...
cargo build --locked --release --features gui --bin p2p-desktop --target %P2P_TARGET%
if errorlevel 1 goto :failed

for /f "usebackq delims=" %%D in (`powershell.exe -NoLogo -NoProfile -Command "[Environment]::GetFolderPath('Desktop')"`) do set "P2P_DESKTOP=%%D"
if not defined P2P_DESKTOP (
    echo ERROR: Could not locate the current user's Desktop folder.
    goto :failed
)
set "P2P_PACKAGE_DIR=%P2P_DESKTOP%\p2p-file-win-x64"
if exist "%P2P_PACKAGE_DIR%\candidate.json" (
    echo ERROR: Candidate output already exists: %P2P_PACKAGE_DIR%
    echo Move or rename it so prior evidence is not overwritten, then retry.
    goto :failed
)

echo Creating and verifying the Windows candidate package...
python.exe scripts\package-desktop.py --binary "target\%P2P_TARGET%\release\p2p-desktop.exe" --target %P2P_TARGET% --output "%P2P_PACKAGE_DIR%"
if errorlevel 1 goto :failed
python.exe scripts\verify-desktop-package.py "%P2P_PACKAGE_DIR%\candidate.json"
if errorlevel 1 goto :failed

set "P2P_SOURCE_PACKAGE="
for /d %%D in ("%P2P_PACKAGE_DIR%\p2p-desktop-*") do if not defined P2P_SOURCE_PACKAGE set "P2P_SOURCE_PACKAGE=%%D"
if not defined P2P_SOURCE_PACKAGE (
    echo ERROR: Verified package directory was not found.
    goto :failed
)
for %%D in ("%P2P_SOURCE_PACKAGE%") do set "P2P_INSTALL=%LOCALAPPDATA%\Programs\P2P File\%%~nxD"

echo Installing and launching P2P File...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $proc=Get-Process -Name 'p2p-desktop' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $env:P2P_INSTALL 'p2p-desktop.exe') }; if ($proc) { throw 'Close the installed P2P File app and run this BAT again' }; New-Item -ItemType Directory -Path (Split-Path -Parent $env:P2P_INSTALL) -Force | Out-Null; if (Test-Path -LiteralPath $env:P2P_INSTALL) { Remove-Item -LiteralPath $env:P2P_INSTALL -Recurse -Force }; Copy-Item -LiteralPath $env:P2P_SOURCE_PACKAGE -Destination $env:P2P_INSTALL -Recurse -Force; $exe=Join-Path $env:P2P_INSTALL 'p2p-desktop.exe'; $desktop=[Environment]::GetFolderPath('Desktop'); $shell=New-Object -ComObject WScript.Shell; $shortcut=$shell.CreateShortcut((Join-Path $desktop 'P2P File.lnk')); $shortcut.TargetPath=$exe; $shortcut.WorkingDirectory=$env:P2P_INSTALL; $shortcut.Description='P2P File'; $shortcut.Save(); Start-Process -FilePath $exe -WorkingDirectory $env:P2P_INSTALL"
if errorlevel 1 goto :failed

echo.
echo Build, package verification, installation, and launch completed.
echo Candidate evidence: %P2P_PACKAGE_DIR%
echo Installed app:     %P2P_INSTALL%\p2p-desktop.exe
popd
exit /b 0

:failed
echo.
echo Build or deployment failed. Review the error above.
popd
pause
exit /b 1
