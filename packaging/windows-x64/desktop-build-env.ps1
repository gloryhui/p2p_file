# Shared Windows-only environment discovery for doctor.ps1 and build.ps1.
# Dot-source this file; all environment changes are limited to the current PowerShell process.
#requires -Version 5.1

function Invoke-P2PDesktopNativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$Arguments
    )

    # Windows PowerShell 5.1 promotes native stderr records to terminating
    # errors when ErrorActionPreference is Stop. Keep probes non-terminating
    # while preserving their output and process exit code.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Executable @Arguments 2>&1)
        return [PSCustomObject]@{
            Output = $output
            ExitCode = $LASTEXITCODE
        }
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Find-P2PVsWhere {
    $fromPath = Get-Command -Name 'vswhere.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $fromPath) {
        return $fromPath.Source
    }

    $roots = @(
        [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'),
        [Environment]::GetEnvironmentVariable('ProgramFiles')
    )
    foreach ($root in $roots) {
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $candidate = Join-Path $root 'Microsoft Visual Studio\Installer\vswhere.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return $candidate
            }
        }
    }
    return $null
}

function Get-P2PVisualStudioInstance {
    param([Parameter(Mandatory = $true)][string]$VsWherePath)

    $common = @('-latest', '-products', '*', '-version', '[17.0,18.0)', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64')
    $installationArguments = $common + @('-property', 'installationPath')
    $installationCapture = Invoke-P2PDesktopNativeCapture -Executable $VsWherePath -Arguments $installationArguments
    $installation = @($installationCapture.Output)
    $resultCode = $installationCapture.ExitCode
    if ($resultCode -ne 0 -or $installation.Count -eq 0 -or [string]::IsNullOrWhiteSpace([string]$installation[0])) {
        throw 'vswhere found no Visual Studio 2022 instance with the MSVC x86/x64 C++ toolset. Install the Desktop development with C++ workload, MSVC v143 x64/x86 tools, and a Windows SDK.'
    }

    $installationPath = [string]$installation[0]
    $devCommand = Join-Path $installationPath 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $devCommand -PathType Leaf)) {
        throw "Visual Studio developer environment script is missing: $devCommand"
    }

    $versionArguments = $common + @('-property', 'installationVersion')
    $versionCapture = Invoke-P2PDesktopNativeCapture -Executable $VsWherePath -Arguments $versionArguments
    $version = @($versionCapture.Output)
    if ($versionCapture.ExitCode -ne 0 -or $version.Count -eq 0) {
        $versionText = 'version unavailable'
    }
    else {
        $versionText = [string]$version[0]
    }

    return [PSCustomObject]@{
        VsWherePath = $VsWherePath
        InstallationPath = $installationPath
        InstallationVersion = $versionText
        VsDevCmdPath = $devCommand
    }
}

function Initialize-P2PVisualStudioEnvironment {
    param([Parameter(Mandatory = $true)][string]$VsWherePath)

    $instance = Get-P2PVisualStudioInstance -VsWherePath $VsWherePath
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('p2p-vsenv-' + [Guid]::NewGuid().ToString('N'))
    $batchPath = Join-Path $temporaryRoot 'initialize.cmd'
    $stdoutPath = Join-Path $temporaryRoot 'environment.txt'
    $stderrPath = Join-Path $temporaryRoot 'errors.txt'
    $oldVsDevCmd = [Environment]::GetEnvironmentVariable('P2P_VSDEV_CMD', 'Process')
    $environmentImported = 0

    try {
        New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null
        [Environment]::SetEnvironmentVariable('P2P_VSDEV_CMD', $instance.VsDevCmdPath, 'Process')
        $batchText = @'
@echo off
call "%P2P_VSDEV_CMD%" -no_logo -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 10
chcp 65001 >nul
set
'@
        $batchText = $batchText -replace "`n", "`r`n"
        [IO.File]::WriteAllText($batchPath, $batchText, [Text.Encoding]::ASCII)

        $commandArguments = '/d /s /c ""' + $batchPath + '""'
        $process = Start-Process -FilePath $env:ComSpec -ArgumentList $commandArguments -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        if ($process.ExitCode -ne 0) {
            $details = ''
            if (Test-Path -LiteralPath $stderrPath) {
                $details = [IO.File]::ReadAllText($stderrPath).Trim()
            }
            throw "VsDevCmd.bat failed to initialize its x64 environment (exit $($process.ExitCode)). $details"
        }

        foreach ($line in [IO.File]::ReadAllLines($stdoutPath)) {
            $separator = $line.IndexOf('=')
            if ($separator -le 0) {
                continue
            }
            $name = $line.Substring(0, $separator)
            $value = $line.Substring($separator + 1)
            if ($name -eq 'P2P_VSDEV_CMD' -or $name -notmatch '^[A-Za-z_][A-Za-z0-9_()]*$') {
                continue
            }
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
            $environmentImported++
        }

        if ($environmentImported -eq 0) {
            throw 'VsDevCmd.bat returned no environment variables; the x64 MSVC environment was not imported.'
        }
        return $instance
    }
    finally {
        [Environment]::SetEnvironmentVariable('P2P_VSDEV_CMD', $oldVsDevCmd, 'Process')
        if (Test-Path -LiteralPath $temporaryRoot) {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-P2PVisualStudioEnvironment {
    $cl = Get-Command -Name 'cl.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $link = Get-Command -Name 'link.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $cl -or $null -eq $link) {
        throw 'The imported x64 developer environment must expose both cl.exe and link.exe.'
    }
    if ($env:VSCMD_ARG_TGT_ARCH -ne 'x64' -or $env:VSCMD_ARG_HOST_ARCH -ne 'x64') {
        throw "Expected an x64-host/x64-target environment; detected host=$env:VSCMD_ARG_HOST_ARCH target=$env:VSCMD_ARG_TGT_ARCH."
    }
    if ([string]$env:VCToolsVersion -notmatch '^14\.(3|4)[0-9]') {
        throw "Expected the Visual Studio 2022 v143 MSVC toolset; detected VCToolsVersion=$env:VCToolsVersion."
    }
    if ([string]::IsNullOrWhiteSpace($env:WindowsSdkDir) -or [string]::IsNullOrWhiteSpace($env:WindowsSDKVersion)) {
        throw 'VsDevCmd did not select a Windows SDK. Install a Windows 10/11 SDK through Visual Studio Installer.'
    }
    $sdkVersionPath = ([string]$env:WindowsSDKVersion).TrimEnd([char[]]@('\', '/'))
    $sdkInclude = [IO.Path]::Combine($env:WindowsSdkDir, 'Include', $sdkVersionPath, 'um', 'Windows.h')
    if (-not (Test-Path -LiteralPath $sdkInclude -PathType Leaf)) {
        throw "Windows SDK headers were not found under $($env:WindowsSdkDir) (version $($env:WindowsSDKVersion))."
    }
    $sdkLibrary = [IO.Path]::Combine($env:WindowsSdkDir, 'Lib', $sdkVersionPath, 'um', 'x64', 'kernel32.lib')
    if (-not (Test-Path -LiteralPath $sdkLibrary -PathType Leaf)) {
        throw "Windows SDK x64 libraries were not found under $($env:WindowsSdkDir) (version $($env:WindowsSDKVersion))."
    }
    if ([string]::IsNullOrWhiteSpace($env:VCToolsInstallDir) -or -not (Test-Path -LiteralPath $env:VCToolsInstallDir -PathType Container)) {
        throw "MSVC x64 toolset directory is unavailable: $env:VCToolsInstallDir"
    }
    $toolsPrefix = $env:VCToolsInstallDir.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    if (-not $cl.Source.StartsWith($toolsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not $link.Source.StartsWith($toolsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "cl.exe and link.exe must come from the selected Visual Studio MSVC toolset at $($env:VCToolsInstallDir)."
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('p2p-msvc-probe-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null
        $sourcePath = Join-Path $temporaryRoot 'sdk_probe.cpp'
        $executablePath = Join-Path $temporaryRoot 'sdk_probe.exe'
        [IO.File]::WriteAllText($sourcePath, "#include <windows.h>`r`nint main(void) { return GetCurrentProcessId() == 0; }`r`n", [Text.Encoding]::ASCII)
        $compilerArguments = @('/nologo', '/EHsc', ('/Fe:' + $executablePath), $sourcePath)
        $compilerCapture = Invoke-P2PDesktopNativeCapture -Executable $cl.Source -Arguments $compilerArguments
        $compilerOutput = @($compilerCapture.Output)
        $compileCode = $compilerCapture.ExitCode
        if ($compileCode -ne 0 -or -not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
            throw "MSVC/Windows SDK compile-and-link probe failed (exit $compileCode): $($compilerOutput -join ' ')"
        }

        return [PSCustomObject]@{
            ClPath = $cl.Source
            LinkPath = $link.Source
            ToolsetVersion = [string]$env:VCToolsVersion
            ToolsDirectory = [string]$env:VCToolsInstallDir
            WindowsSdkDirectory = [string]$env:WindowsSdkDir
            WindowsSdkVersion = [string]$env:WindowsSDKVersion
            TargetArchitecture = [string]$env:VSCMD_ARG_TGT_ARCH
            HostArchitecture = [string]$env:VSCMD_ARG_HOST_ARCH
            Probe = 'windows.h compile and link passed'
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryRoot) {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Find-P2PPython {
    # Avoid quotes in the Python -c payload. Windows PowerShell 5.1 strips
    # embedded quotes from native command arguments before launching Python.
    $probeCode = 'import sys,tomllib; assert sys.version_info >= (3,11); print(sys.version_info[0],sys.version_info[1],sys.version_info[2],sys.executable,sep=chr(124))'
    $candidates = @()
    $launcher = Get-Command -Name 'py.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $launcher) {
        $candidates += [PSCustomObject]@{ Path = $launcher.Source; Prefix = @('-3.12') }
        $candidates += [PSCustomObject]@{ Path = $launcher.Source; Prefix = @('-3') }
    }
    $direct = @(Get-Command -Name 'python3.12.exe', 'python3.exe', 'python.exe' -CommandType Application -All -ErrorAction SilentlyContinue |
        Sort-Object -Property Source -Unique)
    foreach ($command in $direct) {
        if ($command.Source -notmatch '\\Microsoft\\WindowsApps\\') {
            $candidates += [PSCustomObject]@{ Path = $command.Source; Prefix = @() }
        }
    }

    foreach ($candidate in $candidates) {
        $arguments = @($candidate.Prefix) + @('-c', $probeCode)
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $candidate.Path @arguments 2>$null)
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($exitCode -ne 0 -or $output.Count -eq 0) {
            continue
        }
        try {
            $parts = ([string]($output -join [Environment]::NewLine)).Trim() -split '\|'
            if ($parts.Count -ge 4) {
                $pythonPath = [string]$parts[3]
                $pythonVersion = '{0}.{1}.{2}' -f $parts[0], $parts[1], $parts[2]
                [Version]$null = [Version]::Parse($pythonVersion)
            }
            else {
                continue
            }
            if (-not [string]::IsNullOrWhiteSpace($pythonPath) -and $pythonPath -notmatch '\\Microsoft\\WindowsApps\\') {
                return [PSCustomObject]@{
                    Path = $pythonPath
                    Version = $pythonVersion
                    Launcher = [string]$candidate.Path
                }
            }
        }
        catch {
            continue
        }
    }
    return $null
}
