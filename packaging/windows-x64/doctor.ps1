#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:FailureCount = 0
$script:WarningCount = 0
$Target = 'x86_64-pc-windows-msvc'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$HelperPath = Join-Path $PSScriptRoot 'desktop-build-env.ps1'
$RemediateVs = 'In Visual Studio Installer, add Desktop development with C++, MSVC v143 x64/x86 build tools, and a Windows 10/11 SDK; do not install them from this script.'

function Write-DoctorCheck {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'WARN', 'FAIL')][string]$State,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Detected,
        [Parameter(Mandatory = $true)][string]$Required,
        [Parameter(Mandatory = $true)][string]$Remediation
    )
    Write-Host (('{0,-4} | {1} | detected: {2} | required: {3} | remediation: {4}' -f $State, $Name, $Detected, $Required, $Remediation))
    if ($State -eq 'FAIL') { $script:FailureCount++ }
    if ($State -eq 'WARN') { $script:WarningCount++ }
}

function Invoke-P2PNativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$Arguments
    )

    # Windows PowerShell 5.1 promotes native stderr records to terminating
    # errors when ErrorActionPreference is Stop. rustup writes informational
    # version details to stderr, so capture native output with a local,
    # non-terminating preference and preserve the process exit code.
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

function ConvertTo-RustBaseVersion {
    param([Parameter(Mandatory = $true)][string]$ToolName, [Parameter(Mandatory = $true)][string]$Output)
    $escapedName = [Regex]::Escape($ToolName)
    $pattern = '^\s*' + $escapedName + '\s+(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?(?:\s|$)'
    $match = [Regex]::Match($Output.Trim(), $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) { return $null }
    try {
        $triplet = '{0}.{1}.{2}' -f $match.Groups[1].Value, $match.Groups[2].Value, $match.Groups[3].Value
        return [Version]::Parse($triplet)
    }
    catch {
        return $null
    }
}

function Test-RustToolVersion {
    param([Parameter(Mandatory = $true)][string]$Name)
    $displayName = $Name -replace '\.exe$', ''
    $required = '>= 1.90.0'
    $remediation = 'Run: rustup update stable'
    $tool = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $tool) {
        Write-DoctorCheck FAIL ($displayName + ' version') 'not found' $required $remediation
        return $null
    }

    $capture = Invoke-P2PNativeCapture -Executable $tool.Source -Arguments @('--version')
    $versionOutput = @($capture.Output)
    $exitCode = $capture.ExitCode
    $versionLine = [string]($versionOutput | Select-Object -First 1)
    if ($exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($versionLine)) {
        Write-DoctorCheck FAIL ($displayName + ' version') ($tool.Source + ' (version command failed)') $required $remediation
        return $tool
    }

    $parsedVersion = ConvertTo-RustBaseVersion -ToolName $displayName -Output $versionLine
    if ($null -eq $parsedVersion) {
        Write-DoctorCheck FAIL ($displayName + ' version') ($tool.Source + ' (unrecognized version output: ' + $versionLine + ')') $required $remediation
    }
    elseif ($parsedVersion -ge [Version]'1.90.0') {
        Write-DoctorCheck PASS ($displayName + ' version') ($tool.Source + ' (' + $parsedVersion.ToString() + ')') $required 'none'
    }
    else {
        Write-DoctorCheck FAIL ($displayName + ' version') ($tool.Source + ' (' + $parsedVersion.ToString() + ')') $required $remediation
    }
    return $tool
}

function Test-VersionCommand {
    param([string]$Name, [string[]]$Arguments, [string]$Required, [string]$Remediation)
    $tool = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $tool) {
        Write-DoctorCheck FAIL $Name 'not found' $Required $Remediation
        return $null
    }
    $capture = Invoke-P2PNativeCapture -Executable $tool.Source -Arguments $Arguments
    $versionOutput = @($capture.Output)
    $exitCode = $capture.ExitCode
    $version = [string]($versionOutput | Select-Object -First 1)
    if ($exitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($version)) {
        Write-DoctorCheck PASS $Name ($tool.Source + ' (' + $version + ')') $Required 'none'
        return $tool
    }
    Write-DoctorCheck FAIL $Name ($tool.Source + ' (version command failed)') $Required $Remediation
    return $tool
}

Write-Host 'P2P File Windows x64 packaging doctor'
Write-Host ('repo: ' + $RepoRoot)
Write-Host ('target: ' + $Target)

if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Write-DoctorCheck PASS 'operating system' ([Environment]::OSVersion.VersionString) 'Windows x64' 'none'
}
else {
    Write-DoctorCheck FAIL 'operating system' ([Environment]::OSVersion.Platform.ToString()) 'Windows 10 22H2+ or Windows 11 x64' 'Run this doctor on Windows.'
}

$currentVersion = $null
try {
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
}
catch {
    Write-DoctorCheck FAIL 'Windows version/build' ('registry query failed: ' + $_.Exception.Message) 'Windows 10 build 19045+ or Windows 11' 'Run on Windows 10 22H2 or later, or Windows 11.'
}

if ($null -ne $currentVersion) {
    $productName = [string]$currentVersion.ProductName
    $displayVersion = [string]$currentVersion.DisplayVersion
    if ([string]::IsNullOrWhiteSpace($displayVersion)) { $displayVersion = [string]$currentVersion.ReleaseId }
    $osBuild = 0
    $buildParsed = [int]::TryParse([string]$currentVersion.CurrentBuildNumber, [ref]$osBuild)
    $versionDetected = ($productName + '; DisplayVersion=' + $displayVersion + '; build=' + [string]$currentVersion.CurrentBuildNumber)
    if (-not $buildParsed) {
        Write-DoctorCheck FAIL 'Windows version/build' $versionDetected 'Windows 10 build 19045+ or Windows 11' 'Read the OS build from Windows Settings and upgrade if it is below Windows 10 22H2.'
    }
    elseif ($productName -match 'Server') {
        Write-DoctorCheck WARN 'Windows version/build' ($versionDetected + '; Windows Server is development/CI only') 'Windows 10 22H2+ / Windows 11 is the desktop support target' 'Use Windows 10 22H2+ or Windows 11 for desktop-product validation.'
    }
    elseif ($osBuild -ge 22000) {
        Write-DoctorCheck PASS 'Windows version/build' $versionDetected 'Windows 11 x64' 'none'
    }
    elseif ($productName -match 'Windows 10' -and $osBuild -ge 19045) {
        Write-DoctorCheck PASS 'Windows version/build' $versionDetected 'Windows 10 22H2 or later (build 19045+)' 'none'
    }
    elseif ($productName -match 'Windows 10') {
        Write-DoctorCheck FAIL 'Windows version/build' $versionDetected 'Windows 10 build 19045+ (22H2) or Windows 11' 'Upgrade Windows 10 to 22H2 or later (build 19045+), or use Windows 11.'
    }
    else {
        Write-DoctorCheck FAIL 'Windows version/build' $versionDetected 'Windows 10 22H2+ or Windows 11' 'Use Windows 10 22H2+ or Windows 11 x64.'
    }
}

$osArchitectureName = $null
try {
    $processorArchitectures = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -ExpandProperty Architecture -Unique)
    if ($processorArchitectures -contains 9) { $osArchitectureName = 'x64 (AMD64)' }
    elseif ($processorArchitectures -contains 12) { $osArchitectureName = 'ARM64' }
    elseif ($processorArchitectures -contains 0) { $osArchitectureName = 'x86' }
}
catch {
    $osArchitectureName = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
    if ([string]::IsNullOrWhiteSpace($osArchitectureName)) {
        $osArchitectureName = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
    }
}
if ([Environment]::Is64BitOperatingSystem -and $osArchitectureName -match '^(AMD64|x64|x64 \(AMD64\))$') {
    Write-DoctorCheck PASS 'OS architecture' $osArchitectureName 'x64 operating system' 'none'
}
else {
    $architectureFix = 'Use x64 Windows; ARM64 Windows and 32-bit Windows are not supported targets.'
    Write-DoctorCheck FAIL 'OS architecture' ([string]$osArchitectureName) 'x64 (AMD64) operating system' $architectureFix
}
if ([Environment]::Is64BitProcess) {
    Write-DoctorCheck PASS 'PowerShell process architecture' '64-bit process' '64-bit PowerShell for x64 MSVC' 'none'
}
else {
    Write-DoctorCheck FAIL 'PowerShell process architecture' '32-bit process' '64-bit PowerShell for x64 MSVC' 'Launch 64-bit PowerShell; from a 32-bit parent process, use %WINDIR%\Sysnative\WindowsPowerShell\v1.0\powershell.exe.'
}

$git = Test-VersionCommand 'git.exe' @('--version') 'Git available on PATH with a readable version' 'Install Git for Windows from https://git-scm.com/download/win.'
$rustup = Test-VersionCommand 'rustup.exe' @('--version') 'rustup available on PATH with a readable version' 'Install Rust using rustup from https://rustup.rs/.'
$cargo = Test-RustToolVersion 'cargo.exe'
$rustc = Test-RustToolVersion 'rustc.exe'

if ($null -ne $rustup) {
    $targetCapture = Invoke-P2PNativeCapture -Executable $rustup.Source -Arguments @('target', 'list', '--installed')
    $installedTargets = @($targetCapture.Output | ForEach-Object { [string]$_ })
    if ($targetCapture.ExitCode -eq 0 -and $installedTargets -contains $Target) {
        Write-DoctorCheck PASS 'Rust target' ($Target + ' installed') $Target 'none'
    }
    else {
        Write-DoctorCheck FAIL 'Rust target' (($installedTargets -join ', ') -replace '^$', 'no installed targets') $Target ('Install it with: rustup target add ' + $Target)
    }
}
else {
    Write-DoctorCheck FAIL 'Rust target' 'rustup unavailable' ($Target + ' installed') ('Install Rust using rustup, then run: rustup target add ' + $Target)
}

if (Test-Path -LiteralPath $HelperPath -PathType Leaf) {
    . $HelperPath
    $python = Find-P2PPython
}
else {
    $python = $null
}
if ($null -ne $python) {
    Write-DoctorCheck PASS 'Python' ($python.Path + ' (Python ' + $python.Version + '; tomllib import OK)') 'Python >= 3.11 with tomllib; 3.12 recommended' 'none'
}
else {
    Write-DoctorCheck FAIL 'Python' 'no usable Python 3 interpreter found; Microsoft Store aliases are ignored' 'Python >= 3.11 with tomllib' 'Install Python 3.12 from https://www.python.org/downloads/windows/; optional manual example: winget install Python.Python.3.12. Do not use a Microsoft Store execution alias.'
}

$vsWhere = $null
$vsInstance = $null
$vsEnvironment = $null
$vsEnvironmentInitialized = $false
$vsEnvironmentError = 'Visual Studio environment helper is missing.'
if (Test-Path -LiteralPath $HelperPath -PathType Leaf) {
    $vsWhere = Find-P2PVsWhere
}
if ($null -ne $vsWhere) {
    Write-DoctorCheck PASS 'vswhere.exe' $vsWhere 'Visual Studio Installer discovery tool' 'none'
    try {
        $vsInstance = Initialize-P2PVisualStudioEnvironment -VsWherePath $vsWhere
        $vsEnvironmentInitialized = $true
        Write-DoctorCheck PASS 'Visual Studio 2022 / Build Tools' ($vsInstance.InstallationPath + ' (version ' + $vsInstance.InstallationVersion + ')') 'VS 2022 with Microsoft.VisualStudio.Component.VC.Tools.x86.x64' $RemediateVs
    }
    catch {
        $vsEnvironmentError = $_.Exception.Message
        Write-DoctorCheck FAIL 'Visual Studio 2022 / Build Tools' $vsEnvironmentError 'VS 2022 with MSVC v143 x64/x86 and an initializable x64 environment' $RemediateVs
    }
}
else {
    $vsEnvironmentError = 'vswhere.exe was not found; Visual Studio 2022 could not be initialized.'
    Write-DoctorCheck FAIL 'vswhere.exe' 'not found in PATH or Visual Studio Installer directory' 'vswhere.exe from Visual Studio Installer' $RemediateVs
    Write-DoctorCheck FAIL 'Visual Studio 2022 / Build Tools' 'installation not discoverable' 'VS 2022 with MSVC v143 x64/x86' $RemediateVs
}

$clCommand = Get-Command -Name 'cl.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$linkCommand = Get-Command -Name 'link.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($vsEnvironmentInitialized) {
    if ($null -ne $clCommand) {
        Write-DoctorCheck PASS 'cl.exe' $clCommand.Source 'available after VsDevCmd x64 initialization' 'none'
    }
    else {
        Write-DoctorCheck FAIL 'cl.exe' 'not found after VsDevCmd x64 initialization' 'x64 MSVC compiler' $RemediateVs
    }
    if ($null -ne $linkCommand) {
        Write-DoctorCheck PASS 'link.exe' $linkCommand.Source 'available after VsDevCmd x64 initialization' 'none'
    }
    else {
        Write-DoctorCheck FAIL 'link.exe' 'not found after VsDevCmd x64 initialization' 'x64 MSVC linker' $RemediateVs
    }

    if ([string]$env:VCToolsVersion -match '^14\.(3|4)[0-9]' -and -not [string]::IsNullOrWhiteSpace($env:VCToolsInstallDir)) {
        Write-DoctorCheck PASS 'MSVC x64 toolset' ($env:VCToolsVersion + ' at ' + $env:VCToolsInstallDir) 'Visual Studio 2022 v143 x64/x86 toolset' 'none'
    }
    else {
        Write-DoctorCheck FAIL 'MSVC x64 toolset' ([string]$env:VCToolsVersion + ' at ' + [string]$env:VCToolsInstallDir) 'Visual Studio 2022 v143 x64/x86 toolset' $RemediateVs
    }

    $sdkHeader = $null
    $sdkLibrary = $null
    if (-not [string]::IsNullOrWhiteSpace($env:WindowsSdkDir) -and -not [string]::IsNullOrWhiteSpace($env:WindowsSDKVersion)) {
        $sdkVersionPath = ([string]$env:WindowsSDKVersion).TrimEnd([char[]]@('\', '/'))
        $sdkHeader = [IO.Path]::Combine($env:WindowsSdkDir, 'Include', $sdkVersionPath, 'um', 'Windows.h')
        $sdkLibrary = [IO.Path]::Combine($env:WindowsSdkDir, 'Lib', $sdkVersionPath, 'um', 'x64', 'kernel32.lib')
    }
    if ($null -ne $sdkHeader -and (Test-Path -LiteralPath $sdkHeader -PathType Leaf) -and (Test-Path -LiteralPath $sdkLibrary -PathType Leaf)) {
        Write-DoctorCheck PASS 'Windows SDK' ($env:WindowsSdkDir + ' version ' + $env:WindowsSDKVersion + '; Windows.h and x64 kernel32.lib present') 'Windows 10/11 SDK headers and x64 libraries' 'none'
    }
    else {
        Write-DoctorCheck FAIL 'Windows SDK' ([string]$env:WindowsSdkDir + ' version ' + [string]$env:WindowsSDKVersion) 'Windows 10/11 SDK headers and x64 libraries' $RemediateVs
    }

    try {
        $vsEnvironment = Test-P2PVisualStudioEnvironment
        Write-DoctorCheck PASS 'MSVC/SDK compile-link probe' $vsEnvironment.Probe 'compile a windows.h program with the x64 MSVC linker' 'none'
    }
    catch {
        Write-DoctorCheck FAIL 'MSVC/SDK compile-link probe' $_.Exception.Message 'working cl.exe, link.exe, v143 x64 tools, and Windows SDK' $RemediateVs
    }
}
else {
    Write-DoctorCheck FAIL 'cl.exe' ($vsEnvironmentError + '; x64 environment not initialized') 'x64 MSVC compiler' $RemediateVs
    Write-DoctorCheck FAIL 'link.exe' ($vsEnvironmentError + '; x64 environment not initialized') 'x64 MSVC linker' $RemediateVs
    Write-DoctorCheck FAIL 'MSVC x64 toolset / Windows SDK' $vsEnvironmentError 'v143 x64 toolset and Windows 10/11 SDK headers/libraries' $RemediateVs
    Write-DoctorCheck FAIL 'MSVC/SDK compile-link probe' 'x64 developer environment could not be initialized' 'compile a windows.h program with the x64 MSVC linker' $RemediateVs
}

$powerShellVersion = $PSVersionTable.PSVersion.ToString()
if (($PSVersionTable.PSVersion.Major -gt 5) -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -ge 1)) {
    Write-DoctorCheck PASS 'PowerShell' ($PSVersionTable.PSEdition + ' ' + $powerShellVersion + ' at ' + $PSHOME) 'Windows PowerShell 5.1 or PowerShell 7+' 'none'
}
else {
    Write-DoctorCheck FAIL 'PowerShell' ($PSVersionTable.PSEdition + ' ' + $powerShellVersion) 'Windows PowerShell 5.1 or PowerShell 7+' 'Run with Windows PowerShell 5.1 or install/use PowerShell 7.'
}

$signatureCmdlet = Get-Command -Name 'Get-AuthenticodeSignature' -CommandType Cmdlet -ErrorAction SilentlyContinue
$preferredSignatureHost = Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $preferredSignatureHost) {
    $preferredSignatureHost = Get-Command -Name 'powershell.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($null -ne $signatureCmdlet -and $null -ne $preferredSignatureHost) {
    $oldExecutable = [Environment]::GetEnvironmentVariable('P2P_PACKAGE_EXECUTABLE', 'Process')
    $oldModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('P2P_PACKAGE_EXECUTABLE', $PSCommandPath, 'Process')
        [Environment]::SetEnvironmentVariable('PSModulePath', $null, 'Process')
        $signatureProbe = '$signature = Get-AuthenticodeSignature -LiteralPath $env:P2P_PACKAGE_EXECUTABLE; if ($null -eq $signature) { exit 8 }; $signature.Status.ToString()'
        $signatureArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $signatureProbe)
        $signatureCapture = Invoke-P2PNativeCapture -Executable $preferredSignatureHost.Source -Arguments $signatureArguments
        $signatureOutput = @($signatureCapture.Output)
        $signatureExit = $signatureCapture.ExitCode
        $signatureStatus = [string]($signatureOutput | Select-Object -Last 1)
    }
    finally {
        [Environment]::SetEnvironmentVariable('P2P_PACKAGE_EXECUTABLE', $oldExecutable, 'Process')
        [Environment]::SetEnvironmentVariable('PSModulePath', $oldModulePath, 'Process')
    }
    if ($signatureExit -eq 0 -and -not [string]::IsNullOrWhiteSpace($signatureStatus)) {
        Write-DoctorCheck PASS 'Get-AuthenticodeSignature' ($preferredSignatureHost.Source + '; script status=' + $signatureStatus) 'signature inspection usable by the shared packager' 'none'
    }
    else {
        Write-DoctorCheck FAIL 'Get-AuthenticodeSignature' ($preferredSignatureHost.Source + '; invocation failed: ' + ($signatureOutput -join ' ')) 'signature inspection usable by the shared packager' 'Use a PowerShell host with Microsoft.PowerShell.Security and a working Get-AuthenticodeSignature cmdlet.'
    }
}
else {
    Write-DoctorCheck FAIL 'Get-AuthenticodeSignature' 'cmdlet or pwsh.exe/powershell.exe host not found' 'signature inspection usable by the shared packager' 'Use Windows PowerShell 5.1 or PowerShell 7 with Get-AuthenticodeSignature available.'
}

foreach ($relativePath in @('Cargo.toml', 'scripts/package-desktop.py', 'scripts/package-desktop-tests.py', 'scripts/verify-desktop-package.py')) {
    $absolutePath = Join-Path $RepoRoot $relativePath
    if (Test-Path -LiteralPath $absolutePath -PathType Leaf) {
        Write-DoctorCheck PASS ('repository file ' + $relativePath) $absolutePath 'file present' 'none'
    }
    else {
        Write-DoctorCheck FAIL ('repository file ' + $relativePath) 'missing' 'file present' "Restore $relativePath from the repository's main branch."
    }
}

if ($script:FailureCount -eq 0) {
    if ($script:WarningCount -eq 0) {
        Write-Host 'READY'
    }
    else {
        Write-Host 'READY WITH WARNINGS'
    }
    exit 0
}

Write-Host ('NOT READY (' + $script:FailureCount + ' required check(s) failed)')
exit 1
