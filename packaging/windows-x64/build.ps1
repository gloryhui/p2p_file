#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Output,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$Target = 'x86_64-pc-windows-msvc'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$HelperPath = Join-Path $PSScriptRoot 'desktop-build-env.ps1'

if ($Help) {
    Write-Host 'Usage: build.ps1 [-Output PATH]'
    Write-Host 'Builds a native x64 Windows GUI candidate outside the repository.'
    return
}

function Invoke-NativeChecked {
    param([Parameter(Mandatory = $true)][string]$Executable, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & $Executable @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw ("Command failed with exit code {0}: {1} {2}" -f $exitCode, $Executable, ($Arguments -join ' '))
    }
}

function Resolve-BuildOutput {
    param([string]$RequestedPath, [string]$CommitPrefix)

    if ([string]::IsNullOrWhiteSpace($RequestedPath)) {
        $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ', [Globalization.CultureInfo]::InvariantCulture)
        $parent = Join-Path $env:USERPROFILE 'p2p-file-builds'
        $resolved = [IO.Path]::GetFullPath((Join-Path $parent ('windows-x64-' + $stamp + '-' + $CommitPrefix)))
        $suffix = 1
        while (Test-Path -LiteralPath $resolved) {
            $resolved = [IO.Path]::GetFullPath((Join-Path $parent ('windows-x64-' + $stamp + '-' + $CommitPrefix + '-' + [string]$suffix)))
            $suffix++
        }
    }
    else {
        $expanded = [Environment]::ExpandEnvironmentVariables($RequestedPath)
        if ($expanded -eq '~') {
            $expanded = $env:USERPROFILE
        }
        elseif ($expanded.StartsWith('~\') -or $expanded.StartsWith('~/')) {
            $expanded = Join-Path $env:USERPROFILE $expanded.Substring(2)
        }
        $resolved = [IO.Path]::GetFullPath($expanded)
    }

    $probePath = $resolved
    $missingSegments = @()
    while (-not (Test-Path -LiteralPath $probePath)) {
        $parentPath = [IO.Path]::GetDirectoryName($probePath)
        if ([string]::IsNullOrWhiteSpace($parentPath) -or [string]::Equals($parentPath, $probePath, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $missingSegments = @([IO.Path]::GetFileName($probePath)) + $missingSegments
        $probePath = $parentPath
    }
    if (Test-Path -LiteralPath $probePath) {
        if (-not (Test-Path -LiteralPath $probePath -PathType Container)) {
            throw "An existing output path parent is not a directory: $probePath"
        }
        $canonicalProbe = (Resolve-Path -LiteralPath $probePath -ErrorAction Stop).ProviderPath
        foreach ($segment in $missingSegments) {
            $canonicalProbe = Join-Path $canonicalProbe $segment
        }
        $resolved = [IO.Path]::GetFullPath($canonicalProbe)
    }

    $repository = $RepoRoot.TrimEnd([char[]]@('\', '/'))
    $repositoryPrefix = $repository + [IO.Path]::DirectorySeparatorChar
    if ([string]::Equals($resolved, $repository, [StringComparison]::OrdinalIgnoreCase) -or
        $resolved.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Output must be outside the repository: $resolved"
    }
    if (Test-Path -LiteralPath $resolved) {
        if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
            throw "Output path exists and is not a directory: $resolved"
        }
        $existingItem = Get-ChildItem -LiteralPath $resolved -Force | Select-Object -First 1
        if ($null -ne $existingItem) {
            throw "Output directory is not empty; candidate evidence will not be overwritten: $resolved"
        }
    }
    return $resolved
}

try {
    if (-not (Test-Path -LiteralPath $HelperPath -PathType Leaf)) {
        throw "Windows environment helper is missing: $HelperPath"
    }
    . $HelperPath

    $doctorPath = Join-Path $PSScriptRoot 'doctor.ps1'
    if ([string]$PSVersionTable.PSEdition -eq 'Core') {
        $doctorHost = Join-Path $PSHOME 'pwsh.exe'
    }
    else {
        $doctorHost = Join-Path $PSHOME 'powershell.exe'
    }
    if (-not (Test-Path -LiteralPath $doctorHost -PathType Leaf)) {
        throw "The current PowerShell host executable was not found: $doctorHost"
    }
    & $doctorHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $doctorPath
    $doctorExit = $LASTEXITCODE
    if ($doctorExit -ne 0) {
        throw "doctor.ps1 reported NOT READY (exit $doctorExit); Cargo was not started."
    }

    $vsWhere = Find-P2PVsWhere
    if ([string]::IsNullOrWhiteSpace($vsWhere)) {
        throw 'vswhere.exe was not found; install Visual Studio 2022 / Build Tools with the Desktop development with C++ workload.'
    }
    $vsInstance = Initialize-P2PVisualStudioEnvironment -VsWherePath $vsWhere
    $vsEnvironment = Test-P2PVisualStudioEnvironment
    if ($vsEnvironment.TargetArchitecture -ne 'x64' -or $vsEnvironment.HostArchitecture -ne 'x64') {
        throw 'VsDevCmd did not initialize an x64-host/x64-target MSVC environment.'
    }
    Write-Host ('Initialized Visual Studio ' + $vsInstance.InstallationVersion + ' x64 environment via ' + $vsInstance.VsDevCmdPath)
    Write-Host ('cl.exe: ' + $vsEnvironment.ClPath)
    Write-Host ('link.exe: ' + $vsEnvironment.LinkPath)
    Write-Host ('Windows SDK: ' + $vsEnvironment.WindowsSdkDirectory + ' ' + $vsEnvironment.WindowsSdkVersion)

    $git = Get-Command -Name 'git.exe' -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $statusLines = @(& $git.Source '-C' $RepoRoot 'status' '--porcelain' '--untracked-files=all')
    $gitStatus = $LASTEXITCODE
    if ($gitStatus -ne 0) {
        throw "Unable to inspect Git worktree state (git exit $gitStatus)."
    }
    if ($statusLines.Count -gt 0) {
        throw 'Complete packaging requires a clean Git worktree; commit or stash local changes first.'
    }
    $headLines = @(& $git.Source '-C' $RepoRoot 'rev-parse' 'HEAD')
    if ($LASTEXITCODE -ne 0 -or $headLines.Count -eq 0) {
        throw 'Unable to read the current Git build SHA.'
    }
    $buildSha = [string]$headLines[0]
    $python = Find-P2PPython
    if ($null -eq $python) {
        throw 'Python 3.11+ with tomllib was not found. Install Python 3.12 from python.org and disable Microsoft Store aliases.'
    }
    $outputPath = Resolve-BuildOutput -RequestedPath $Output -CommitPrefix $buildSha.Substring(0, 12)

    $cargo = Get-Command -Name 'cargo.exe' -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $packageTests = Join-Path $RepoRoot 'scripts\package-desktop-tests.py'
    $packageScript = Join-Path $RepoRoot 'scripts\package-desktop.py'
    $verifyScript = Join-Path $RepoRoot 'scripts\verify-desktop-package.py'
    $binaryPath = Join-Path $RepoRoot ('target\' + $Target + '\release\p2p-desktop.exe')

    Push-Location $RepoRoot
    try {
        Invoke-NativeChecked -Executable $python.Path $packageTests
        Invoke-NativeChecked -Executable $cargo.Source 'build' '--locked' '--release' '--features' 'gui' '--bin' 'p2p-desktop' '--target' $Target
        Invoke-NativeChecked -Executable $python.Path $packageScript '--binary' $binaryPath '--target' $Target '--output' $outputPath
        $candidatePath = Join-Path $outputPath 'candidate.json'
        Invoke-NativeChecked -Executable $python.Path $verifyScript $candidatePath
    }
    finally {
        Pop-Location
    }

    $candidate = Get-Content -LiteralPath $candidatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    $archivePath = Join-Path $outputPath ([string]$candidate.archive)
    $packageName = [IO.Path]::GetFileNameWithoutExtension([string]$candidate.archive)
    $packageRoot = Join-Path $outputPath $packageName
    $executableRelative = ([string]$candidate.executable).Replace('/', [IO.Path]::DirectorySeparatorChar)
    $packagedExecutable = Join-Path $packageRoot $executableRelative
    $inspectionPath = Join-Path $packageRoot 'native-inspection.json'
    $inspection = Get-Content -LiteralPath $inspectionPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $authenticodeStatus = [string]$inspection.authenticode
    if ($authenticodeStatus -ne 'NotSigned') {
        throw "Expected an unsigned Windows candidate; actual Authenticode state was '$authenticodeStatus'."
    }

    Write-Host ('build SHA: ' + [string]$candidate.build_sha)
    Write-Host ('target: ' + [string]$candidate.target)
    Write-Host ('artifact path: ' + $archivePath)
    Write-Host ('archive SHA256: ' + [string]$candidate.archive_sha256)
    Write-Host ('executable path: ' + $packagedExecutable)
    Write-Host ('Authenticode status: ' + $authenticodeStatus + ' (unsigned)')
    exit 0
}
catch {
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
