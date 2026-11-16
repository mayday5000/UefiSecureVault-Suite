# UefiSecureVault-Suite — build_win32.ps1
# Windows PowerShell 5.1. Probes the host, installs a compiler only when none
# is present, and writes each .obj and .exe under .\win32\build. Executables are
# also copied to .\workspace for the WinPE injection step.
#
# Usage:
#   .\build_win32.ps1
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if ($args.Count -ne 0) {
    Write-Host "build_win32.ps1 takes no arguments."
    exit 1
}

$Pass = 0
$Fail = 0
function Report([string]$State, [string]$Name, [string]$Detail) {
    if ($State -eq "ok") {
        Write-Host ("  ok    " + $Name + " " + $Detail)
        $script:Pass++
    } else {
        Write-Host ("  miss  " + $Name + " " + $Detail)
        $script:Fail++
    }
}

function Has-Command([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

$Sources = @(
    "win32\VerifyRuntimeBoundaries.cpp",
    "win32\AuditMeasuredBootLog.cpp",
    "win32\LowLevelBootTools.cpp",
    "win32\ParseSmBios.cpp",
    "win32\WinVerifyTrust.cpp",
    "win32\DumpNtfsVolume.cpp"
)

Write-Host "========================================================================="
Write-Host "UEFI Secure Vault Win32 probe, revision ps51e"
Write-Host "========================================================================="
Write-Host ("Repository: " + $Root)
Write-Host "Host commands"

$Cl = Get-Command cl.exe -ErrorAction SilentlyContinue
$Gpp = Get-Command g++.exe -ErrorAction SilentlyContinue
$VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if ($Cl) { Report "ok" "cl.exe" $Cl.Source } else { Report "miss" "cl.exe" "" }
if ($Gpp) { Report "ok" "g++.exe" $Gpp.Source } else { Report "miss" "g++.exe" "" }
if (Test-Path $VsWhere) { Report "ok" "vswhere.exe" $VsWhere } else { Report "miss" "vswhere.exe" "" }
if (Has-Command "winget") { Report "ok" "winget" "" } else { Report "miss" "winget" "" }

Write-Host "Suite sources"
foreach ($src in $Sources) {
    if (Test-Path (Join-Path $Root $src)) { Report "ok" $src "" } else { Report "miss" $src "" }
}
Write-Host ("Probe summary: " + $Pass + " present, " + $Fail + " missing")

foreach ($src in $Sources) {
    if (-not (Test-Path (Join-Path $Root $src))) {
        Write-Host ("Suite source missing: " + $src)
        exit 1
    }
}

function Find-VcVars {
    if (-not (Test-Path $VsWhere)) { return $null }
    $install = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if (-not $install) { return $null }
    $vcvars = Join-Path $install "VC\Auxiliary\Build\vcvars64.bat"
    if (Test-Path $vcvars) { return $vcvars }
    return $null
}

$VcVars = Find-VcVars
if ($VcVars) { Report "ok" "vcvars64.bat" $VcVars }

$Compiler = $null
if ($Cl -or $VcVars) { $Compiler = "msvc" }
elseif ($Gpp) { $Compiler = "g++" }

if (-not $Compiler) {
    Write-Host "Toolchain incomplete. Installing Visual Studio 2022 Build Tools."
    if (-not (Has-Command "winget")) {
        Write-Host "winget is not available, and neither cl.exe nor g++.exe is on PATH."
        exit 1
    }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Package install needs an elevated PowerShell."
        exit 1
    }
    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-package-agreements --accept-source-agreements --override "--wait --quiet --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    $VcVars = Find-VcVars
    if (-not $VcVars) {
        Write-Host "Build Tools installed, but vcvars64.bat was not found."
        exit 1
    }
    $Compiler = "msvc"
    Write-Host "Host toolchain is present."
} else {
    Write-Host ("Compiler already present: " + $Compiler)
}

$BuildDir = Join-Path $Root "win32\build"
$WorkspaceDir = Join-Path $Root "workspace"
$StaleRootBuild = Join-Path $Root "build"
if (Test-Path (Join-Path $StaleRootBuild "compile_one.bat")) {
    Remove-Item -Recurse -Force $StaleRootBuild
}
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $WorkspaceDir | Out-Null

function Compile-Msvc([string]$Src, [string]$Name, [string[]]$Libs) {
    $srcPath = Join-Path $Root $Src
    $objPath = Join-Path $BuildDir ($Name + ".obj")
    $exePath = Join-Path $BuildDir ($Name + ".exe")
    $libArgs = ($Libs | ForEach-Object { $_ }) -join " "
    Write-Host ("Compiling " + $Name)
    $cmd = 'call "' + $VcVars + '" >nul & cl /nologo /EHsc /O2 /W3 "' + $srcPath + '" /Fo"' + $objPath + '" /Fe"' + $exePath + '" /link ' + $libArgs
    cmd /c $cmd
    if ($LASTEXITCODE -ne 0) { throw ("cl failed on " + $Src) }
    if (-not (Test-Path $exePath)) { throw ("cl produced no executable for " + $Src) }
    Copy-Item -Force $exePath (Join-Path $WorkspaceDir ($Name + ".exe"))
    Remove-Item -ErrorAction SilentlyContinue (Join-Path $Root ($Name + ".obj"))
    Write-Host ("  obj " + $objPath)
    Write-Host ("  exe " + $exePath)
}

function Compile-Gpp([string]$Src, [string]$Name, [string[]]$Libs) {
    $srcPath = Join-Path $Root $Src
    $objPath = Join-Path $BuildDir ($Name + ".obj")
    $exePath = Join-Path $BuildDir ($Name + ".exe")
    Write-Host ("Compiling " + $Name)
    & g++.exe -O2 -Wall -c $srcPath -o $objPath
    if ($LASTEXITCODE -ne 0) { throw ("g++ compile failed on " + $Src) }
    & g++.exe -O2 -static $objPath -o $exePath @Libs
    if ($LASTEXITCODE -ne 0) { throw ("g++ link failed on " + $Src) }
    Copy-Item -Force $exePath (Join-Path $WorkspaceDir ($Name + ".exe"))
    Write-Host ("  obj " + $objPath)
    Write-Host ("  exe " + $exePath)
}

$Jobs = @(
    @{ Src = "win32\VerifyRuntimeBoundaries.cpp"; Name = "VerifyRuntimeBoundaries"; Msvc = @("advapi32.lib"); Gpp = @("-ladvapi32") },
    @{ Src = "win32\AuditMeasuredBootLog.cpp";    Name = "AuditMeasuredBootLog";    Msvc = @("tbs.lib", "crypt32.lib"); Gpp = @("-ltbs", "-lcrypt32") },
    @{ Src = "win32\LowLevelBootTools.cpp";       Name = "LowLevelBootTools";       Msvc = @("wintrust.lib", "crypt32.lib", "ole32.lib", "advapi32.lib"); Gpp = @("-lwintrust", "-lcrypt32", "-lole32", "-ladvapi32") },
    @{ Src = "win32\ParseSmBios.cpp";             Name = "ParseSmBios";             Msvc = @(); Gpp = @() },
    @{ Src = "win32\WinVerifyTrust.cpp";          Name = "WinVerifyTrust";          Msvc = @("wintrust.lib", "crypt32.lib"); Gpp = @("-lwintrust", "-lcrypt32") },
    @{ Src = "win32\DumpNtfsVolume.cpp";          Name = "DumpNtfsVolume";          Msvc = @(); Gpp = @() }
)

foreach ($job in $Jobs) {
    if ($Compiler -eq "msvc") {
        Compile-Msvc $job.Src $job.Name $job.Msvc
    } else {
        Compile-Gpp $job.Src $job.Name $job.Gpp
    }
}

Write-Host "========================================================================="
Write-Host "Objects and executables:"
foreach ($job in $Jobs) {
    Write-Host ("  " + (Join-Path $BuildDir ($job.Name + ".obj")))
    Write-Host ("  " + (Join-Path $BuildDir ($job.Name + ".exe")))
}
Write-Host "Executables also copied to workspace for the WinPE injection step."
Write-Host "Run them from an elevated prompt. Firmware reads need SE_SYSTEM_ENVIRONMENT_NAME."
Write-Host "========================================================================="
