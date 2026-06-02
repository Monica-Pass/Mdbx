param(
    [string]$Configuration = "debug",
    [string]$OutDir = "",
    [string]$RuntimeOutDir = "",
    [string]$RustupToolchain = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$workspace = Split-Path -Parent $PSScriptRoot
$configurationName = if ($Configuration.Equals("release", [System.StringComparison]::OrdinalIgnoreCase)) { "release" } else { "debug" }

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $workspace "artifacts\csharp\Monica.Mdbx.Ffi"
}

if ([string]::IsNullOrWhiteSpace($RuntimeOutDir)) {
    $RuntimeOutDir = Join-Path $OutDir "runtimes"
}

$configPath = Join-Path $workspace "crates\mdbx-ffi\uniffi.toml"
$targetDir = Join-Path $workspace "target\$configurationName"
$libraryName = if ($IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    "mdbx_ffi.dll"
} elseif ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)) {
    "libmdbx_ffi.dylib"
} else {
    "libmdbx_ffi.so"
}
$libraryPath = Join-Path $targetDir $libraryName

if (-not $SkipBuild) {
    $buildArgs = @("build", "-p", "mdbx-ffi")
    if ($configurationName -eq "release") {
        $buildArgs += "--release"
    }

    Push-Location $workspace
    try {
        if ([string]::IsNullOrWhiteSpace($RustupToolchain)) {
            & cargo @buildArgs
        } else {
            & rustup run $RustupToolchain cargo @buildArgs
        }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $libraryPath)) {
    throw "Native library was not found at '$libraryPath'. Build mdbx-ffi first or pass the matching -Configuration."
}

$bindgen = Get-Command "uniffi-bindgen-cs" -ErrorAction SilentlyContinue
if ($null -eq $bindgen) {
    throw "uniffi-bindgen-cs was not found on PATH. Install the generator with: cargo install uniffi-bindgen-cs --git https://github.com/NordSecurity/uniffi-bindgen-cs --tag v0.10.0+v0.29.4"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

& $bindgen.Source --library $libraryPath --out-dir $OutDir --config $configPath

New-Item -ItemType Directory -Force -Path $RuntimeOutDir | Out-Null
Copy-Item -Path $libraryPath -Destination (Join-Path $RuntimeOutDir $libraryName) -Force

Write-Host "Generated C# bindings in $OutDir"
Write-Host "Copied native library to $RuntimeOutDir"
