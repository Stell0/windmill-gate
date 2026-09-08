param(
    [string]$Version = $(if ($env:GATE_VERSION) { $env:GATE_VERSION } else { "latest" }),
    [string]$InstallDir = $(if ($env:GATE_INSTALL_DIR) { $env:GATE_INSTALL_DIR } else { "windmill-gate" })
)

$ErrorActionPreference = "Stop"
$repository = "stell0/windmill-gate"

if (Test-Path -LiteralPath $InstallDir) {
    throw "Gate installer: $InstallDir already exists"
}

$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($architecture) {
    "X64" { $gateArch = "amd64" }
    "Arm64" { $gateArch = "arm64" }
    default { throw "Gate installer: unsupported CPU architecture $architecture" }
}

if ($Version -eq "latest") {
    $releaseBase = "https://github.com/$repository/releases/latest/download"
} else {
    $releaseBase = "https://github.com/$repository/releases/download/$Version"
}
if ($env:GATE_RELEASE_BASE_URL) {
    $releaseBase = $env:GATE_RELEASE_BASE_URL.TrimEnd("/")
}
$archiveName = "windmill-gate_windows_$gateArch.zip"
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("windmill-gate-install-" + [guid]::NewGuid())

try {
    New-Item -ItemType Directory -Path $temporary | Out-Null
    $archivePath = Join-Path $temporary $archiveName
    $checksumsPath = Join-Path $temporary "checksums.txt"
    Write-Host "Downloading Gate $Version for windows/$gateArch..."
    Invoke-WebRequest -UseBasicParsing -Uri "$releaseBase/$archiveName" -OutFile $archivePath
    Invoke-WebRequest -UseBasicParsing -Uri "$releaseBase/checksums.txt" -OutFile $checksumsPath

    $checksumLine = Get-Content -LiteralPath $checksumsPath | Where-Object {
        $_ -match ("\s" + [regex]::Escape($archiveName) + "$")
    } | Select-Object -First 1
    if (-not $checksumLine) {
        throw "Gate installer: release checksum is missing"
    }
    $expected = ($checksumLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Gate installer: checksum verification failed"
    }

    $unpack = Join-Path $temporary "unpack"
    Expand-Archive -LiteralPath $archivePath -DestinationPath $unpack
    $bundle = Join-Path $unpack "windmill-gate"
    if (-not (Test-Path -LiteralPath (Join-Path $bundle "gate.exe") -PathType Leaf)) {
        throw "Gate installer: release archive is invalid"
    }
    $parent = Split-Path -Parent $InstallDir
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    Move-Item -LiteralPath $bundle -Destination $InstallDir

    try {
        & (Join-Path $InstallDir "update-nethserver-admin.ps1")
        Write-Host "NethServer admin skill installed."
    } catch {
        Write-Warning "Gate installed, but the NethServer admin skill could not be downloaded: $_"
        Write-Warning "Retry later with: .\$InstallDir\update-nethserver-admin.ps1"
    }
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`nGate is ready in $InstallDir"
Write-Host "Next:"
Write-Host "  Set-Location '$InstallDir'"
Write-Host "  .\gate.exe --bastion operator@bastion.example --agent codex-1"
