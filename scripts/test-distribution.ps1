$ErrorActionPreference = "Stop"

$gateRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("windmill-gate-windows-distribution-test-" + [guid]::NewGuid())
$downloads = Join-Path $temporary "downloads"
$archiveRoot = Join-Path $temporary "archive"
$bundle = Join-Path $archiveRoot "windmill-gate"
$skillRoot = Join-Path $temporary "agents-main\skills\nethserver-admin"
$installDirectory = Join-Path $temporary "installed"
$archiveName = "windmill-gate_windows_amd64.zip"

$previousInstallDirectory = $env:GATE_INSTALL_DIR
$previousReleaseBase = $env:GATE_RELEASE_BASE_URL
$previousSkillUrl = $env:GATE_NETHSERVER_SKILL_URL
$previousTestDownloads = $env:GATE_TEST_DOWNLOADS

function Restore-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )

    if ($null -eq $Value) {
        Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    } else {
        Set-Item -LiteralPath "Env:$Name" -Value $Value
    }
}

function Invoke-WebRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [switch]$UseBasicParsing
    )

    $fileName = [System.IO.Path]::GetFileName(([uri]$Uri).AbsolutePath)
    $source = Join-Path $env:GATE_TEST_DOWNLOADS $fileName
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Windows distribution test: unexpected download $Uri"
    }
    Copy-Item -LiteralPath $source -Destination $OutFile
}

try {
    New-Item -ItemType Directory -Path $downloads, $bundle, $skillRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $bundle "gate.exe") -Value "test gate binary" -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $bundle "gate-sh.exe") -Value "test gate client" -Encoding ASCII
    Copy-Item -LiteralPath (Join-Path $gateRoot "update-nethserver-admin.ps1") -Destination $bundle
    Set-Content -LiteralPath (Join-Path $skillRoot "SKILL.md") -Value "# Test skill" -Encoding ASCII

    $archivePath = Join-Path $downloads $archiveName
    Compress-Archive -LiteralPath $bundle -DestinationPath $archivePath
    Compress-Archive -LiteralPath (Join-Path $temporary "agents-main") -DestinationPath (Join-Path $downloads "agents.zip")
    $checksum = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    Set-Content -LiteralPath (Join-Path $downloads "checksums.txt") -Value "$checksum  $archiveName" -Encoding ASCII

    $env:GATE_INSTALL_DIR = $installDirectory
    $env:GATE_RELEASE_BASE_URL = "https://gate-test.invalid"
    $env:GATE_NETHSERVER_SKILL_URL = "https://gate-test.invalid/agents.zip"
    $env:GATE_TEST_DOWNLOADS = $downloads

    $installer = Get-Content -LiteralPath (Join-Path $gateRoot "install.ps1") -Raw
    Invoke-Expression $installer

    foreach ($expected in @(
        "gate.exe",
        "gate-sh.exe",
        ".agents\skills\nethserver-admin\SKILL.md"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $installDirectory $expected) -PathType Leaf)) {
            throw "Windows distribution test: missing installed file $expected"
        }
    }

    Write-Host "PASS: Windows distribution installer"
} finally {
    Restore-EnvironmentVariable -Name "GATE_INSTALL_DIR" -Value $previousInstallDirectory
    Restore-EnvironmentVariable -Name "GATE_RELEASE_BASE_URL" -Value $previousReleaseBase
    Restore-EnvironmentVariable -Name "GATE_NETHSERVER_SKILL_URL" -Value $previousSkillUrl
    Restore-EnvironmentVariable -Name "GATE_TEST_DOWNLOADS" -Value $previousTestDownloads
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
