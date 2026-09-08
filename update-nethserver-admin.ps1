$ErrorActionPreference = "Stop"

$gateRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$skillDirectory = Join-Path $gateRoot ".agents\skills"
$skillUrl = if ($env:GATE_NETHSERVER_SKILL_URL) {
    $env:GATE_NETHSERVER_SKILL_URL
} else {
    "https://codeload.github.com/NethServer/agents/zip/refs/heads/main"
}
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("gate-skill-update-" + [guid]::NewGuid())

try {
    New-Item -ItemType Directory -Path $temporary | Out-Null
    $archive = Join-Path $temporary "agents.zip"
    Write-Host "Downloading nethserver-admin from NethServer/agents..."
    Invoke-WebRequest -UseBasicParsing -Uri $skillUrl -OutFile $archive
    Expand-Archive -LiteralPath $archive -DestinationPath $temporary
    $source = Join-Path $temporary "agents-main\skills\nethserver-admin"
    if (-not (Test-Path -LiteralPath (Join-Path $source "SKILL.md") -PathType Leaf)) {
        throw "Skill updater: downloaded bundle is invalid"
    }

    New-Item -ItemType Directory -Force -Path $skillDirectory | Out-Null
    $destination = Join-Path $skillDirectory "nethserver-admin"
    $previous = Join-Path $temporary "previous-nethserver-admin"
    if (Test-Path -LiteralPath $destination) {
        Move-Item -LiteralPath $destination -Destination $previous
    }
    try {
        Move-Item -LiteralPath $source -Destination $destination
    } catch {
        if (Test-Path -LiteralPath $previous) {
            Move-Item -LiteralPath $previous -Destination $destination
        }
        throw
    }
    Write-Host "Updated $destination"
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
