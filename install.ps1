# Rex Boing Remote — agent installer for Windows.
#
# Installs the agent for the user who runs it, authorises your Mac's key to
# start it, and prints a pairing code to paste into Rex Boing Remote. The app
# shows this exact command, key included:
#
#   & ([scriptblock]::Create((irm https://github.com/rexyrex/Rex-Boing-Remote/releases/latest/download/install.ps1))) -Key 'ssh-ed25519 AAAA… rex-boing-remote:Your-Mac'
#
# Needs OpenSSH Server (Settings > System > Optional features). Run it in
# PowerShell as the user Rex Boing Remote should log in as. Administrators'
# keys live in a protected file, so for an administrator account run it in an
# elevated PowerShell.
param(
    [string]$Key = "",
    [string]$Label = "",
    [string]$Version = "latest",
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "rexyrex/Rex-Boing-Remote"
$InstallDir = Join-Path $env:LOCALAPPDATA "RexBoingRemote"
$Agent = Join-Path $InstallDir "rex-boing-agent.exe"

if ($Uninstall) {
    if (Test-Path $Agent) { & $Agent uninstall } else { Write-Host "The agent isn't installed for $env:USERNAME." }
    return
}
if (-not $Key) { throw "Missing -Key. Copy the full command from Rex Boing Remote > Add Server." }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$asset = "rex-boing-agent-windows-$arch.exe"
$base = if ($Version -eq "latest") { "https://github.com/$Repo/releases/latest/download" } else { "https://github.com/$Repo/releases/download/$Version" }

$tmp = Join-Path $env:TEMP ("rbr-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading the Rex Boing Remote agent ($asset)..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp "rex-boing-agent.exe")
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS")

    $line = Get-Content (Join-Path $tmp "SHA256SUMS") | Where-Object { $_ -match " $([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $line) { throw "No checksum for $asset." }
    $expected = ($line -split "\s+")[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp "rex-boing-agent.exe")).Hash.ToLower()
    if ($expected -ne $actual) { throw "The download's checksum doesn't match. Nothing was installed." }

    $download = Join-Path $tmp "rex-boing-agent.exe"
    $arguments = @("install", "--key", $Key)
    if ($Label) { $arguments += @("--label", $Label) }
    $result = & $download @arguments
    Write-Host $result
    if ($LASTEXITCODE -ne 0) { throw "Install failed." }

    $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $sshd) {
        Write-Host ""
        Write-Host "OpenSSH Server isn't installed. In an elevated PowerShell:"
        Write-Host "  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
        Write-Host "  Start-Service sshd; Set-Service sshd -StartupType Automatic"
    } elseif ($sshd.Status -ne "Running") {
        Write-Host ""
        Write-Host "OpenSSH Server is stopped. In an elevated PowerShell: Start-Service sshd; Set-Service sshd -StartupType Automatic"
    }

    $code = & $Agent pair-code
    Write-Host ""
    Write-Host "Installed for $env:USERNAME. Paste this into Rex Boing Remote > Add Server > Set it up from the server:"
    Write-Host ""
    Write-Host "  $code"
    Write-Host ""
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
