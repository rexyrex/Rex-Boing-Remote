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
#
# The download is checked against the release's SHA256SUMS. Unlike
# install.sh, this does not check that file's signature.
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
    if (Test-Path $Agent) { & $Agent uninstall; return }
    # The agent's file is gone, but its keys or its scheduled task may not
    # be: download the agent (checked as for an install) to remove them.
    Write-Host "The agent's file is missing; downloading it to remove anything it left behind."
} elseif (-not $Key) {
    throw "Missing -Key. Copy the full command from Rex Boing Remote > Add Server."
}

# An x64 PowerShell emulated on ARM64 Windows sees AMD64 in
# PROCESSOR_ARCHITECTURE; PROCESSOR_ARCHITEW6432 names the machine's own.
$machine = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$arch = if ($machine -eq "ARM64") { "arm64" } else { "amd64" }
$asset = "rex-boing-agent-windows-$arch.exe"
$base = if ($Version -eq "latest") { "https://github.com/$Repo/releases/latest/download" } else { "https://github.com/$Repo/releases/download/$Version" }

$tmp = Join-Path $env:TEMP ("rbr-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading the Rex Boing Remote agent ($asset)..."
    # Windows PowerShell on an older .NET offers only TLS 1.0 by default,
    # which GitHub refuses: add TLS 1.2. Where .NET leaves the choice to
    # Windows (SystemDefault, 0), leave it, so TLS 1.3 stays available.
    $protocols = [int][Net.ServicePointManager]::SecurityProtocol
    $tls12 = [int][Net.SecurityProtocolType]::Tls12
    if ($protocols -ne 0 -and ($protocols -band $tls12) -eq 0) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]($protocols -bor $tls12)
    }
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp "rex-boing-agent.exe")
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS")

    $line = Get-Content (Join-Path $tmp "SHA256SUMS") | Where-Object { $_ -match " $([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $line) { throw "No checksum for $asset." }
    $expected = ($line -split "\s+")[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp "rex-boing-agent.exe")).Hash.ToLower()
    if ($expected -ne $actual) { throw "The download's checksum doesn't match. Nothing was installed." }

    $download = Join-Path $tmp "rex-boing-agent.exe"
    if ($Uninstall) {
        # It finds the keys and the task from this user's profile, not from
        # where it runs.
        & $download uninstall
        return
    }
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
