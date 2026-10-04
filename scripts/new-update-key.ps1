# Generate the minisign key pair that signs desktop updates (SHA256SUMS.minisig).
# The key pair goes to ..\..\signing (next to the repositories, never inside one);
# back it up offline. Installed apps trust only the public key they were built
# with, so replacing the key means users must install the next version by hand.
#
#   .\scripts\new-update-key.ps1                      # just generate
#   .\scripts\new-update-key.ps1 -SetGitHubSecrets    # also set the repository secrets
#                                                     # NPW_UPDATE_PRIVATE_KEY / NPW_UPDATE_PUBKEY (gh CLI)
param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\..\signing'),
    [switch]$SetGitHubSecrets
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
if ($OutDir.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) { throw "keep the key outside the repository ($OutDir)" }

$keyFile = Join-Path $OutDir 'nyapassword-update.key'
$pubFile = Join-Path $OutDir 'nyapassword-update.pub'
if ((Test-Path -LiteralPath $keyFile) -and (Test-Path -LiteralPath $pubFile)) {
    Write-Host "using the existing key pair in $OutDir"
} else {
    Push-Location $repo
    try {
        $ErrorActionPreference = 'Continue'
        & cargo run --quiet --release -p npw-update-sign -- keygen $OutDir
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($code -ne 0) { throw "key generation failed (exit $code)" }
    } finally { Pop-Location }
}

$pub = (Get-Content -LiteralPath $pubFile)[1].Trim()
Write-Host ''
Write-Host "public key (NPW_UPDATE_PUBKEY): $pub" -ForegroundColor Green
Write-Host "secret key file: $keyFile  -- back it up offline; it must never enter a repository" -ForegroundColor Yellow

if ($SetGitHubSecrets) {
    Push-Location $repo
    try {
        Get-Content -LiteralPath $keyFile -Raw | & gh secret set NPW_UPDATE_PRIVATE_KEY
        if ($LASTEXITCODE -ne 0) { throw 'gh secret set NPW_UPDATE_PRIVATE_KEY failed' }
        & gh secret set NPW_UPDATE_PUBKEY --body $pub
        if ($LASTEXITCODE -ne 0) { throw 'gh secret set NPW_UPDATE_PUBKEY failed' }
        Write-Host 'GitHub secrets NPW_UPDATE_PRIVATE_KEY and NPW_UPDATE_PUBKEY are set' -ForegroundColor Green
    } finally { Pop-Location }
} else {
    Write-Host 'to store it in the repository secrets, run again with -SetGitHubSecrets (reuses this key pair)'
}
