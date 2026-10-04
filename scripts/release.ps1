# Make a desktop release: set the version (VERSION, src-tauri/Cargo.toml,
# package.json, src-tauri/tauri.conf.json), pin the common commit the build
# uses (COMMON_REF), commit and tag v<version>. Pushing the tag makes GitHub
# Actions build the installers for Windows / macOS / Linux and publish them.
#
#   .\scripts\release.ps1 0.1.1           # then: git push origin HEAD v0.1.1
#   .\scripts\release.ps1 0.2.0-beta.1 -Push
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Version,
    [switch]$Push
)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $repo '..\common\scripts\release-lib.ps1')
Publish-NpwVersion -Repo $repo -Product 'NyaPassword Desktop' `
    -Tomls @('src-tauri/Cargo.toml') `
    -Jsons @('package.json', 'src-tauri/tauri.conf.json') `
    -Version $Version -Push:$Push
