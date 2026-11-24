#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the Windows package: the gateway and wafctl (self-contained, win-x64) with Install.ps1, as a folder and a zip.

.PARAMETER Output
    Folder for the package. Default: artifacts\windows in the repository.

.PARAMETER Runtime
    Runtime identifier. Default: win-x64.

.PARAMETER Configuration
    Build configuration. Default: Release.

.EXAMPLE
    .\deploy\windows\Build-Package.ps1
    Creates artifacts\windows\WafGateway-win-x64\ (run Install.ps1 in it as Administrator) and WafGateway-win-x64.zip.
#>
[CmdletBinding()]
param(
    [string] $Output,
    [string] $Runtime = 'win-x64',
    [string] $Configuration = 'Release'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Output) { $Output = Join-Path $repository 'artifacts\windows' }
$Output = [IO.Path]::GetFullPath($Output)
$package = Join-Path $Output "WafGateway-$Runtime"
if (Test-Path -LiteralPath $package) { Remove-Item -LiteralPath $package -Recurse -Force }
New-Item -ItemType Directory -Path $package -Force | Out-Null

foreach ($project in @('Waf.Host', 'Waf.Cli')) {
    Write-Host "==> Publishing $project ($Runtime)" -ForegroundColor Cyan
    & dotnet publish (Join-Path $repository "src\$project\$project.csproj") -c $Configuration -r $Runtime --self-contained `
        -p:PublishSingleFile=true -o $package --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish $project failed (exit code $LASTEXITCODE)." }
}

Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install.ps1') -Destination $package
# Not used by the service: debug symbols, Development settings and IIS hosting files.
Get-ChildItem -LiteralPath $package -Filter '*.pdb' | Remove-Item -Force
foreach ($file in @('appsettings.Development.json', 'web.config', 'aspnetcorev2_inprocess.dll')) {
    $path = Join-Path $package $file
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}

$zip = "$package.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $package '*') -DestinationPath $zip
Write-Host "==> Package: $package" -ForegroundColor Cyan
Write-Host "    Zip:     $zip"
