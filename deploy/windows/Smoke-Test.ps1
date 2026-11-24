#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the programs of the Windows package: wafctl, then the gateway on spare ports with a temporary data folder,
    until its admin UI answers. Changes nothing on the machine.

.DESCRIPTION
    The release workflow runs it after hiding the .NET installation of the build machine (-HideDotNet), which is how
    it proves that the package needs no .NET runtime.

.PARAMETER Package
    The package folder (for example artifacts\windows\WafGateway-win-x64).

.PARAMETER HideDotNet
    Renames %ProgramFiles%\dotnet for the duration of the test and removes it from the PATH. For build machines only.

.PARAMETER TimeoutSeconds
    How long the gateway may take to start. Default: 120.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Package,
    [switch] $HideDotNet,
    [int] $TimeoutSeconds = 120
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$Package = (Resolve-Path -LiteralPath $Package).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ("waf-smoke-" + [guid]::NewGuid().ToString('N'))
$dotnet = Join-Path $env:ProgramFiles 'dotnet'
$hidden = "$dotnet.hidden"
$gateway = $null
$savedPath = $env:Path
$exitCode = 0

function Get-StatusCode([string] $Url) {
    try { return [int](Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5).StatusCode }
    catch [System.Net.WebException] {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}

try {
    if ($HideDotNet -and (Test-Path -LiteralPath $dotnet)) {
        # Build servers keep files in the folder open.
        & (Join-Path $dotnet 'dotnet.exe') build-server shutdown *> $null
        Get-Process -Name dotnet -ErrorAction SilentlyContinue | Stop-Process -Force
        Rename-Item -LiteralPath $dotnet -NewName (Split-Path -Leaf $hidden)
        Write-Host "Hid $dotnet."
    }
    $env:Path = (($env:Path -split ';') | Where-Object { $_ -and $_ -notlike '*\dotnet*' }) -join ';'
    Remove-Item Env:DOTNET_ROOT -ErrorAction SilentlyContinue
    if (Get-Command dotnet -ErrorAction SilentlyContinue) {
        Write-Host "Note: dotnet is still found ($((Get-Command dotnet).Source)); the test does not prove the package runs without it."
    } else {
        Write-Host 'No .NET found (no dotnet on the PATH).'
    }

    Write-Host '=== wafctl'
    & (Join-Path $Package 'wafctl.exe') --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "wafctl --help failed (exit code $LASTEXITCODE)." }
    Write-Host 'wafctl runs.'

    Write-Host '=== Gateway'
    New-Item -ItemType Directory -Path (Join-Path $work 'data'), (Join-Path $work 'config') -Force | Out-Null
    $env:DOTNET_ENVIRONMENT = 'Production'
    $env:Gateway__Storage__DataDirectory = Join-Path $work 'data'
    $env:Gateway__Storage__ConfigDirectory = Join-Path $work 'config'
    $env:Gateway__Endpoints__HttpPort = '18080'
    $env:Gateway__Endpoints__HttpsPort = '18443'
    $env:Gateway__Endpoints__AdminPort = '18900'
    $gateway = Start-Process -FilePath (Join-Path $Package 'WafGateway.exe') -WorkingDirectory $Package -PassThru `
        -RedirectStandardOutput (Join-Path $work 'gateway.log') -RedirectStandardError (Join-Path $work 'gateway.err')

    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-StatusCode 'http://127.0.0.1:18900/healthz') -ne 200) {
        if ($gateway.HasExited) { throw "The gateway stopped while starting (exit code $($gateway.ExitCode))." }
        if ($watch.Elapsed.TotalSeconds -gt $TimeoutSeconds) { throw "The admin UI did not answer within $TimeoutSeconds seconds." }
        Start-Sleep -Seconds 1
    }
    Write-Host "The admin UI answers after $([int]$watch.Elapsed.TotalSeconds) s."

    $code = Get-StatusCode 'http://127.0.0.1:18080/'
    if ($code -eq 0) { throw 'The public port 18080 does not answer.' }
    Write-Host "The public port answers (HTTP $code)."
    if (-not (Test-Path -LiteralPath (Join-Path $work 'data\config.db'))) { throw 'config.db was not created in the data folder.' }
    Write-Host 'config.db created.'
    Write-Host 'Smoke test passed.'
}
catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    foreach ($log in @('gateway.log', 'gateway.err')) {
        $file = Join-Path $work $log
        if (Test-Path -LiteralPath $file) { Get-Content -LiteralPath $file -Tail 50 | Write-Host }
    }
    $exitCode = 1
}
finally {
    if ($gateway -and -not $gateway.HasExited) { Stop-Process -Id $gateway.Id -Force; $gateway.WaitForExit() }
    $env:Path = $savedPath
    if ($HideDotNet -and (Test-Path -LiteralPath $hidden)) {
        Rename-Item -LiteralPath $hidden -NewName (Split-Path -Leaf $dotnet)
        Write-Host "Restored $dotnet."
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit $exitCode
