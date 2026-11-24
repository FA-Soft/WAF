#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    End-to-end check of Install.ps1 on this machine: install, upgrade, firewall, data folder ACLs, IIS handling and
    uninstall. Changes the machine while it runs and removes everything again at the end (including the data folder).
    Meant for CI runners, containers and test machines, not for a machine where WAF Gateway is in use.

.PARAMETER Package
    The package folder made by Build-Package.ps1 (with Install.ps1, WafGateway.exe and wafctl.exe).

.PARAMETER WithIis
    IIS is installed and a site is bound to port 80 (as on a default IIS install): checks that the installer leaves
    IIS alone without -MoveIisBindings, and moves the binding (with a backup) with it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Package,

    [switch] $WithIis
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
trap { Write-Host "ERROR: $_" -ForegroundColor Red; Write-Host $_.ScriptStackTrace; exit 1 }

$installer = Join-Path (Resolve-Path -LiteralPath $Package).Path 'Install.ps1'
$installPath = Join-Path $env:ProgramFiles 'WafGateway'
$dataPath = Join-Path $env:ProgramData 'WafGateway'
$applicationHost = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
$script:failures = 0
$firewall = (Get-Service -Name 'MpsSvc' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running') -ne $null

function Test-That([bool] $Condition, [string] $Description) {
    if ($Condition) {
        Write-Host "  [ok]   $Description" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] $Description" -ForegroundColor Red
        $script:failures++
    }
}

function Invoke-Installer([hashtable] $Arguments) {
    Write-Host "--- Install.ps1 $(($Arguments.Keys | ForEach-Object { "-$_" }) -join ' ')" -ForegroundColor Yellow
    & $installer @Arguments
}

function Get-StatusCode([string] $Url) {
    try {
        return [int] (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10).StatusCode
    }
    catch [System.Net.WebException] {
        if ($null -ne $_.Exception.Response) { return [int] $_.Exception.Response.StatusCode }
        return 0
    }
}

function Get-FileHashText([string] $Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

function Get-IisBindingText([string] $Site) {
    if (-not ('Microsoft.Web.Administration.ServerManager' -as [type])) {
        $dll = @(Get-ChildItem -Path (Join-Path $env:windir 'System32\inetsrv'), (Join-Path $env:windir 'assembly\GAC_MSIL\Microsoft.Web.Administration') `
            -Recurse -Filter 'Microsoft.Web.Administration.dll' -ErrorAction SilentlyContinue)[0]
        Add-Type -Path $dll.FullName
    }
    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try { return @($manager.Sites[$Site].Bindings | ForEach-Object { "$($_.Protocol)/$($_.BindingInformation)" }) }
    finally { $manager.Dispose() }
}

function Test-Running {
    $service = Get-CimInstance Win32_Service -Filter "Name='WafGateway'"
    Test-That ($null -ne $service -and $service.State -eq 'Running') 'the service is running'
    Test-That ($null -ne $service -and $service.StartName -eq 'NT SERVICE\WafGateway') 'it runs as NT SERVICE\WafGateway'
    Test-That ($null -ne $service -and $service.StartMode -eq 'Auto') 'it starts automatically'
    Test-That ((Get-StatusCode 'http://127.0.0.1:8900/healthz') -eq 200) 'the admin UI answers on 127.0.0.1:8900'
    Test-That ((Get-StatusCode 'http://127.0.0.1/') -ne 0) 'the gateway answers on port 80'
}

if ($WithIis) {
    Write-Host '=== IIS: reported, never changed without -MoveIisBindings' -ForegroundColor Cyan
    $before = Get-FileHashText $applicationHost
    Test-That ((Get-IisBindingText 'Default Web Site') -contains 'http/*:80:') 'IIS serves Default Web Site on *:80'

    Invoke-Installer @{}
    Test-That ((Get-FileHashText $applicationHost) -eq $before) 'applicationHost.config is unchanged'
    Test-That ((Get-Service WafGateway).Status -eq 'Stopped') 'the service is installed but not started (port 80 is in use)'
    Test-That ((Get-IisBindingText 'Default Web Site') -contains 'http/*:80:') 'IIS still serves Default Web Site on *:80'

    Write-Host '=== IIS: -MoveIisBindings' -ForegroundColor Cyan
    Invoke-Installer @{ MoveIisBindings = $true }
    $backups = @(Get-ChildItem -LiteralPath (Join-Path $dataPath 'backups') -Directory -Filter 'iis-*' -ErrorAction SilentlyContinue)
    Test-That ($backups.Count -eq 1) 'a backup folder was made'
    Test-That ($backups.Count -eq 1 -and (Get-FileHashText (Join-Path $backups[0].FullName 'applicationHost.config')) -eq $before) 'it holds the original applicationHost.config'
    Test-That ((Get-IisBindingText 'Default Web Site') -contains 'http/127.0.0.1:8080:') 'Default Web Site moved to 127.0.0.1:8080'
    Test-That ((Get-IisBindingText 'Default Web Site') -notcontains 'http/*:80:') 'it no longer uses port 80'
    Test-That ((Get-StatusCode 'http://127.0.0.1:8080/') -eq 200) 'IIS answers on 127.0.0.1:8080'
    $moved = Get-FileHashText $applicationHost
}
else {
    Write-Host '=== Install' -ForegroundColor Cyan
    Invoke-Installer @{}
}

Test-Running
Test-That (Test-Path -LiteralPath (Join-Path $installPath 'wafctl.exe')) "the program files are in $installPath"
Test-That (([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') -contains $installPath) 'the program folder is on the PATH'
Test-That (Test-Path -LiteralPath (Join-Path $dataPath 'config.db')) 'config.db was created in the data folder'
Test-That (Test-Path -LiteralPath (Join-Path $dataPath 'keys')) 'the data protection keys are in the data folder'

$acl = Get-Acl -LiteralPath $dataPath
$identities = @($acl.Access | ForEach-Object { $_.IdentityReference.Value })
Test-That ($acl.AreAccessRulesProtected) 'the data folder does not inherit permissions'
Test-That ($identities -contains 'NT SERVICE\WafGateway') 'the service account has access to the data folder'
Test-That (@($identities | Where-Object { $_ -match 'Users|Everyone|Authenticated' }).Count -eq 0) 'users have no access to the data folder'
$dbAcl = @((Get-Acl -LiteralPath (Join-Path $dataPath 'config.db')).Access | ForEach-Object { $_.IdentityReference.Value })
Test-That (@($dbAcl | Where-Object { $_ -match 'Users|Everyone|Authenticated' }).Count -eq 0) 'users have no access to config.db'

if ($firewall) {
    $rules = @(Get-NetFirewallRule -Group 'WAF Gateway' -ErrorAction SilentlyContinue)
    $ports = @($rules | Get-NetFirewallPortFilter | ForEach-Object { [string] $_.LocalPort } | Sort-Object)
    Test-That (($ports -join ',') -eq '443,80') 'the firewall allows ports 80 and 443 (and nothing else)'
    Test-That (@($rules | Get-NetFirewallApplicationFilter | Where-Object { $_.Program -like '*WafGateway.exe' }).Count -eq 2) 'the rules apply to WafGateway.exe only'
}
else {
    Write-Host '  [skip] Windows Firewall is not running here (a container): firewall checks skipped' -ForegroundColor DarkYellow
}

$status = & (Join-Path $installPath 'wafctl.exe') status 2>&1
Test-That ($LASTEXITCODE -eq 0 -and ($status -join "`n") -match 'Remote admin:\s+off') 'wafctl status works (remote admin off)'

if ($firewall) {
    Write-Host '=== -OpenAdminPort' -ForegroundColor Cyan
    Invoke-Installer @{ OpenAdminPort = $true } 3>&1 | Out-Null
    Test-That (@(Get-NetFirewallRule -Group 'WAF Gateway').Count -eq 2) 'without a registered admin URL no extra port is opened'
    Invoke-Installer @{ OpenAdminPort = $true; RemoteAdminPort = 9443 }
    $ports = @(Get-NetFirewallRule -Group 'WAF Gateway' | Get-NetFirewallPortFilter | ForEach-Object { [string] $_.LocalPort } | Sort-Object)
    Test-That (($ports -join ',') -eq '443,80,9443') 'with -RemoteAdminPort 9443 that port is opened too'
}
$refused = $false
try { Invoke-Installer @{ OpenAdminPort = $true; RemoteAdminPort = 8900 } } catch { $refused = $true }
Test-That $refused 'the local admin port 8900 is never opened'

Write-Host '=== Upgrade (run again)' -ForegroundColor Cyan
$configBefore = (Get-Item -LiteralPath (Join-Path $dataPath 'config.db')).Length
Invoke-Installer @{}
Test-Running
Test-That ((Get-Item -LiteralPath (Join-Path $dataPath 'config.db')).Length -ge $configBefore) 'the configuration is kept'
if ($firewall) {
    Test-That (@(Get-NetFirewallRule -Group 'WAF Gateway').Count -eq 2) 'the firewall rules are recreated (remote admin port closed again)'
}

Write-Host '=== Uninstall' -ForegroundColor Cyan
Invoke-Installer @{ Uninstall = $true }
Test-That ($null -eq (Get-Service WafGateway -ErrorAction SilentlyContinue)) 'the service is removed'
if ($firewall) {
    Test-That (@(Get-NetFirewallRule -Group 'WAF Gateway' -ErrorAction SilentlyContinue).Count -eq 0) 'the firewall rules are removed'
}
Test-That (-not (Test-Path -LiteralPath $installPath)) 'the program folder is removed'
Test-That (Test-Path -LiteralPath (Join-Path $dataPath 'config.db')) 'the data folder is kept'
if ($WithIis) {
    Test-That ((Get-FileHashText $applicationHost) -eq $moved) 'uninstalling does not change IIS'
}

Invoke-Installer @{ Uninstall = $true; RemoveData = $true }
Test-That (-not (Test-Path -LiteralPath $dataPath)) 'with -RemoveData the data folder is deleted'

if ($script:failures -gt 0) {
    Write-Host "$($script:failures) check(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host 'All checks passed.' -ForegroundColor Green
