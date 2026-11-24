#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs WAF Gateway as a Windows service (or removes it with -Uninstall).

.DESCRIPTION
    Copies the gateway to Program Files, creates the WafGateway service running as its own virtual account
    (NT SERVICE\WafGateway), restricts the data folder to that account, SYSTEM and Administrators, opens the
    public HTTP and HTTPS ports in Windows Firewall and starts the service. Running it again upgrades an
    existing installation; the data folder (configuration, accounts, logs) is kept.

    IIS: the installer reports IIS sites bound to the public ports, and any other program listening on them.
    It never changes IIS unless -MoveIisBindings is given. Then applicationHost.config is backed up first and
    the sites' bindings on those ports are moved to 127.0.0.1 (ports 8080 and 8443 by default), so they can be
    added to the gateway as routes.

    Use -WhatIf to see what would happen without changing anything.

.PARAMETER SourcePath
    Folder with the published gateway (WafGateway.exe, wafctl.exe). Default: the folder of this script.

.PARAMETER InstallPath
    Program folder. Default: %ProgramFiles%\WafGateway.

.PARAMETER DataPath
    Data folder (config.db, identity.db, events.db, keys, optional appsettings.json). Default: %ProgramData%\WafGateway.

.PARAMETER OpenAdminPort
    Also opens the remote admin port in Windows Firewall: the port of the registered remote admin URL
    (see "wafctl status"), or -RemoteAdminPort. The local admin port (8900) is never opened: it only listens on
    127.0.0.1 and ::1.

.PARAMETER RemoteAdminPort
    The remote admin port to open with -OpenAdminPort, when the admin URL is not registered yet.

.PARAMETER MoveIisBindings
    Moves IIS site bindings on the public ports to 127.0.0.1:IisHttpPort (http) and 127.0.0.1:IisHttpsPort
    (https), after backing up applicationHost.config and the HTTP.sys certificate bindings.

.PARAMETER IisHttpPort
    New port for IIS http bindings moved with -MoveIisBindings. Default: 8080.

.PARAMETER IisHttpsPort
    New port for IIS https bindings moved with -MoveIisBindings. Default: 8443.

.PARAMETER NoStart
    Installs (or upgrades) without starting the service.

.PARAMETER Uninstall
    Stops and removes the service, its firewall rules, the program folder and the PATH entry. The data folder
    is kept unless -RemoveData is given. IIS is never changed.

.PARAMETER RemoveData
    With -Uninstall: also deletes the data folder (configuration, accounts, request log, keys).

.EXAMPLE
    .\Install.ps1
    Installs the service, sets the data folder ACLs, opens ports 80 and 443 and starts the gateway.

.EXAMPLE
    .\Install.ps1 -MoveIisBindings
    Also moves IIS sites from ports 80 and 443 to 127.0.0.1:8080 and 127.0.0.1:8443 (backing up IIS first).

.EXAMPLE
    .\Install.ps1 -Uninstall
    Removes the service; keeps the data folder.
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [string] $SourcePath,

    [string] $InstallPath = (Join-Path $env:ProgramFiles 'WafGateway'),

    [string] $DataPath = (Join-Path $env:ProgramData 'WafGateway'),

    [Parameter(ParameterSetName = 'Install')]
    [switch] $OpenAdminPort,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 65535)]
    [int] $RemoteAdminPort,

    [Parameter(ParameterSetName = 'Install')]
    [switch] $MoveIisBindings,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 65535)]
    [int] $IisHttpPort = 8080,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 65535)]
    [int] $IisHttpsPort = 8443,

    [Parameter(ParameterSetName = 'Install')]
    [switch] $NoStart,

    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)]
    [switch] $Uninstall,

    [Parameter(ParameterSetName = 'Uninstall')]
    [switch] $RemoveData
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$ServiceName = 'WafGateway'
$ServiceAccount = "NT SERVICE\$ServiceName"
$DisplayName = 'WAF Gateway'
$FirewallGroup = 'WAF Gateway'
$GatewayExe = Join-Path $InstallPath 'WafGateway.exe'
$InetSrv = Join-Path $env:windir 'System32\inetsrv'

function Write-Step([string] $Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

function Write-Note([string] $Text) { Write-Host "    $Text" }

# ---------------------------------------------------------------------------------------------------------------
# Settings and ports
# ---------------------------------------------------------------------------------------------------------------

<# The effective Gateway:Endpoints:<Name>: the built-in appsettings.json, overridden by the one in the data folder. #>
function Get-EndpointSetting([string] $Name, [int] $Default) {
    $value = $Default
    foreach ($file in @((Join-Path $InstallPath 'appsettings.json'), (Join-Path $DataPath 'appsettings.json'))) {
        if (-not (Test-Path -LiteralPath $file)) { continue }
        try {
            $json = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Could not read $file ($($_.Exception.Message)); assuming $Name = $value."
            continue
        }
        $gateway = $json.PSObject.Properties['Gateway']
        if ($null -eq $gateway) { continue }
        $endpoints = $gateway.Value.PSObject.Properties['Endpoints']
        if ($null -eq $endpoints) { continue }
        $setting = $endpoints.Value.PSObject.Properties[$Name]
        if ($null -ne $setting -and $null -ne $setting.Value) { $value = [int] $setting.Value }
    }
    return $value
}

<# Programs listening on TCP <Ports>, with a readable name (PID 4 is HTTP.sys: IIS or another HTTP.sys user). #>
function Get-PortListener([int[]] $Ports) {
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $Ports -contains $_.LocalPort })
    foreach ($listener in $listeners) {
        $name = if ($listener.OwningProcess -eq 4) {
            'HTTP.sys (IIS or another HTTP.sys user)'
        }
        else {
            $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            if ($null -ne $process) { "$($process.ProcessName) (process $($listener.OwningProcess))" } else { "process $($listener.OwningProcess)" }
        }
        [pscustomobject] @{ Port = $listener.LocalPort; Address = $listener.LocalAddress; Program = $name }
    }
}

# ---------------------------------------------------------------------------------------------------------------
# IIS
# ---------------------------------------------------------------------------------------------------------------

function Test-IisInstalled { return (Test-Path -LiteralPath (Join-Path $InetSrv 'config\applicationHost.config')) }

<# IIS's configuration API: in inetsrv when the IIS management tools are installed, otherwise only in the GAC. #>
function New-ServerManager {
    if (-not ('Microsoft.Web.Administration.ServerManager' -as [type])) {
        $candidates = @(Join-Path $InetSrv 'Microsoft.Web.Administration.dll') +
            @(Get-ChildItem -Path (Join-Path $env:windir 'assembly\GAC_MSIL\Microsoft.Web.Administration') -Recurse -Filter 'Microsoft.Web.Administration.dll' -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending | ForEach-Object { $_.FullName })
        $dll = @($candidates | Where-Object { Test-Path -LiteralPath $_ })
        if ($dll.Count -eq 0) { throw 'IIS is installed, but its configuration API (Microsoft.Web.Administration) was not found.' }
        Add-Type -Path $dll[0]
    }
    return New-Object Microsoft.Web.Administration.ServerManager
}

<# IIS site bindings (http and https) on <Ports>. #>
function Get-IisBinding([int[]] $Ports) {
    if (-not (Test-IisInstalled)) { return @() }
    $manager = New-ServerManager
    try {
        foreach ($site in $manager.Sites) {
            $state = 'Unknown'
            try { $state = [string] $site.State } catch { $state = 'Unknown' }
            foreach ($binding in $site.Bindings) {
                if ($binding.Protocol -notin @('http', 'https')) { continue }
                if ($binding.BindingInformation -notmatch '^(?<ip>.*):(?<port>\d+):(?<host>[^:]*)$') { continue }
                $port = [int] $Matches['port']
                if ($Ports -notcontains $port) { continue }
                [pscustomobject] @{
                    Site     = $site.Name
                    State    = $state
                    Protocol = $binding.Protocol
                    Binding  = $binding.BindingInformation
                    Address  = $Matches['ip']
                    Port     = $port
                    HostName = $Matches['host']
                }
            }
        }
    }
    finally {
        $manager.Dispose()
    }
}

<# Copies applicationHost.config, the HTTP.sys certificate bindings and an IIS configuration backup; returns the folder. #>
function Backup-IisConfiguration {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $folder = Join-Path $DataPath "backups\iis-$stamp"
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $original = Join-Path $InetSrv 'config\applicationHost.config'
    Copy-Item -LiteralPath $original -Destination $folder
    if ((Get-FileHash -LiteralPath $original).Hash -ne (Get-FileHash -LiteralPath (Join-Path $folder 'applicationHost.config')).Hash) {
        throw "The copy of applicationHost.config in $folder does not match the original; IIS was not changed."
    }
    & netsh.exe http show sslcert | Out-File -FilePath (Join-Path $folder 'http-sslcert.txt') -Encoding utf8

    # Also an IIS configuration backup (restorable with appcmd), when IIS can make one; the copy above is what counts.
    $appcmd = Join-Path $InetSrv 'appcmd.exe'
    $backupName = "WafGateway-$stamp"
    $restore = "copy applicationHost.config from this folder back to $InetSrv\config (stop IIS first: iisreset /stop, then iisreset /start)."
    if (Test-Path -LiteralPath $appcmd) {
        $output = & $appcmd add backup $backupName 2>&1
        if ($LASTEXITCODE -eq 0) {
            $restore = "$appcmd restore backup `"$backupName`"`r`nor $restore"
        }
        else {
            Write-Warning "IIS could not make its own configuration backup ($output); the copy of applicationHost.config in $folder is the backup."
            $backupName = $null
        }
    }
    @"
Backup of the IIS configuration made by the WAF Gateway installer before moving site bindings ($stamp).

To undo the move:
  $restore
The HTTP.sys certificate bindings at that time are in http-sslcert.txt.
"@ | Out-File -FilePath (Join-Path $folder 'README.txt') -Encoding utf8
    return [pscustomobject] @{ Folder = $folder; Name = $backupName }
}

<# Moves the given IIS bindings to 127.0.0.1 on the new ports (certificates and SSL flags kept). #>
function Move-IisBinding([object[]] $Bindings) {
    $manager = New-ServerManager
    try {
        $moves = @()
        foreach ($item in $Bindings) {
            $site = $manager.Sites[$item.Site]
            $binding = @($site.Bindings | Where-Object { $_.Protocol -eq $item.Protocol -and $_.BindingInformation -eq $item.Binding })[0]
            $port = if ($item.Protocol -eq 'https') { $IisHttpsPort } else { $IisHttpPort }
            $target = "127.0.0.1:${port}:$($item.HostName)"
            foreach ($other in $manager.Sites) {
                foreach ($existing in $other.Bindings) {
                    if ($existing.BindingInformation -eq $target) {
                        throw "IIS site '$($other.Name)' already uses $target; choose other ports with -IisHttpPort and -IisHttpsPort."
                    }
                }
            }
            $moves += [pscustomobject] @{ Site = $site; Binding = $binding; Target = $target; Item = $item }
        }

        foreach ($move in $moves) {
            $old = $move.Binding
            if ($move.Item.Protocol -eq 'https') {
                $hash = $old.CertificateHash
                $store = $old.CertificateStoreName
                $flags = $old.SslFlags
                $move.Site.Bindings.Remove($old)
                if ($null -ne $hash -and $hash.Length -gt 0) {
                    $move.Site.Bindings.Add($move.Target, $hash, $store, $flags) | Out-Null
                }
                else {
                    $new = $move.Site.Bindings.Add($move.Target, 'https')
                    $new.SetAttributeValue('sslFlags', [int] $flags)
                }
            }
            else {
                $move.Site.Bindings.Remove($old)
                $move.Site.Bindings.Add($move.Target, 'http') | Out-Null
            }
            Write-Note "$($move.Item.Site): $($move.Item.Protocol) $($move.Item.Binding) -> $($move.Target)"
        }
        $manager.CommitChanges()
    }
    finally {
        $manager.Dispose()
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Service, folders, firewall
# ---------------------------------------------------------------------------------------------------------------

function Get-GatewayService { return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue }

function Stop-GatewayService {
    $service = Get-GatewayService
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop the service')) {
            Stop-Service -Name $ServiceName -Force
            (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
        }
    }
}

function Invoke-Sc([string[]] $Arguments) {
    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sc.exe $($Arguments -join ' ') failed (exit code $LASTEXITCODE): $output" }
}

<# Data folder: only SYSTEM, Administrators (full control) and the service account (modify); nothing inherited. #>
function Set-DataFolderAccess([string] $Path) {
    $inherit = [System.Security.AccessControl.InheritanceFlags] 'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $system = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
    $administrators = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $service = (New-Object System.Security.Principal.NTAccount $ServiceAccount).Translate([System.Security.Principal.SecurityIdentifier])

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $inherit, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($service, 'Modify', $inherit, $none, $allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl

    # Files from an earlier installation or a manual run get the folder's permissions too.
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
        & icacls.exe (Join-Path $Path '*') /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls could not reset the permissions in $Path (exit code $LASTEXITCODE)." }
    }
}

<# Windows Firewall can be off (another firewall, or a container): then no rules are made, with a warning. #>
function Test-FirewallRunning {
    $firewall = Get-Service -Name 'MpsSvc' -ErrorAction SilentlyContinue
    return ($null -ne $firewall -and $firewall.Status -eq 'Running')
}

function Add-FirewallRule([string] $Name, [int] $Port) {
    New-NetFirewallRule -DisplayName "$DisplayName ($Name)" -Group $FirewallGroup -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $Port -Program $GatewayExe -Profile Any | Out-Null
    Write-Note "Inbound TCP $Port allowed for WafGateway.exe ($Name)."
}

<# The port of the registered remote admin URL (from "wafctl status"); 0 when none is registered or it has no port of its own. #>
function Get-RemoteAdminPort {
    $wafctl = Join-Path $InstallPath 'wafctl.exe'
    $status = & $wafctl status --data-dir $DataPath 2>&1
    if ($LASTEXITCODE -ne 0) { throw "wafctl status failed (exit code $LASTEXITCODE): $status" }
    foreach ($line in $status) {
        if ("$line" -match '^Remote admin:\s+(?<url>\S+)') {
            if ($Matches['url'] -eq 'off') { return 0 }
            $url = [Uri] $Matches['url']
            if ($url.IsDefaultPort) { return 0 }
            return $url.Port
        }
    }
    return 0
}

function Add-ToMachinePath([string] $Folder) {
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($path -split ';' | Where-Object { $_ -ne '' })
    if ($parts -notcontains $Folder) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $Folder) -join ';'), 'Machine')
        Write-Note "$Folder added to PATH (for wafctl; open a new terminal)."
    }
}

function Remove-FromMachinePath([string] $Folder) {
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($path -split ';' | Where-Object { $_ -ne '' -and $_ -ne $Folder })
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'Machine')
}

function Wait-GatewayHealthy([int] $AdminPort) {
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $service = Get-GatewayService
        if ($null -eq $service -or $service.Status -eq 'Stopped') { return $false }
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:$AdminPort/healthz" -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) { return $true }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    return $false
}

# ---------------------------------------------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------------------------------------------

if ($Uninstall) {
    Write-Step 'Removing WAF Gateway'
    Stop-GatewayService
    if ($null -ne (Get-GatewayService) -and $PSCmdlet.ShouldProcess($ServiceName, 'Remove the service')) {
        Invoke-Sc @('delete', $ServiceName)
        Write-Note 'Service removed.'
    }
    $rules = @(if (Test-FirewallRunning) { Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue })
    if ($rules.Count -gt 0 -and $PSCmdlet.ShouldProcess($FirewallGroup, 'Remove the firewall rules')) {
        $rules | Remove-NetFirewallRule
        Write-Note "$($rules.Count) firewall rule(s) removed."
    }
    if ($PSCmdlet.ShouldProcess($InstallPath, 'Remove the program folder and its PATH entry')) {
        Remove-FromMachinePath $InstallPath
        if (Test-Path -LiteralPath $InstallPath) { Remove-Item -LiteralPath $InstallPath -Recurse -Force }
        Write-Note "$InstallPath removed."
    }
    if ($RemoveData) {
        if ((Test-Path -LiteralPath $DataPath) -and $PSCmdlet.ShouldProcess($DataPath, 'Delete the data folder (configuration, accounts, logs, keys)')) {
            Remove-Item -LiteralPath $DataPath -Recurse -Force
            Write-Note "$DataPath deleted."
        }
    }
    elseif (Test-Path -LiteralPath $DataPath) {
        Write-Note "The data folder $DataPath is kept (configuration, accounts, request log). Delete it with -RemoveData."
        $backups = Join-Path $DataPath 'backups'
        if (Test-Path -LiteralPath $backups) {
            Write-Note "IIS was not changed. Backups of the IIS configuration made by the installer are in $backups."
        }
    }
    Write-Step 'WAF Gateway is removed.'
    return
}

# ---------------------------------------------------------------------------------------------------------------
# Install or upgrade
# ---------------------------------------------------------------------------------------------------------------

if (-not $SourcePath) { $SourcePath = $PSScriptRoot }
$SourcePath = (Resolve-Path -LiteralPath $SourcePath).Path
foreach ($file in @('WafGateway.exe', 'wafctl.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $SourcePath $file))) {
        throw "$file is not in $SourcePath. Run the installer from the extracted package, or pass -SourcePath."
    }
}

$existing = Get-GatewayService
$moved = $false
Write-Step $(if ($null -ne $existing) { "Upgrading WAF Gateway in $InstallPath" } else { "Installing WAF Gateway in $InstallPath" })

# Stop an existing installation first, so its own listeners do not count as "port in use".
Stop-GatewayService

# 1. Program files.
$sameFolder = [string]::Equals($SourcePath.TrimEnd('\'), [IO.Path]::GetFullPath($InstallPath).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
if (-not $sameFolder -and $PSCmdlet.ShouldProcess($InstallPath, "Copy the program files from $SourcePath")) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    & robocopy.exe $SourcePath $InstallPath /MIR /NFL /NDL /NJH /NJS /NP /R:2 /W:2 | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Copying the program files to $InstallPath failed (robocopy exit code $LASTEXITCODE)." }
    Write-Note "Program files copied to $InstallPath."
}

# 2. The service, as its own virtual account, restarted automatically after a failure.
if ($PSCmdlet.ShouldProcess($ServiceName, 'Create or update the Windows service')) {
    $binaryPath = "`"$GatewayExe`""
    if ($null -eq $existing) {
        New-Service -Name $ServiceName -BinaryPathName $binaryPath -DisplayName $DisplayName -StartupType Automatic `
            -Description 'Reverse proxy with a web application firewall. Admin UI: http://localhost:8900' | Out-Null
    }
    else {
        Invoke-Sc @('config', $ServiceName, 'binPath=', $binaryPath, 'start=', 'auto')
    }
    Invoke-Sc @('sidtype', $ServiceName, 'unrestricted')
    Invoke-Sc @('config', $ServiceName, 'obj=', $ServiceAccount)
    Invoke-Sc @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/10000/restart/60000')
    Write-Note "Service '$ServiceName' runs as $ServiceAccount and restarts after a failure."
}

# 3. Data folder: only the service account, SYSTEM and Administrators.
if ($PSCmdlet.ShouldProcess($DataPath, "Create the data folder and limit access to $ServiceAccount, SYSTEM and Administrators")) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    Set-DataFolderAccess $DataPath
    Write-Note "Data folder $DataPath is accessible only to $ServiceAccount, SYSTEM and Administrators."
}

# 4. Who else uses the public ports: IIS sites and other programs.
$httpPort = Get-EndpointSetting 'HttpPort' 80
$httpsPort = Get-EndpointSetting 'HttpsPort' 443
$adminPort = Get-EndpointSetting 'AdminPort' 8900
$publicPorts = @($httpPort, $httpsPort)

$iisBindings = @(Get-IisBinding $publicPorts)
if ($iisBindings.Count -gt 0) {
    Write-Step "IIS has sites on the public ports ($($publicPorts -join ' and '))"
    $iisBindings | Format-Table Site, State, Protocol, Binding -AutoSize | Out-String -Width 200 | Write-Host
    if ($MoveIisBindings) {
        if ($PSCmdlet.ShouldProcess('IIS', "Back up applicationHost.config and move these bindings to 127.0.0.1:$IisHttpPort (http) and 127.0.0.1:$IisHttpsPort (https)")) {
            $backup = Backup-IisConfiguration
            Write-Note "IIS configuration backed up to $($backup.Folder)$(if ($backup.Name) { " (and as IIS backup '$($backup.Name)')" })."
            Move-IisBinding -Bindings $iisBindings
            $moved = $true
            Write-Note 'Add these sites to the gateway as routes (Routes -> Add a route), for example:'
            foreach ($item in $iisBindings) {
                $port = if ($item.Protocol -eq 'https') { $IisHttpsPort } else { $IisHttpPort }
                $hostName = if ($item.HostName) { $item.HostName } else { '(any host name)' }
                Write-Note "  $hostName -> $($item.Protocol)://127.0.0.1:$port"
            }
        }
    }
    else {
        Write-Note 'The installer does not change IIS unless you ask: run it again with -MoveIisBindings to move these'
        Write-Note "bindings to 127.0.0.1:$IisHttpPort and 127.0.0.1:$IisHttpsPort (applicationHost.config is backed up first),"
        Write-Note 'or change them yourself in IIS Manager.'
    }
}
elseif (Test-IisInstalled) {
    Write-Note "IIS is installed; no IIS site uses port $($publicPorts -join ' or ')."
}

# 5. Firewall: the public ports, and the remote admin port only when asked.
$firewall = Test-FirewallRunning
if (-not $firewall) {
    Write-Warning "Windows Firewall is not running, so no firewall rules were added. Allow inbound TCP $($publicPorts -join ' and ') in the firewall you use."
}
elseif ($PSCmdlet.ShouldProcess($FirewallGroup, "Allow inbound TCP $($publicPorts -join ' and ') for WafGateway.exe")) {
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Add-FirewallRule 'HTTP-In' $httpPort
    Add-FirewallRule 'HTTPS-In' $httpsPort
}
if ($OpenAdminPort) {
    $port = if ($RemoteAdminPort -gt 0) { $RemoteAdminPort } else { Get-RemoteAdminPort }
    if ($port -eq 0) {
        Write-Warning ('-OpenAdminPort: no remote admin port to open. Register the remote admin URL with a port of its own ' +
            '(Remote access page, e.g. https://admin.example.com:8443) or pass -RemoteAdminPort. An admin URL without a port uses 443, which is open already.')
    }
    elseif ($port -eq $adminPort) {
        throw "-OpenAdminPort: port $port is the local admin port, which must never be reachable from the network."
    }
    elseif (-not $firewall) {
        Write-Warning "Windows Firewall is not running; allow inbound TCP $port (remote admin) in the firewall you use."
    }
    elseif ($PSCmdlet.ShouldProcess($FirewallGroup, "Allow inbound TCP $port (remote admin)")) {
        Add-FirewallRule 'remote admin' $port
    }
}
else {
    Write-Note 'The remote admin port is not opened (use -OpenAdminPort).'
}

# 6. wafctl on the PATH.
if ($PSCmdlet.ShouldProcess('PATH', "Add $InstallPath")) { Add-ToMachinePath $InstallPath }

# 7. Start, unless something else holds the public ports. IIS needs a moment to apply moved bindings.
$busy = @(Get-PortListener $publicPorts)
if ($moved) {
    $deadline = (Get-Date).AddSeconds(30)
    while ($busy.Count -gt 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 1
        $busy = @(Get-PortListener $publicPorts)
    }
}
if ($NoStart) {
    Write-Step "Installed; not started (-NoStart). Start it with: Start-Service $ServiceName"
}
elseif ($busy.Count -gt 0) {
    Write-Step 'Installed, but not started: the public ports are in use'
    $busy | Format-Table Port, Address, Program -AutoSize | Out-String -Width 200 | Write-Host
    Write-Note "Free the ports (see the IIS note above), then start the gateway with: Start-Service $ServiceName"
}
elseif ($PSCmdlet.ShouldProcess($ServiceName, 'Start the service')) {
    Start-Service -Name $ServiceName
    if (Wait-GatewayHealthy $adminPort) {
        Write-Step 'WAF Gateway is running'
    }
    else {
        Write-Warning "The service did not become healthy within 60 seconds. See Event Viewer (Windows Logs > Application, source $ServiceName), or run: wafctl status"
    }
}

Write-Note "Admin UI (on this machine only): http://localhost:$adminPort - the first visit creates the admin account."
Write-Note "Data folder: $DataPath    Recovery tool: wafctl (as Administrator)"
