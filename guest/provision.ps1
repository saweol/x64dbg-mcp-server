<#
.SYNOPSIS
  Prepares a Windows analysis VM for x64dbg-vm-gateway (clean snapshot contract,
  docs/VM_ORCHESTRATION_PLAN.md section 5.7). Idempotent.

.DESCRIPTION
  Parameters come from a JSON file that the host copies into the guest. The file
  may contain secrets (guest password for auto-logon) and is deleted as soon as
  it has been read. Nothing secret is written to the log or the summary.

  JSON keys:
    x64dbg_root   e.g. "C:\\Users\\analyst\\Desktop\\x64dbg\\release" (contains x64\ and x32\)
    user          interactive account that runs the debuggers (e.g. "analyst")
    password      optional; required only when autologon = true
    autologon     bool, configure Winlogon auto-logon for `user`
    bind          plugin bind address written to mcp_config.json (e.g. "0.0.0.0")
    ports         { "x64": 9094, "x32": 9095 }
    job_root      e.g. "C:\\mcp\\jobs"
    tokens        optional { "x64": "...", "x32": "..." }; existing valid tokens are kept,
                  missing/corrupt ones are generated
    no_sleep      bool, disable standby/monitor timeouts

  Results:
    C:\mcp\provision.log            progress log (no secrets)
    C:\mcp\provision.result.json    summary (paths, task names, token lengths only)
#>
param(
    [string]$ParamsFile = 'C:\mcp\provision.json'
)

$ErrorActionPreference = 'Stop'
$McpDir = 'C:\mcp'
$LogFile = Join-Path $McpDir 'provision.log'
New-Item -ItemType Directory -Force -Path $McpDir | Out-Null

function Write-Log([string]$Message) {
    $line = '[{0}] {1}' -f (Get-Date -Format s), $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function New-Token {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

function Read-ExistingToken([string]$ConfigPath) {
    # Returns the token from an existing plugin config, or $null when the file is
    # missing, unreadable, zero-filled (seen in practice after a snapshot) or invalid.
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $null }
    try {
        $raw = [System.IO.File]::ReadAllText($ConfigPath)
        if ($raw.Trim([char]0).Trim().Length -eq 0) { return $null }
        $cfg = $raw | ConvertFrom-Json
        $tok = [string]$cfg.AuthToken
        if ($tok -match '^[A-Za-z0-9]{32,64}$') { return $tok }
    } catch { }
    return $null
}

try {
    Write-Log "provision start (params: $ParamsFile)"
    if (-not (Test-Path -LiteralPath $ParamsFile)) { throw "params file not found: $ParamsFile" }
    $p = Get-Content -Raw -LiteralPath $ParamsFile | ConvertFrom-Json
    Remove-Item -Force -LiteralPath $ParamsFile
    Write-Log 'params read and params file deleted'

    $root = [string]$p.x64dbg_root
    $user = [string]$p.user
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { throw "x64dbg_root not found: $root" }
    if (-not $user) { throw 'user is required' }
    $bind = if ($p.bind) { [string]$p.bind } else { '127.0.0.1' }
    $jobRoot = if ($p.job_root) { [string]$p.job_root } else { 'C:\mcp\jobs' }

    $result = [ordered]@{ x64dbg_root = $root; user = $user; bind = $bind; job_root = $jobRoot; backends = @{} }

    # 1. job root
    New-Item -ItemType Directory -Force -Path $jobRoot | Out-Null
    Write-Log "job root ready: $jobRoot"

    # 2. plugin configs + 3. scheduled tasks (one per architecture)
    $archs = @(
        @{ id = 'x64'; exe = 'x64dbg.exe'; task = 'MCP-x64dbg'; port = 9094 },
        @{ id = 'x32'; exe = 'x32dbg.exe'; task = 'MCP-x32dbg'; port = 9095 }
    )
    foreach ($a in $archs) {
        $dir = Join-Path $root $a.id
        $exe = Join-Path $dir $a.exe
        if (-not (Test-Path -LiteralPath $exe)) { Write-Log "skip $($a.id): $exe not found"; continue }
        $port = if ($p.ports -and $p.ports.($a.id)) { [int]$p.ports.($a.id) } else { $a.port }
        $cfgPath = Join-Path $dir 'mcp_config.json'

        $token = $null
        if ($p.tokens -and $p.tokens.($a.id)) { $token = [string]$p.tokens.($a.id) }
        if (-not $token) { $token = Read-ExistingToken $cfgPath }
        $generated = $false
        if (-not $token) { $token = New-Token; $generated = $true }

        $cfg = [ordered]@{ IpAddress = $bind; Port = $port; AutoStart = $true; AuthToken = $token }
        Write-Utf8NoBom $cfgPath ($cfg | ConvertTo-Json -Compress)
        Write-Log "config written: $cfgPath (bind=$bind port=$port token_generated=$generated)"

        $action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $dir
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $a.task -Action $action -Trigger $trigger -Principal $principal `
            -Settings $settings -Force | Out-Null
        Write-Log "scheduled task registered: $($a.task) -> $exe (Interactive, Highest, AtLogOn)"

        $result.backends[$a.id] = [ordered]@{
            exe = $exe; config = $cfgPath; port = $port; task = $a.task
            token_length = $token.Length; token_generated = $generated
        }
    }

    # 4. auto-logon (Winlogon registry; the password is stored by Windows, never logged here)
    if ($p.autologon) {
        if (-not $p.password) { throw 'autologon requested but no password supplied' }
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Set-ItemProperty -Path $wl -Name AutoAdminLogon -Value '1'
        Set-ItemProperty -Path $wl -Name DefaultUserName -Value $user
        Set-ItemProperty -Path $wl -Name DefaultDomainName -Value $env:COMPUTERNAME
        Set-ItemProperty -Path $wl -Name DefaultPassword -Value ([string]$p.password)
        Remove-ItemProperty -Path $wl -Name AutoLogonCount -ErrorAction SilentlyContinue
        Write-Log "auto-logon configured for $user"
        $result.autologon = $true
    }

    # 5. keep the session awake
    if ($p.no_sleep) {
        & powercfg.exe /change standby-timeout-ac 0 | Out-Null
        & powercfg.exe /change monitor-timeout-ac 0 | Out-Null
        & powercfg.exe /change hibernate-timeout-ac 0 | Out-Null
        Write-Log 'power timeouts disabled'
    }

    $result.status = 'ok'
    Write-Utf8NoBom (Join-Path $McpDir 'provision.result.json') ($result | ConvertTo-Json -Depth 5)
    Write-Log 'provision done'
    exit 0
} catch {
    Write-Log ("provision FAILED: " + $_.Exception.Message)
    Write-Utf8NoBom (Join-Path $McpDir 'provision.result.json') (@{ status = 'failed'; error = $_.Exception.Message } | ConvertTo-Json)
    if (Test-Path -LiteralPath $ParamsFile) { Remove-Item -Force -LiteralPath $ParamsFile -ErrorAction SilentlyContinue }
    exit 1
}
