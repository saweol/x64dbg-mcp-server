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
    password      optional; required only when autologon = true (and not dry_run:
                  the host does not send it for a dry run)
    autologon     bool, configure Winlogon auto-logon for `user`
    bind          plugin bind address written to mcp_config.json (e.g. "0.0.0.0")
    allowed_clients  optional list of IPv4 addresses / CIDR ranges; when non-empty the
                  config also gets AllowExternal = true and AllowedClients, which plugin
                  v1.10+ requires for a non-loopback bind (older plugins ignore both)
    ports         { "x64": 9094, "x32": 9095 }
    job_root      e.g. "C:\\mcp\\jobs"; created and made writable (Modify) for `user`
    tokens        optional { "x64": "...", "x32": "..." }; existing valid tokens are kept,
                  missing/corrupt ones are generated
    no_sleep      bool, disable standby/monitor timeouts
    dry_run       bool, only report the planned actions (log + result "actions");
                  nothing is changed except that the params file is still deleted
                  and the log/result files are written. Same as the -DryRun switch.

  mcp_config.json is merged: IpAddress, Port, AutoStart, AuthToken (and
  AllowExternal / AllowedClients when allowed_clients is given) are written
  first, every other key of an existing valid config is kept as it was.

  x64dbg settings: [Engine] DisableDatabaseCompression=1 is written into the
  debugger's ini file next to its exe (x64dbg.ini / x32dbg.ini), creating the
  file, section or key as needed and keeping every other line, so databases
  saved to x64dbg's default location are plain JSON (the gateway's
  ida_export_annotations cannot read LZ4-compressed ones).

  Results:
    C:\mcp\provision.log            progress log (no secrets), including the plugin
                                    build found in each plugins folder
    C:\mcp\provision.result.json    summary (paths, task names, token lengths and
                                    plugin file info only)

  The gateway runs this script through x64dbg_vm_gateway/provision.py, which
  ships a byte-identical copy as x64dbg_vm_gateway/data/guest/provision.ps1.
  Keep this file ASCII-only: Windows PowerShell 5.1 reads BOM-less scripts in
  the ANSI code page.
#>
param(
    [string]$ParamsFile = 'C:\mcp\provision.json',
    [switch]$DryRun
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

function Read-ConfigObject([string]$ConfigPath) {
    # The top-level keys of an existing plugin config as an ordered dictionary, or an
    # empty one when the file is missing, zero-filled, corrupt or not a JSON object.
    $out = [ordered]@{}
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { return $out }
    try {
        $raw = [System.IO.File]::ReadAllText($ConfigPath)
        if ($raw.Trim([char]0).Trim().Length -eq 0) { return $out }
        $obj = $raw | ConvertFrom-Json
        if ($null -ne $obj) {
            foreach ($prop in @($obj.PSObject.Properties)) {
                if ($prop.MemberType -eq 'NoteProperty') { $out[$prop.Name] = $prop.Value }
            }
        }
    } catch { }
    return $out
}

function Set-IniValue([string]$Path, [string]$Section, [string]$Key, [string]$Value) {
    # Sets Key=Value in [Section] of an INI file: creates the file, the section or the key
    # when missing, replaces the key's line in place when present (section and key are
    # compared case-insensitively) and keeps every other line as it was, a UTF-8 BOM
    # included. Returns $false when the file already had exactly that line.
    $lines = New-Object System.Collections.Generic.List[string]
    $bom = $false
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $raw = [System.IO.File]::ReadAllBytes($Path)
        $bom = ($raw.Length -ge 3) -and ($raw[0] -eq 0xEF) -and ($raw[1] -eq 0xBB) -and ($raw[2] -eq 0xBF)
        foreach ($l in [System.IO.File]::ReadAllLines($Path)) { $lines.Add($l) }
    }
    $header = '[' + $Section + ']'
    $wanted = $Key + '=' + $Value
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -ieq $header) { $start = $i; break }
    }
    if ($start -lt 0) {
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1].Trim() -ne '') { $lines.Add('') }
        $lines.Add($header)
        $lines.Add($wanted)
    } else {
        $end = $lines.Count
        for ($i = $start + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim().StartsWith('[')) { $end = $i; break }
        }
        $found = -1
        for ($i = $start + 1; $i -lt $end; $i++) {
            $t = $lines[$i].Trim()
            $eq = $t.IndexOf('=')
            if ($eq -gt 0 -and $t.Substring(0, $eq).Trim() -ieq $Key) { $found = $i; break }
        }
        if ($found -ge 0) {
            if ($lines[$found] -ceq $wanted) { return $false }
            $lines[$found] = $wanted
        } else {
            # after the section's last non-empty line
            $insert = $end
            while ($insert -gt $start + 1 -and $lines[$insert - 1].Trim() -eq '') { $insert-- }
            $lines.Insert($insert, $wanted)
        }
    }
    [System.IO.File]::WriteAllLines($Path, $lines, (New-Object System.Text.UTF8Encoding($bom)))
    return $true
}

function Get-PluginInfo([string]$Path) {
    # Identifies the deployed plugin build: the file version when the DLL carries
    # one, otherwise size + mtime + SHA-256 tell builds apart. Read-only.
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [ordered]@{ present = $false } }
    $item = Get-Item -LiteralPath $Path -Force
    $version = $null
    try { $version = $item.VersionInfo.FileVersion } catch { }
    $hash = $null
    try { $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() } catch { }
    return [ordered]@{
        present = $true; file_version = $version; size = $item.Length
        mtime = $item.LastWriteTimeUtc.ToString('s') + 'Z'; sha256 = $hash
    }
}

$dry = [bool]$DryRun
$planned = New-Object System.Collections.Generic.List[string]

function Invoke-Planned([string]$Description, [scriptblock]$Change) {
    # Applies one change, or in dry-run mode only records and logs it. $Change runs in
    # a child scope: it must not assign variables that later steps read.
    if ($script:dry) {
        $script:planned.Add($Description)
        Write-Log "dry-run, would: $Description"
        return
    }
    & $Change
    Write-Log $Description
}

try {
    Write-Log "provision start (params: $ParamsFile)"
    if (-not (Test-Path -LiteralPath $ParamsFile)) { throw "params file not found: $ParamsFile" }
    $p = Get-Content -Raw -LiteralPath $ParamsFile | ConvertFrom-Json
    Remove-Item -Force -LiteralPath $ParamsFile
    Write-Log 'params read and params file deleted'
    if ($p.dry_run) { $dry = $true }
    if ($dry) { Write-Log 'DRY RUN: reporting planned actions only, nothing is changed' }

    $root = [string]$p.x64dbg_root
    $user = [string]$p.user
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { throw "x64dbg_root not found: $root" }
    if (-not $user) { throw 'user is required' }
    if ($p.autologon -and -not $p.password -and -not $dry) { throw 'autologon requested but no password supplied' }
    $bind = if ($p.bind) { [string]$p.bind } else { '127.0.0.1' }
    $jobRoot = if ($p.job_root) { [string]$p.job_root } else { 'C:\mcp\jobs' }
    $allowedClients = [string[]]@($p.allowed_clients | Where-Object { $_ } | ForEach-Object { [string]$_ })

    $result = [ordered]@{
        x64dbg_root = $root; user = $user; bind = $bind; job_root = $jobRoot; dry_run = $dry
        backends = [ordered]@{}; skipped = @()
    }

    # 1. job root, writable by the interactive user even from a non-elevated process
    Invoke-Planned "create job root $jobRoot" {
        New-Item -ItemType Directory -Force -Path $jobRoot | Out-Null
    }
    Invoke-Planned "grant $user Modify (inherited by subfolders and files) on $jobRoot" {
        $dirInfo = Get-Item -LiteralPath $jobRoot -Force
        $acl = $dirInfo.GetAccessControl('Access')
        $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
            -ArgumentList $user, 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
        $acl.SetAccessRule($rule)
        $dirInfo.SetAccessControl($acl)
    }

    # 2. plugin configs + 3. scheduled tasks (one per architecture)
    $archs = @(
        @{ id = 'x64'; exe = 'x64dbg.exe'; plugin = 'x64dbg-MCP-Server.dp64'; task = 'MCP-x64dbg'; port = 9094 },
        @{ id = 'x32'; exe = 'x32dbg.exe'; plugin = 'x64dbg-MCP-Server.dp32'; task = 'MCP-x32dbg'; port = 9095 }
    )
    foreach ($a in $archs) {
        $dir = Join-Path $root $a.id
        $exe = Join-Path $dir $a.exe
        if (-not (Test-Path -LiteralPath $exe)) {
            Write-Log "skip $($a.id): $exe not found"
            $result.skipped += $a.id
            continue
        }
        $port = if ($p.ports -and $p.ports.($a.id)) { [int]$p.ports.($a.id) } else { $a.port }
        $cfgPath = Join-Path $dir 'mcp_config.json'

        $plugin = Get-PluginInfo (Join-Path (Join-Path $dir 'plugins') $a.plugin)
        if ($plugin.present) {
            Write-Log ('plugin {0}: {1} version={2} size={3} mtime={4} sha256={5}' -f $a.id, $a.plugin,
                $plugin.file_version, $plugin.size, $plugin.mtime, $plugin.sha256)
        } else {
            Write-Log "plugin $($a.id): $($a.plugin) not found in $dir\plugins"
        }

        $token = $null
        $tokenSource = 'params'
        if ($p.tokens -and $p.tokens.($a.id)) { $token = [string]$p.tokens.($a.id) }
        if (-not $token) { $token = Read-ExistingToken $cfgPath; $tokenSource = 'existing' }
        $generated = $false
        if (-not $token) {
            $generated = $true
            $tokenSource = 'generated'
            if (Test-Path -LiteralPath $cfgPath) {
                Write-Log "existing $cfgPath has no valid token (corrupt, zero-filled or invalid)"
            }
            if (-not $dry) { $token = New-Token }
        }
        $tokenLength = if ($token) { $token.Length } else { 32 }

        # The keys every plugin version reads come first (v1.3 reads only 512 bytes).
        $cfg = [ordered]@{ IpAddress = $bind; Port = $port; AutoStart = $true; AuthToken = $token }
        $allowText = 'unchanged'
        if ($allowedClients.Count -gt 0) {
            $cfg.AllowExternal = $true
            $cfg.AllowedClients = $allowedClients
            $allowText = $allowedClients -join ','
        }
        # Keep every other key of an existing config (operator settings such as MaxClients).
        $existing = Read-ConfigObject $cfgPath
        $kept = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($existing.Keys)) {
            if (-not $cfg.Contains($k)) { $cfg[$k] = $existing[$k]; $kept.Add([string]$k) }
        }
        $keptText = if ($kept.Count -gt 0) { $kept -join ',' } else { 'none' }
        Invoke-Planned "write $cfgPath (bind=$bind port=$port token=$tokenSource allowed_clients=$allowText kept_keys=$keptText)" {
            Write-Utf8NoBom $cfgPath ($cfg | ConvertTo-Json -Compress -Depth 10)
        }

        # x64dbg reads its settings from <exe dir>\<exe name>.ini (x64dbg.ini, x32dbg.ini).
        # Engine/DisableDatabaseCompression=1 keeps databases saved to x64dbg's default
        # location plain JSON instead of LZ4 (ida_export_annotations parses them).
        # ASSUMPTION, to be verified on the real VM: the ini file name (taken from the exe
        # name, as x64dbg's bridge does) and the section/key names (x64dbg database.cpp).
        # A debugger running now may write its own settings back when it exits; the reboot
        # that normally follows provisioning starts it with the new file.
        $ini = [System.IO.Path]::ChangeExtension($exe, '.ini')
        $dbgName = [System.IO.Path]::GetFileNameWithoutExtension($exe)
        if (@(Get-Process -Name $dbgName -ErrorAction SilentlyContinue).Count -gt 0) {
            Write-Log "note: $($a.exe) is running; it may rewrite $ini when it exits"
        }
        Invoke-Planned "set [Engine] DisableDatabaseCompression=1 in $ini" {
            Set-IniValue $ini 'Engine' 'DisableDatabaseCompression' '1' | Out-Null
        }

        Invoke-Planned "register scheduled task $($a.task) -> $exe (user $user, Interactive, Highest, AtLogOn)" {
            $action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $dir
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
            $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName $a.task -Action $action -Trigger $trigger -Principal $principal `
                -Settings $settings -Force | Out-Null
        }

        $result.backends[$a.id] = [ordered]@{
            exe = $exe; config = $cfgPath; port = $port; task = $a.task
            token_length = $tokenLength; token_generated = $generated; plugin = $plugin
            settings_ini = $ini; db_compression = $(if ($dry) { 'unchanged' } else { 'disabled' })
        }
    }

    # 4. auto-logon (Winlogon registry; the password is stored by Windows, never logged here)
    if ($p.autologon) {
        Invoke-Planned "configure auto-logon for $user" {
            $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Set-ItemProperty -Path $wl -Name AutoAdminLogon -Value '1'
            Set-ItemProperty -Path $wl -Name DefaultUserName -Value $user
            Set-ItemProperty -Path $wl -Name DefaultDomainName -Value $env:COMPUTERNAME
            Set-ItemProperty -Path $wl -Name DefaultPassword -Value ([string]$p.password)
            Remove-ItemProperty -Path $wl -Name AutoLogonCount -ErrorAction SilentlyContinue
        }
        $result.autologon = $true
    }

    # 5. keep the session awake
    if ($p.no_sleep) {
        Invoke-Planned 'disable standby, monitor and hibernate timeouts (AC power)' {
            & powercfg.exe /change standby-timeout-ac 0 | Out-Null
            & powercfg.exe /change monitor-timeout-ac 0 | Out-Null
            & powercfg.exe /change hibernate-timeout-ac 0 | Out-Null
        }
    }

    if ($dry) { $result.actions = @($planned) }
    $result.status = 'ok'
    Write-Utf8NoBom (Join-Path $McpDir 'provision.result.json') ($result | ConvertTo-Json -Depth 6)
    Write-Log 'provision done'
    exit 0
} catch {
    Write-Log ("provision FAILED: " + $_.Exception.Message)
    Write-Utf8NoBom (Join-Path $McpDir 'provision.result.json') (@{ status = 'failed'; error = $_.Exception.Message } | ConvertTo-Json)
    if (Test-Path -LiteralPath $ParamsFile) { Remove-Item -Force -LiteralPath $ParamsFile -ErrorAction SilentlyContinue }
    exit 1
}
