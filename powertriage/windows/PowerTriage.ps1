<#PSScriptInfo
.VERSION 2.3.4
.GUID 978e8b23-1d54-46c5-a20c-7b2d5f81e7d2
.AUTHOR Jesus Angosto
.COMPANYNAME PowerForensics
.COPYRIGHT (c) 2025 Jesus Angosto. All rights reserved.
.TAGS DFIR, Forensics, IncidentResponse, Triage, PowerShell, Windows, LiveResponse, CommunityEdition
.LICENSEURI https://github.com/PowerForensics/powerforensics/blob/main/LICENSE
.PROJECTURI  https://github.com/PowerForensics/powerforensics
.RELEASENOTES Default execution now runs the full CE workflow without interactive prompts, aligns output-directory behavior with unattended use, and improves browser profile collection plus Chronos timeline compatibility.
#>

<#
.SYNOPSIS
    PowerTriage Windows CE - Community Edition live triage for DFIR on Windows.

.DESCRIPTION
    PowerTriage Windows CE is a native PowerShell triage script designed for Incident Response (DFIR) and forensic triage on compromised Windows systems.
    It focuses on practical live response, low deployment friction, and dependency-free artifact collection in the Community Edition.
    
    Community Edition highlights:
    - Native PowerShell: Runs on standard PowerShell 5.1+
    - Live Triage: Focused on rapid collection from running Windows hosts
    - Broad Coverage: Network, process, persistence, system, browser, cloud, and user artifacts
    - Browser Forensics: Chrome, Edge, Firefox, Opera, Brave (history, cookies, extensions, sync status)
    - System Triage: Network connections, processes, services, scheduled tasks, registry autoruns
    - Structured Output: CSV/TXT artifacts, hashes, and a packaged final collection
    - Low Friction: Intended for practical adoption by responders and analysts

    The Pro workflow extends this model with advanced capabilities such as offline mounted-volume collection,
    chain of custody outputs, executive reporting, and enhanced evidence packaging.

.PARAMETER OutputDirectory
    Specifies the directory where the triage results will be saved. Defaults to current directory.

.PARAMETER OutputRetention
    Controls whether PowerTriage keeps the directory tree, the ZIP file, or both:
    Both (default), DirectoryOnly, or ZipOnly.

.PARAMETER PacketCapture
    Enables native packet capture using pktmon during live collection.

.PARAMETER PacketCaptureQuick
    Enables a short packet capture profile intended for rapid triage.

.PARAMETER PacketCaptureDuration
    Specifies the packet capture duration in seconds. Default: 30.

.PARAMETER PacketCaptureFormat
    Specifies the packet capture output format: etl, pcapng, or both.

.PARAMETER PacketCaptureProtocol
    Limits packet capture to a protocol: Any, TCP, UDP, ICMP, or ICMPv6.

.PARAMETER PacketCaptureDropOnly
    Restricts packet capture to dropped packets.

.PARAMETER PacketCaptureIP
    Applies one or more IP or CIDR filters to packet capture.

.PARAMETER PacketCapturePort
    Applies one or more TCP/UDP port filters to packet capture.

.PARAMETER BrowserCollectionMode
    Controls how browser artifacts are collected when a browser is running:
    BestEffort (default), GracefulClose, or ForceKill.

.PARAMETER Timeline
    Generates a Chronos-compatible JSON timeline from collected CE artifacts.

.PARAMETER NexusLite
    Generates a lightweight Nexus graph JSON from CE process, network, and RDP data.

.PARAMETER Help
    Shows the built-in help panel and exits.

.PARAMETER Full
    Performs the complete CE workflow, including full collection, Chronos timeline,
    Nexus Lite, findings generation, and Executive HTML summary.

.PARAMETER Minimal
    Performs a quick triage collecting only Volatile Data (Network, Process, System).

.EXAMPLE
    .\PowerTriage.ps1
    Runs the full CE workflow by default and saves output to the current directory.

.EXAMPLE
    .\PowerTriage.ps1 -Minimal
    Runs a quick triage (Network, Process, System only).

.EXAMPLE
    .\PowerTriage.ps1 -OutputDirectory "C:\Cases\Case404"
    Runs a full triage and saves output to C:\Cases\Case404.

.EXAMPLE
    .\PowerTriage.ps1 -OutputRetention DirectoryOnly
    Keeps the directory tree only and skips final ZIP generation.

.EXAMPLE
    .\PowerTriage.ps1 -BrowserCollectionMode GracefulClose
    Attempts to close supported browsers cleanly before collecting browser artifacts.

.EXAMPLE
    .\PowerTriage.ps1 -Full -Timeline -NexusLite
    Runs a full collection and generates Chronos timeline plus Nexus Lite graph outputs.

.NOTES
    Community Edition (CE) focuses on strong live triage for the DFIR community.
    Some protected artifacts require administrator privileges; without elevation, the script continues in degraded mode when possible.

.LINK
   https://github.com/PowerForensics/powerforensics
#>

param(
    [Alias('O')]
    [string]$OutputDirectory,
    [ValidateSet('Both','DirectoryOnly','ZipOnly')]
    [string]$OutputRetention = 'Both',
    [switch]$PacketCapture,
    [switch]$PacketCaptureQuick,
    [ValidateRange(5, 3600)]
    [int]$PacketCaptureDuration = 30,
    [ValidateSet('etl','pcapng','both')]
    [string]$PacketCaptureFormat = 'both',
    [ValidateSet('Any','TCP','UDP','ICMP','ICMPv6')]
    [string]$PacketCaptureProtocol = 'Any',
    [switch]$PacketCaptureDropOnly,
    [string[]]$PacketCaptureIP,
    [int[]]$PacketCapturePort,
    [ValidateSet('BestEffort','GracefulClose','ForceKill')]
    [string]$BrowserCollectionMode = 'BestEffort',
    [switch]$Timeline,
    [switch]$NexusLite,
    [Parameter(Mandatory=$false)]
    [Alias('h')]
    [switch]$Help,
    [Parameter(Mandatory=$false)]
    [Alias('f')]
    [switch]$Full,
    [Parameter(Mandatory=$false)]
    [Alias('m')]
    [switch]$Minimal
)

# PowerTriage Windows CE
# Live Response & Forensic Triage Tool

$Version = "2.3.4"

function Show-Banner {
    Clear-Host
    Write-Host "__________                         ___________       .__                      " -ForegroundColor Cyan
    Write-Host "\______   \______  _  __ _________ \__    ___/_______|__|____     ____   ____ " -ForegroundColor Cyan
    Write-Host " |     ___/  _ \ \/ \/ // __ \_  __ \|    |  \_  __ \  \__  \   / ___\_/ __ \ " -ForegroundColor Cyan
    Write-Host " |    |  (  <_> )     /\  ___/|  | \/|    |   |  | \/  |/ __ \_/ /_/  >  ___/ " -ForegroundColor Cyan
    Write-Host " |____|   \____/ \/\_/  \___  >__|   |____|   |__|  |__(____  /\___  / \___  > " -ForegroundColor Cyan
    Write-Host "                            \/                              \//_____/      \/ " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "PowerTriage Windows CE is a community live-triage script for Windows DFIR and Incident Response." -ForegroundColor Yellow
    Write-Host "Version: $Version (Community Edition)" -ForegroundColor White
    Write-Host "By twitter 'X': @jdangosto, https://github.com/jdangosto  - Jesus Angosto (jdangosto)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "=============================================================" -ForegroundColor Green
    Write-Host "Execution Date (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
    Write-Host "Hostname            : $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host "User                : $env:USERNAME" -ForegroundColor Green
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    Write-Host "Admin Privileges    : $isAdmin" -ForegroundColor Green
    Write-Host "=============================================================" -ForegroundColor Green
    Write-Host ""
}

function Show-Help {
    Show-Banner
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\PowerTriage.ps1 [Options]"
    Write-Host ""
    Write-Host "COLLECTION MODES:" -ForegroundColor Yellow
    Write-Host "  -Full, -f               Complete Community Edition workflow"
    Write-Host "                           Includes: Network, System, Process, Events, Users,"
    Write-Host "                           Browser, Disk, Cloud, Chronos Timeline,"
    Write-Host "                           Nexus Lite, findings, and Executive HTML summary."
    Write-Host "  -Minimal, -m            Quick triage mode"
    Write-Host "                           Includes: Network, System, and Process artifacts only."
    Write-Host "                           Default execution mode is Full when none is specified."
    Write-Host ""
    Write-Host "GENERAL OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -OutputDirectory, -O    Directory where results will be stored."
    Write-Host "                           Default: current directory."
    Write-Host "  -OutputRetention        Both, DirectoryOnly, or ZipOnly."
    Write-Host "                           Default: Both."
    Write-Host "  -BrowserCollectionMode  BestEffort, GracefulClose, or ForceKill."
    Write-Host "                           Default: BestEffort."
    Write-Host "  -Timeline               Export a Chronos-compatible timeline JSON."
    Write-Host "  -NexusLite              Export a lightweight Nexus graph JSON."
    Write-Host "  -Help, -h               Show this help panel and exit."
    Write-Host ""
    Write-Host "PACKET CAPTURE OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -PacketCapture          Enable pktmon packet capture during triage."
    Write-Host "  -PacketCaptureQuick     Use the short packet capture profile (15 seconds)."
    Write-Host "  -PacketCaptureDuration  Capture duration in seconds. Default: 30."
    Write-Host "  -PacketCaptureFormat    etl, pcapng, or both. Default: both."
    Write-Host "  -PacketCaptureProtocol  Any, TCP, UDP, ICMP, or ICMPv6. Default: Any."
    Write-Host "  -PacketCaptureDropOnly  Capture dropped packets only."
    Write-Host "  -PacketCaptureIP        One or more IP or CIDR filters."
    Write-Host "  -PacketCapturePort      One or more TCP/UDP port filters."
    Write-Host ""
    Write-Host "OUTPUTS:" -ForegroundColor Yellow
    Write-Host "  - Directory tree per execution: PowerTriage_<HOST>_<Timestamp>"
    Write-Host "  - PowerTriage.log"
    Write-Host "  - Hashes.csv"
    Write-Host "  - Structured CSV/TXT artifacts by category"
    Write-Host "  - Findings\\Findings.csv, Findings.jsonl, Findings_Summary.txt"
    Write-Host "  - Executive_Report.html"
    Write-Host "  - Optional Timeline\\PowerTriage_Timeline_Chronos.json when -Timeline is enabled"
    Write-Host "  - Optional Network\\Nexus_Graph_Lite.json when -NexusLite is enabled"
    Write-Host "  - Optional final compressed collection package depending on -OutputRetention"
    Write-Host "  - Optional Network\\PacketCapture outputs when pktmon is enabled"
    Write-Host ""
    Write-Host "ABOUT CE:" -ForegroundColor Yellow
    Write-Host "  Community Edition focuses on live triage, low friction, and practical DFIR adoption."
    Write-Host "  Some advanced offline acquisition, reporting, and evidence-packaging workflows are reserved for PRO."
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\PowerTriage.ps1"
    Write-Host "  .\PowerTriage.ps1 -Full"
    Write-Host "  .\PowerTriage.ps1 -Minimal"
    Write-Host "  .\PowerTriage.ps1 -OutputDirectory 'C:\Cases\Case001'"
    Write-Host "  .\PowerTriage.ps1 -OutputRetention DirectoryOnly"
    Write-Host "  .\PowerTriage.ps1 -BrowserCollectionMode GracefulClose"
    Write-Host "  .\PowerTriage.ps1 -Full -Timeline -NexusLite"
    Write-Host "  .\PowerTriage.ps1 -PacketCapture -PacketCaptureDuration 60"
    Write-Host "  .\PowerTriage.ps1 -PacketCaptureQuick -PacketCaptureIP '10.10.10.10' -PacketCapturePort 443"
    Write-Host "  .\PowerTriage.ps1 -PacketCapture -PacketCaptureProtocol TCP -PacketCaptureDropOnly -PacketCaptureFormat pcapng"
    Write-Host ""
}

# Show Help if requested
if ($Help) {
    Show-Help
    exit 0
}

# Apply Minimal or Full logic
if ($Full -and $Minimal) {
    Write-Warning "Use either -Full or -Minimal, not both."
    exit 1
}

if ((-not $Full) -and (-not $Minimal)) {
    $Full = $true
}

# Initialize internal flags
$Network = $false
$System = $false
$Process = $false
$Events = $false
$Users = $false
$Browser = $false
$Disk = $false
$Cloud = $false
$RunAll = $false
$GenerateFindings = $true
$GenerateExecutiveReport = $true

if ($PacketCaptureQuick -or $PacketCaptureIP -or $PacketCapturePort -or $PacketCaptureDropOnly -or ($PacketCaptureProtocol -ne 'Any')) {
    $PacketCapture = $true
}

if ($PacketCaptureQuick -and $PacketCaptureDuration -eq 30) {
    $PacketCaptureDuration = 15
}

if ($Minimal) {
    $Network = $true
    $System = $true
    $Process = $true
} else {
    $RunAll = $true
    $Network = $true
    $System = $true
    $Process = $true
    $Events = $true
    $Users = $true
    $Browser = $true
    $Disk = $true
    $Cloud = $true
    $Timeline = $true
    $NexusLite = $true
}

Show-Banner

# Check Admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    Write-Warning "Continuing in degraded mode; some artifacts may be unavailable."
}

# Output Directory Selection
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $targetDir = $PWD
} else {
    $targetDir = $OutputDirectory
}

# Resolve relative paths & Create if missing
if (-not (Test-Path $targetDir)) {
    try {
        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $targetDir" -ForegroundColor Green
    } catch {
        Write-Warning "Could not create directory '$targetDir'. Using current directory."
        $targetDir = $PWD
    }
} else {
    # Ensure we have the absolute path for cleaner logs
    $targetDir = (Resolve-Path $targetDir).Path
}

# Setup
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$FolderCreation = Join-Path $targetDir "PowerTriage_$($env:COMPUTERNAME)_$Timestamp"
New-Item -Path $FolderCreation -ItemType Directory -Force | Out-Null
$LogFile = "$FolderCreation\PowerTriage.log"

function WriteLog {
    param([string]$Level, [string]$Message)
    $LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $LogEntry | Out-File -Append -FilePath $LogFile -Encoding UTF8
}

function WriteHash {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        try {
            $Hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            if ($Hash) {
                "$($Hash.Algorithm),$($Hash.Hash),$($Hash.Path)" | Out-File -Append -FilePath "$FolderCreation\Hashes.csv" -Encoding UTF8
            }
        } catch {}
    }
}

function Set-ArtifactVisible {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            cmd /c attrib -h -s "$Path" 2>$null | Out-Null
        }
    } catch {}
}

function Ensure-AcquiredArtifactAccessible {
    param([string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return }

        Set-ArtifactVisible -Path $Path

        try {
            $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            if ($item.PSIsContainer) {
                Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    Set-ArtifactVisible -Path $_.FullName
                }
            } else {
                $item.Attributes = [System.IO.FileAttributes]::Normal
            }
        } catch {}

        $currentIdentity = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
        try {
            cmd /c "takeown /f ""$Path"" /a /r /d y" 1>$null 2>$null | Out-Null
        } catch {}
        try {
            cmd /c "icacls ""$Path"" /inheritance:e /grant:r ""$currentIdentity"":F /t /c" 1>$null 2>$null | Out-Null
        } catch {}
    } catch {}
}

function Get-RelativeChildPath {
    param(
        [string]$BasePath,
        [string]$FullPath
    )

    $normalizedBase = $BasePath.TrimEnd('\')
    if ($FullPath.StartsWith($normalizedBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $FullPath.Substring($normalizedBase.Length).TrimStart('\')
    }

    return [System.IO.Path]::GetFileName($FullPath)
}

function Copy-LiveArtifactWithFallback {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [ValidateSet('Copy','Esent','Backup')]
        [string]$PreferredMethod = 'Copy',
        [string]$ArtifactTag = 'Artifact'
    )

    if (-not (Test-Path -LiteralPath $SourcePath -ErrorAction SilentlyContinue)) {
        WriteLog -Level "WARN" -Message "$ArtifactTag source not found: $SourcePath"
        return $false
    }

    $destDir = Split-Path -Path $DestinationPath -Parent
    if (-not (Test-Path -LiteralPath $destDir -ErrorAction SilentlyContinue)) {
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
    }

    $copySucceeded = $false
    $copyMethod = $null

    try {
        Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
        $copySucceeded = $true
        $copyMethod = "CopyItem"
    } catch {
        $message = $_.Exception.Message
        $lockHint = if ($message -match 'used by another process|sharing violation|being used') { " Possible lock detected." } else { "" }
        WriteLog -Level "WARN" -Message "$ArtifactTag direct copy failed. Src=$SourcePath Dest=$DestinationPath Error=$message$lockHint"
        Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
    }

    if ((-not $copySucceeded) -and ($PreferredMethod -eq 'Esent')) {
        $esentCmd = Get-Command esentutl -ErrorAction SilentlyContinue
        if ($esentCmd) {
            try {
                $esentOutput = & esentutl /y $SourcePath /d $DestinationPath /o 2>&1 | Out-String
                if ((Test-Path -LiteralPath $DestinationPath -ErrorAction SilentlyContinue) -and ($LASTEXITCODE -eq 0)) {
                    $copySucceeded = $true
                    $copyMethod = "esentutl"
                } else {
                    WriteLog -Level "WARN" -Message "$ArtifactTag esentutl fallback failed. Src=$SourcePath Dest=$DestinationPath ExitCode=$LASTEXITCODE Output=$($esentOutput.Trim())"
                    Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
                }
            } catch {
                WriteLog -Level "WARN" -Message "$ArtifactTag esentutl fallback exception. Src=$SourcePath Dest=$DestinationPath Error=$($_.Exception.Message)"
                Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
            }
        } else {
            WriteLog -Level "WARN" -Message "$ArtifactTag esentutl fallback unavailable on this host. Src=$SourcePath"
        }
    }

    if (-not $copySucceeded) {
        try {
            $srcDir = Split-Path -Path $SourcePath -Parent
            $srcName = Split-Path -Path $SourcePath -Leaf
            $roboOutput = & robocopy $srcDir $destDir $srcName /B /R:0 /W:0 /COPY:DAT /NP /NFL /NDL /NJH /NJS 2>&1 | Out-String
            if (Test-Path -LiteralPath $DestinationPath -ErrorAction SilentlyContinue) {
                $copySucceeded = $true
                $copyMethod = "robocopy /B"
            } else {
                WriteLog -Level "WARN" -Message "$ArtifactTag robocopy backup fallback failed. Src=$SourcePath Dest=$DestinationPath ExitCode=$LASTEXITCODE Output=$($roboOutput.Trim())"
            }
        } catch {
            WriteLog -Level "WARN" -Message "$ArtifactTag robocopy backup fallback exception. Src=$SourcePath Dest=$DestinationPath Error=$($_.Exception.Message)"
        }
    }

    if ($copySucceeded) {
        Ensure-AcquiredArtifactAccessible -Path $DestinationPath
        WriteHash -FilePath $DestinationPath
        WriteLog -Level "INFO" -Message "$ArtifactTag acquired using $copyMethod. Src=$SourcePath Dest=$DestinationPath"
        return $true
    }

    WriteLog -Level "ERROR" -Message "$ArtifactTag acquisition failed after live copy fallbacks. Src=$SourcePath Dest=$DestinationPath"
    return $false
}

function Get-BrowserProcessNames {
    param([string]$BrowserName)

    switch ($BrowserName) {
        "Firefox" { return @("firefox") }
        "Opera" { return @("opera") }
        "OperaGX" { return @("opera") }
        "Edge" { return @("msedge") }
        "Chrome" { return @("chrome") }
        "CCleaner" { return @("CCleanerBrowser") }
        "Brave" { return @("brave") }
        default { return @() }
    }
}

function Add-BrowserProcessAction {
    param(
        [string]$Browser,
        [string]$User,
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Mode,
        [string]$Action,
        [string]$Status,
        [string]$Details
    )

    if (-not (Get-Variable -Name BrowserProcessActions -Scope Script -ErrorAction SilentlyContinue)) {
        $script:BrowserProcessActions = New-Object System.Collections.Generic.List[object]
    }

    $script:BrowserProcessActions.Add([PSCustomObject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        Browser = $Browser
        User = $User
        ProcessId = $ProcessId
        ProcessName = $ProcessName
        Mode = $Mode
        Action = $Action
        Status = $Status
        Details = $Details
    }) | Out-Null
}

function Invoke-BrowserCollectionPreparation {
    param([string]$BrowserName)

    if ($BrowserCollectionMode -eq 'BestEffort') {
        WriteLog -Level "INFO" -Message "Browser collection mode for ${BrowserName}: BestEffort (no process interaction)."
        return
    }

    $processNames = Get-BrowserProcessNames -BrowserName $BrowserName
    if ($processNames.Count -eq 0) {
        return
    }

    $running = @(Get-Process -Name $processNames -ErrorAction SilentlyContinue | Sort-Object Id -Unique)
    if ($running.Count -eq 0) {
        WriteLog -Level "INFO" -Message "No running processes found for browser $BrowserName."
        return
    }

    Write-Host "Browser collection mode for ${BrowserName}: $BrowserCollectionMode" -ForegroundColor DarkYellow
    WriteLog -Level "INFO" -Message "Preparing browser collection for ${BrowserName} using mode $BrowserCollectionMode."

    foreach ($proc in $running) {
        $userName = "Unknown"
        try {
            $owner = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($owner -and $owner.User) {
                $userName = if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { $owner.User }
            }
        } catch {}

        if ($BrowserCollectionMode -in @('GracefulClose','ForceKill')) {
            try {
                if ($proc.MainWindowHandle -ne 0) {
                    $closed = $proc.CloseMainWindow()
                    Add-BrowserProcessAction -Browser $BrowserName -User $userName -ProcessId $proc.Id -ProcessName $proc.ProcessName -Mode $BrowserCollectionMode -Action "CloseMainWindow" -Status $(if ($closed) { "Requested" } else { "Rejected" }) -Details "Requested graceful close before artifact collection."
                } else {
                    Add-BrowserProcessAction -Browser $BrowserName -User $userName -ProcessId $proc.Id -ProcessName $proc.ProcessName -Mode $BrowserCollectionMode -Action "CloseMainWindow" -Status "Skipped" -Details "Process has no main window handle."
                }
            } catch {
                Add-BrowserProcessAction -Browser $BrowserName -User $userName -ProcessId $proc.Id -ProcessName $proc.ProcessName -Mode $BrowserCollectionMode -Action "CloseMainWindow" -Status "Error" -Details $_.Exception.Message
            }
        }
    }

    Start-Sleep -Seconds 4

    if ($BrowserCollectionMode -eq 'ForceKill') {
        $remaining = @(Get-Process -Name $processNames -ErrorAction SilentlyContinue | Sort-Object Id -Unique)
        foreach ($proc in $remaining) {
            $userName = "Unknown"
            try {
                $owner = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($owner -and $owner.User) {
                    $userName = if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { $owner.User }
                }
            } catch {}

            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Add-BrowserProcessAction -Browser $BrowserName -User $userName -ProcessId $proc.Id -ProcessName $proc.ProcessName -Mode $BrowserCollectionMode -Action "Stop-Process" -Status "Success" -Details "Forced termination before artifact collection."
            } catch {
                Add-BrowserProcessAction -Browser $BrowserName -User $userName -ProcessId $proc.Id -ProcessName $proc.ProcessName -Mode $BrowserCollectionMode -Action "Stop-Process" -Status "Error" -Details $_.Exception.Message
            }
        }
    }
}

function Add-PacketCaptureFilters {
    param(
        [string[]]$IPs,
        [int[]]$Ports,
        [string]$Protocol = 'Any'
    )

    $filtersApplied = New-Object System.Collections.Generic.List[string]
    try { & pktmon filter remove 2>$null | Out-Null } catch {}

    $normalizedIps = @($IPs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $normalizedPorts = @($Ports | Where-Object { $_ -gt 0 } | Select-Object -Unique)
    $filterIndex = 0

    $transportArgs = @()
    if ($Protocol -and $Protocol -ne 'Any') {
        $transportArgs = @('-t', $Protocol)
    }

    if (($Protocol -in @('ICMP','ICMPv6')) -and $normalizedPorts.Count -gt 0) {
        $normalizedPorts = @()
    }

    if ($normalizedIps.Count -gt 0 -and $normalizedPorts.Count -gt 0) {
        foreach ($ip in $normalizedIps) {
            foreach ($port in $normalizedPorts) {
                $filterIndex++
                $name = "PT_IPPort_$filterIndex"
                $args = @('filter','add',$name,'-i',$ip,'-p',$port) + $transportArgs
                & pktmon @args 2>&1 | Out-Null
                [void]$filtersApplied.Add("name=$name ip=$ip port=$port protocol=$Protocol")
            }
        }
    } elseif ($normalizedIps.Count -gt 0) {
        foreach ($ip in $normalizedIps) {
            $filterIndex++
            $name = "PT_IP_$filterIndex"
            $args = @('filter','add',$name,'-i',$ip) + $transportArgs
            & pktmon @args 2>&1 | Out-Null
            [void]$filtersApplied.Add("name=$name ip=$ip protocol=$Protocol")
        }
    } elseif ($normalizedPorts.Count -gt 0) {
        foreach ($port in $normalizedPorts) {
            $filterIndex++
            $name = "PT_Port_$filterIndex"
            $args = @('filter','add',$name,'-p',$port) + $transportArgs
            & pktmon @args 2>&1 | Out-Null
            [void]$filtersApplied.Add("name=$name port=$port protocol=$Protocol")
        }
    } elseif ($transportArgs.Count -gt 0) {
        $filterIndex++
        $name = "PT_Proto_$filterIndex"
        $args = @('filter','add',$name) + $transportArgs
        & pktmon @args 2>&1 | Out-Null
        [void]$filtersApplied.Add("name=$name protocol=$Protocol")
    }

    return @($filtersApplied)
}

function New-PacketCaptureOutputEntry {
    param([string]$Path)

    $exists = Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    $size = $null
    $sha256 = $null

    if ($exists) {
        try { $size = (Get-Item -LiteralPath $Path -ErrorAction Stop).Length } catch {}
        try { $sha256 = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
    }

    return [ordered]@{
        path = $Path
        exists = [bool]$exists
        size = $size
        sha256 = $sha256
    }
}

function Convert-ToTimelineTimestamp {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq 'N/A') { return $null }

    try {
        if ($text -match '^\d{14}\.\d{6}[\+\-]\d{3}$') {
            $dt = [System.Management.ManagementDateTimeConverter]::ToDateTime($text)
            if ($dt.Year -le 1601) { return $null }
            return $dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    } catch {}

    try {
        $dt = [datetime]::Parse($text)
        if ($dt.Year -le 1601) { return $null }
        return $dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    } catch {}

    return $null
}

function New-ChronosTimelineEvent {
    param(
        [string]$Timestamp,
        [string]$Title,
        [string]$Description,
        [string]$Type,
        [string]$Priority,
        [string]$Source,
        [hashtable]$Metadata = $null
    )

    if ([string]::IsNullOrWhiteSpace($Timestamp)) { return $null }

    if (-not $Metadata) {
        $Metadata = @{}
    }

    if (-not $Metadata.ContainsKey('tags')) {
        $Metadata['tags'] = @('powertriage','windows','ce')
    }

    if (-not $script:ChronosTimelineEventCounter) {
        $script:ChronosTimelineEventCounter = 0
    }
    $script:ChronosTimelineEventCounter++
    $eventId = "pt-ce-{0:D6}" -f $script:ChronosTimelineEventCounter

    return [PSCustomObject][ordered]@{
        id = $eventId
        timestamp = $Timestamp
        title = $Title
        description = $Description
        type = $Type
        priority = $Priority
        asset = $env:COMPUTERNAME
        source = $Source
        author = 'PowerTriage'
        caseId = "powertriage-$($env:COMPUTERNAME.ToLowerInvariant())"
        metadata = $Metadata
    }
}

function Add-ChronosTimelineEvent {
    param(
        [System.Collections.Generic.List[object]]$Events,
        [object]$Event
    )

    if ($null -ne $Event) {
        $Events.Add($Event) | Out-Null
    }
}

function Add-TimelineFileArtifactEvents {
    param(
        [System.Collections.Generic.List[object]]$Events,
        [string]$RootPath,
        [string]$Source,
        [string]$Type,
        [string]$Priority,
        [string]$TitlePrefix
    )

    if (-not (Test-Path -LiteralPath $RootPath -ErrorAction SilentlyContinue)) { return }

    Get-ChildItem -LiteralPath $RootPath -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $timestamp = Convert-ToTimelineTimestamp $_.LastWriteTime
        $relativePath = $_.FullName.Substring($FolderCreation.Length + 1)
        $description = "Observed file artifact: $relativePath | Size=$($_.Length) | LastWriteTime=$($_.LastWriteTime)"
        $metadata = @{
            tags = @('powertriage','windows','ce',$Source)
            path = $relativePath
            evidencePath = $relativePath
            activityType = 'Observed'
        }
        Add-ChronosTimelineEvent -Events $Events -Event (New-ChronosTimelineEvent -Timestamp $timestamp -Title "${TitlePrefix}: $($_.Name)" -Description $description -Type $Type -Priority $Priority -Source $Source -Metadata $metadata)
    }
}

function Add-NexusLiteNode {
    param(
        [System.Collections.Generic.List[object]]$Nodes,
        [hashtable]$Tracker,
        [string]$Id,
        [string]$Type,
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Id)) { return }
    if (-not $Tracker.ContainsKey($Id)) {
        $Nodes.Add([PSCustomObject][ordered]@{
            id = $Id
            type = $Type
            label = $Label
        }) | Out-Null
        $Tracker[$Id] = $true
    }
}

function Add-NexusLiteEdge {
    param(
        [System.Collections.Generic.List[object]]$Edges,
        [hashtable]$Tracker,
        [hashtable]$Edge
    )

    $key = @(
        $Edge.type,
        $Edge.src,
        $Edge.dst,
        $(if ($Edge.timestamp) { $Edge.timestamp } else { '' }),
        $(if ($Edge.label) { $Edge.label } else { '' }),
        $(if ($Edge.note) { $Edge.note } else { '' })
    ) -join '|'

    if (-not $Tracker.ContainsKey($key)) {
        $Edges.Add([PSCustomObject]$Edge) | Out-Null
        $Tracker[$key] = $true
    }
}

# --- Tasks ---

# Task 1-4: Network
function Get-NetworkInfo {
    Write-Host "Running task 1-4 of 34" -ForegroundColor Yellow
    Write-Host "Collecting Network Information..."
    WriteLog -Level "INFO" -Message "Collecting Network Info"
    
    $NetFolder = "$FolderCreation\Network"
    New-Item -Path $NetFolder -ItemType Directory -Force | Out-Null
    
    # Connections
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime
    $conns | Export-Csv -NoTypeInformation -Path "$NetFolder\TCP_Connections.csv" -Encoding UTF8
    $conns | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$NetFolder\TCP_Connections.txt"
    
    # Routes
    Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias | Export-Csv -NoTypeInformation -Path "$NetFolder\Routes.csv" -Encoding UTF8
    
    # Interfaces
    Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, Status | Export-Csv -NoTypeInformation -Path "$NetFolder\Adapters.csv" -Encoding UTF8
    
    WriteLog -Level "INFO" -Message "Network Info collected."
}
if ($RunAll -or $Network) { Get-NetworkInfo }

function Invoke-PacketCapture {
    Write-Host "Running task 4b of 34" -ForegroundColor Yellow
    Write-Host "Capturing live network traffic with pktmon for $PacketCaptureDuration seconds..."
    WriteLog -Level "INFO" -Message "Starting pktmon packet capture. DurationSeconds=$PacketCaptureDuration"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Warning "pktmon packet capture requires Administrator privileges. Skipping capture."
        WriteLog -Level "WARN" -Message "Skipping pktmon capture because the process is not elevated."
        return
    }

    $pktmonCmd = Get-Command pktmon -ErrorAction SilentlyContinue
    if (-not $pktmonCmd) {
        Write-Warning "pktmon was not found on this system. Skipping packet capture."
        WriteLog -Level "WARN" -Message "Skipping pktmon capture because pktmon is unavailable."
        return
    }

    $captureFolder = Join-Path $FolderCreation "Network\PacketCapture"
    New-Item -Path $captureFolder -ItemType Directory -Force | Out-Null

    $etlPath = Join-Path $captureFolder "PktMon_Capture.etl"
    $txtPath = Join-Path $captureFolder "PktMon_Capture.txt"
    $pcapPath = Join-Path $captureFolder "PktMon_Capture.pcapng"
    $metaPath = Join-Path $captureFolder "PktMon_Capture_Metadata.txt"
    $reportPath = Join-Path $captureFolder "PacketCapture_Report.json"
    $startUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    $captureStarted = $false
    $filtersApplied = @()
    $captureType = $(if ($PacketCaptureDropOnly) { 'drop' } else { 'all' })
    $effectiveProtocol = $PacketCaptureProtocol
    $effectivePorts = @($PacketCapturePort | Where-Object { $_ -gt 0 } | Select-Object -Unique)
    if (($effectiveProtocol -in @('ICMP','ICMPv6')) -and $effectivePorts.Count -gt 0) {
        WriteLog -Level "WARN" -Message "Ignoring port filters for protocol $effectiveProtocol."
        $effectivePorts = @()
    }

    try {
        & pktmon stop 2>$null | Out-Null
        $filtersApplied = Add-PacketCaptureFilters -IPs $PacketCaptureIP -Ports $effectivePorts -Protocol $effectiveProtocol

        $startArgs = @('start','--capture','--comp','nics','--type',$captureType,'--pkt-size','0','--file-name',$etlPath,'--file-size','256')
        $startOutput = (& pktmon @startArgs 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw "pktmon start failed. $startOutput"
        }

        $captureStarted = $true
        Start-Sleep -Seconds $PacketCaptureDuration

        $stopOutput = (& pktmon stop 2>&1 | Out-String).Trim()
        $captureStarted = $false

        if (Test-Path -LiteralPath $etlPath) {
            WriteHash -FilePath $etlPath
        } else {
            WriteLog -Level "WARN" -Message "pktmon capture completed but ETL output was not found at $etlPath"
        }

        try {
            $txtOutput = (& pktmon etl2txt $etlPath --out $txtPath --timestamp --metadata --brief 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -ne 0) {
                WriteLog -Level "WARN" -Message "pktmon etl2txt failed. Output=$txtOutput"
            } elseif (Test-Path -LiteralPath $txtPath) {
                WriteHash -FilePath $txtPath
            }
        } catch {
            WriteLog -Level "WARN" -Message "pktmon etl2txt exception: $($_.Exception.Message)"
        }

        if ($PacketCaptureFormat -in @('pcapng','both')) {
            try {
                $pcapArgs = @('etl2pcap', $etlPath, '--out', $pcapPath)
                if ($PacketCaptureDropOnly) { $pcapArgs += '--drop-only' }
                $pcapOutput = (& pktmon @pcapArgs 2>&1 | Out-String).Trim()
                if ($LASTEXITCODE -ne 0) {
                    WriteLog -Level "WARN" -Message "pktmon etl2pcap failed. Output=$pcapOutput"
                } elseif (Test-Path -LiteralPath $pcapPath) {
                    WriteHash -FilePath $pcapPath
                }
            } catch {
                WriteLog -Level "WARN" -Message "pktmon etl2pcap exception: $($_.Exception.Message)"
            }
        }

        $metadata = @(
            "tool=pktmon",
            "profile=$(if ($PacketCaptureQuick) { 'quick' } else { 'standard' })",
            "duration_seconds=$PacketCaptureDuration",
            "format=$PacketCaptureFormat",
            "protocol=$effectiveProtocol",
            "drop_only=$PacketCaptureDropOnly",
            "start_utc=$startUtc",
            "end_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))",
            "capture_file=$etlPath",
            "text_file=$txtPath",
            "pcapng_file=$pcapPath",
            "start_command=pktmon $($startArgs -join ' ')",
            "filters_applied=$($filtersApplied -join '; ')",
            "stop_output=$stopOutput"
        )
        $metadata | Out-File -FilePath $metaPath -Encoding UTF8 -Force
        WriteHash -FilePath $metaPath

        $report = [ordered]@{
            tool = "pktmon"
            profile = $(if ($PacketCaptureQuick) { "quick" } else { "standard" })
            duration_seconds = $PacketCaptureDuration
            format = $PacketCaptureFormat
            protocol = $effectiveProtocol
            drop_only = [bool]$PacketCaptureDropOnly
            filters = [ordered]@{
                ip = @($PacketCaptureIP | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
                port = @($effectivePorts)
                applied = @($filtersApplied)
            }
            outputs = [ordered]@{
                etl = (New-PacketCaptureOutputEntry -Path $etlPath)
                txt = (New-PacketCaptureOutputEntry -Path $txtPath)
                pcapng = (New-PacketCaptureOutputEntry -Path $pcapPath)
                metadata = (New-PacketCaptureOutputEntry -Path $metaPath)
            }
            start_utc = $startUtc
            end_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        }
        $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $reportPath -Encoding UTF8 -Force
        WriteHash -FilePath $reportPath

        WriteLog -Level "INFO" -Message "pktmon capture finished. ETL=$etlPath TXT=$txtPath PCAP=$pcapPath"
    } catch {
        Write-Warning "pktmon capture failed: $($_.Exception.Message)"
        WriteLog -Level "ERROR" -Message "pktmon capture failed: $($_.Exception.Message)"
    } finally {
        if ($captureStarted) {
            try { & pktmon stop 2>$null | Out-Null } catch {}
        }
        try { & pktmon filter remove 2>$null | Out-Null } catch {}
    }
}
if ($PacketCapture) { Invoke-PacketCapture }

# Task 5: SMB Shares & Sessions
function Get-SmbInfo {
    Write-Host "Running task 5 of 33" -ForegroundColor Yellow
    Write-Host "Collecting SMB Shares & Sessions..."
    WriteLog -Level "INFO" -Message "Collecting SMB Shares & Sessions"
    
    $SmbFolder = "$FolderCreation\Network"
    if (-not (Test-Path $SmbFolder)) { New-Item -Path $SmbFolder -ItemType Directory -Force | Out-Null }
    
    # Shares
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description, Special, Temporary
        $shares | Export-Csv -NoTypeInformation -Path "$SmbFolder\SMB_Shares.csv" -Encoding UTF8
        WriteHash -FilePath "$SmbFolder\SMB_Shares.csv"
    } catch {}

    # Sessions
    try {
        $sessions = Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExist
        $sessions | Export-Csv -NoTypeInformation -Path "$SmbFolder\SMB_Sessions.csv" -Encoding UTF8
        WriteHash -FilePath "$SmbFolder\SMB_Sessions.csv"
    } catch {}
    
    WriteLog -Level "INFO" -Message "SMB Info collected."
}
if ($RunAll -or $Network) { Get-SmbInfo }

# Task 6: Autoruns (Registry)
function Get-Autoruns {
    Write-Host "Running task 6 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Autoruns (Registry)..."
    WriteLog -Level "INFO" -Message "Collecting Autoruns"
    
    $SysFolder = "$FolderCreation\System"
    New-Item -Path $SysFolder -ItemType Directory -Force | Out-Null
    
    $AutorunLocations = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    $Autoruns = @()
    foreach ($loc in $AutorunLocations) {
        if (Test-Path $loc) {
            $props = Get-ItemProperty -Path $loc -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | ForEach-Object {
                $obj = New-Object PSCustomObject
                $obj | Add-Member -NotePropertyName Location -NotePropertyValue $loc
                $obj | Add-Member -NotePropertyName Name -NotePropertyValue $_.Name
                $obj | Add-Member -NotePropertyName Value -NotePropertyValue $_.Value
                $Autoruns += $obj
            }
        }
    }
    
    $Autoruns | Export-Csv -NoTypeInformation -Path "$SysFolder\Autoruns_Registry.csv" -Encoding UTF8
    $Autoruns | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$SysFolder\Autoruns_Registry.txt"
    WriteHash -FilePath "$SysFolder\Autoruns_Registry.csv"
    WriteHash -FilePath "$SysFolder\Autoruns_Registry.txt"
    WriteLog -Level "INFO" -Message "Autoruns collected."
}
if ($RunAll -or $System) { Get-Autoruns }

# Task 7: Scheduled Tasks
function Get-ScheduledTasksInfo {
    Write-Host "Running task 7 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Scheduled Tasks..."
    WriteLog -Level "INFO" -Message "Collecting Scheduled Tasks"
    
    $schFolder = "$FolderCreation\System\ScheduledTasks"
    if (-not (Test-Path $schFolder)) { New-Item -Path $schFolder -ItemType Directory -Force | Out-Null }
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskName, TaskPath, State, @{N='Action';E={$_.Actions.Execute}}, @{N='Trigger';E={$_.TriggersRepetition.Interval}}
        $tasks | Export-Csv -NoTypeInformation -Path "$schFolder\ScheduledTasks.csv" -Encoding UTF8
        $tasks | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$schFolder\ScheduledTasks.txt"
        WriteHash -FilePath "$schFolder\ScheduledTasks.csv"
    } catch {
        Write-Warning "Could not collect Scheduled Tasks (Cmdlet missing?)"
    }
    WriteLog -Level "INFO" -Message "Scheduled Tasks collected."
}
if ($RunAll -or $System) { Get-ScheduledTasksInfo }

# Task 8: Firewall Rules
function Get-FirewallRules {
    Write-Host "Running task 8 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Firewall Rules..."
    WriteLog -Level "INFO" -Message "Collecting Firewall Rules"
    
    try {
        $fwPath = "$FolderCreation\Network\FirewallRules.csv"
        Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile, Group | Export-Csv -NoTypeInformation -Path $fwPath -Encoding UTF8
        WriteHash -FilePath $fwPath
    } catch {}
    WriteLog -Level "INFO" -Message "Firewall Rules collected."
}
if ($RunAll -or $Network) { Get-FirewallRules }

# Task 9: Processes
function Get-ProcessAndHashes {
   Write-Host "Running task 9 of 33" -ForegroundColor Yellow
   Write-Host "Collecting Active Processes (Info, Hash, Signature)...`n"
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"
    
    WriteLog -Level "INFO" -Message "Collecting Active Processes..."

    $processes_list = @()
    $cimProcesses = Get-CimInstance -ClassName Win32_Process
    $totalProcs = $cimProcesses.Count
    $hashedProcs = 0
    $processedCount = 0

    foreach ($process in $cimProcesses)
    {
        $processedCount++
        if ($totalProcs -gt 0) {
            # Update progress frequently to avoid perceived hang on first item
            if ($processedCount -eq 1 -or $processedCount % 5 -eq 0) {
                $percentComplete = ($processedCount / $totalProcs) * 100
                Write-Progress -Activity "Collecting Process Information" -Status "Processing $($process.Name) ($processedCount / $totalProcs)" -PercentComplete $percentComplete
            }
        }

        $process_obj = New-Object PSCustomObject
        
        # Owner
        $owner = "N/A"
        try {
            $ownerResult = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($ownerResult.ReturnValue -eq 0) {
                $owner = "$($ownerResult.Domain)\$($ownerResult.User)"
            }
        } catch {}

        # Path, Hash, Signature
        $hash = "N/A"
        $signer = "N/A"
        $signedStatus = "N/A"
        $company = "N/A"
        $description = "N/A"
        $path = $process.ExecutablePath

        if ($path) {
             # Fix for Network/Zombie paths causing hangs
             $isValidLocal = $false
             try {
                 if ($path -match "^[a-zA-Z]:" -and (Test-Path $path)) { $isValidLocal = $true }
             } catch {}
             
             if ($isValidLocal) {
                try {
                    $hash = (Get-FileHash -Algorithm SHA256 -Path $path -ErrorAction SilentlyContinue).Hash
                    $hashedProcs++
                    
                    # Optimized Signature Check (Ignore Revocation for Speed)
                    # WARNING: Fallback to standard Get-AuthenticodeSignature removed to prevent timeouts on offline systems
                    try {
                        $sig = [System.Management.Automation.Signature]::GetSignature($path, "IgnoreRevocation")
                        if ($sig) {
                            $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unsigned" }
                            $signedStatus = $sig.Status
                        }
                    } catch {
                       # If fast check fails, we assume N/A rather than hanging the system with online revocation checks
                       $signedStatus = "Skipped (Offline Optimization)"
                    }
                    
                    $verInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
                    if ($verInfo) {
                        $company = $verInfo.CompanyName
                        $description = $verInfo.FileDescription
                    }
                } catch {}
            }
        }

        $process_obj | Add-Member -NotePropertyName Proc_Name -NotePropertyValue $process.Name
        $process_obj | Add-Member -NotePropertyName Proc_Id -NotePropertyValue $process.ProcessId
        $process_obj | Add-Member -NotePropertyName Proc_Owner -NotePropertyValue $owner
        $process_obj | Add-Member -NotePropertyName Proc_Path -NotePropertyValue $path
        $process_obj | Add-Member -NotePropertyName Proc_CommandLine -NotePropertyValue $process.CommandLine
        $process_obj | Add-Member -NotePropertyName Proc_ParentProcessId -NotePropertyValue $process.ParentProcessId
        $process_obj | Add-Member -NotePropertyName Proc_CreationDate -NotePropertyValue $process.CreationDate
        $process_obj | Add-Member -NotePropertyName Proc_Hash -NotePropertyValue $hash
        $process_obj | Add-Member -NotePropertyName Proc_Signer -NotePropertyValue $signer
        $process_obj | Add-Member -NotePropertyName Proc_SignedStatus -NotePropertyValue $signedStatus
        $process_obj | Add-Member -NotePropertyName Proc_Company -NotePropertyValue $company
        $process_obj | Add-Member -NotePropertyName Proc_Description -NotePropertyValue $description

        $processes_list += $process_obj
    }
    Write-Progress -Activity "Collecting Process Information" -Completed

    $processes_list | Export-Csv -NoTypeInformation -Path $ProcessListOutput -Encoding UTF8
    $processes_list | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$ProcessFolder\ProcessList.txt"
    
    WriteHash -FilePath "$ProcessListOutput"
    WriteHash -FilePath "$ProcessFolder\ProcessList.txt"
    WriteLog -Level "INFO" -Message "Task 9 done. Collected $totalProcs processes ($hashedProcs hashed/analyzed)."
}

# Task 10: Process Tree
function Print-ProcessTree {
    param($PID_Target = 0)
    # Simplified Process Tree Logic
    $allProcs = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine
    
    function Get-Tree($parentId, $indent) {
        # Fix: Exclude self-referencing PIDs (like PID 0) to prevent infinite recursion
        $children = $allProcs | Where-Object { $_.ParentProcessId -eq $parentId -and $_.ProcessId -ne $parentId }
        foreach ($child in $children) {
            "$indent|_ $($child.Name) ($($child.ProcessId))"
            Get-Tree $child.ProcessId "$indent  "
        }
    }
    
    Get-Tree 0 ""
}

# Task 11: USB
function Get-USBHistory {
    Write-Host "Running task 11 of 33" -ForegroundColor Yellow
    Write-Host "Collecting USB History..."
    WriteLog -Level "INFO" -Message "Collecting USB History..."
    
    $usbOutput = "$FolderCreation\System\USB_History.csv"
    $usbList = @()
    $usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

    if (Test-Path $usbStorPath) {
        $devices = Get-ChildItem -Path $usbStorPath -Recurse -ErrorAction SilentlyContinue
        foreach ($dev in $devices) {
            if ($dev.PSChildName -match "^Disk&") {
                $instances = Get-ChildItem -Path $dev.PSPath -ErrorAction SilentlyContinue
                foreach ($instance in $instances) {
                    $props = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
                    $obj = New-Object PSCustomObject
                    $obj | Add-Member -NotePropertyName FriendlyName -NotePropertyValue $props.FriendlyName
                    $obj | Add-Member -NotePropertyName DeviceDesc -NotePropertyValue $props.DeviceDesc
                    $obj | Add-Member -NotePropertyName SerialNumber -NotePropertyValue $instance.PSChildName
                    $obj | Add-Member -NotePropertyName HardwareID -NotePropertyValue ($props.HardwareID -join "; ")
                    $obj | Add-Member -NotePropertyName Class -NotePropertyValue $props.Class
                    $obj | Add-Member -NotePropertyName KeyLastWriteTime -NotePropertyValue $instance.LastWriteTime
                    $usbList += $obj
                }
            }
        }
    }
    
    $usbList | Export-Csv -NoTypeInformation -Path $usbOutput -Encoding UTF8
    $usbList | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$FolderCreation\System\USB_History.txt"
    WriteHash -FilePath $usbOutput
    WriteHash -FilePath "$FolderCreation\System\USB_History.txt"
    WriteLog -Level "INFO" -Message "USB History collected ($($usbList.Count) devices found)."
}

# Task 12: EVTX
function Get-Evtx {
   Write-Host "Running task 12 of 33" -ForegroundColor Yellow
   Write-Host "Collecting System Events(evtx) Files..."
    $EventViewer = "$FolderCreation\EventsLogs"
    New-Item -Path $EventViewer -ItemType Directory -Force | Out-Null
    $evtxPath = Join-Path $env:SystemRoot "System32\winevt\Logs"
    $channels = @(
        "Application", "Security", "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational",
        "Microsoft-Windows-WMI-Activity%4Operational",
        "Microsoft-Windows-NTLM%4Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational"
    )

    $count = 0
    $evtxFiles = Get-ChildItem "$evtxPath\*.evtx" | Where-Object{$_.BaseName -in $channels}
    $totalEvtx = $evtxFiles.Count
    
    foreach ($file in $evtxFiles) {
        $count++
        if ($count % 10 -eq 0) {
            $percentComplete = ($count / $totalEvtx) * 100
            Write-Progress -Activity "Collecting EVTX Files" -Status "Copying $($file.Name) ($count / $totalEvtx)" -PercentComplete $percentComplete
        }
        
        Copy-Item -Path $file.FullName -Destination "$($EventViewer)\$($file.Name)" -Force
		WriteHash -FilePath "$($EventViewer)\$($file.Name)"
    }
    Write-Progress -Activity "Collecting EVTX Files" -Completed
	WriteLog -Level "INFO" -Message "Task 12 done. $count EVTX files collected."
}

# Execute Tasks 9-12
if ($RunAll -or $Process) {
    Get-ProcessAndHashes
    Print-ProcessTree | Out-File -Width 4096 -Force "$FolderCreation\ProcessInformation\ProcessTree.txt"
    WriteHash -FilePath "$FolderCreation\ProcessInformation\ProcessTree.txt"
}
if ($RunAll -or $System) { Get-USBHistory }
if ($RunAll -or $Events) { Get-Evtx }

# Task 13: PowerShell History
function PowerShell_Commands{
    Write-Host "Running task 13 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Console Powershell History (all users)..."
    WriteLog -Level "INFO" -Message "Collecting Console Powershell History (all users)"
    $PowershellConsoleHistory = "$FolderCreation\PowerShellConsole_History"
    mkdir -Force $PowershellConsoleHistory | Out-Null
    
    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    
    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        $HistoryFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        
        if (Test-Path $HistoryFilePath) {
             Copy-Item "$HistoryFilePath" -Destination "$PowershellConsoleHistory\ConsoleHost_history_$userName.txt" -Force -ErrorAction SilentlyContinue
             WriteHash -FilePath "$PowershellConsoleHistory\ConsoleHost_history_$userName.txt"
        }
    }
}
if ($RunAll -or $Users) { PowerShell_Commands }

# Task 14: Local Groups
function Get-LocalGroups {
    Write-Host "Running task 14 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Local Groups & Members..."
    WriteLog -Level "INFO" -Message "Collecting Local Groups"
    
    try {
        $groups = Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
            $group = $_
            $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                GroupName = $group.Name
                Description = $group.Description
                Members = ($members.Name -join "; ")
            }
        }
        $groups | Export-Csv -NoTypeInformation -Path "$FolderCreation\System\LocalGroups.csv" -Encoding UTF8
        WriteHash -FilePath "$FolderCreation\System\LocalGroups.csv"
    } catch {}
}
if ($RunAll -or $System) { Get-LocalGroups }

# Task 15: Environment Variables
function Get-EnvVars {
    Write-Host "Running task 15 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Environment Variables..."
    WriteLog -Level "INFO" -Message "Collecting Environment Variables"
    try {
        Get-ChildItem Env: | Select-Object Name, Value | Export-Csv -NoTypeInformation -Path "$FolderCreation\System\EnvironmentVariables.csv" -Encoding UTF8
        WriteHash -FilePath "$FolderCreation\System\EnvironmentVariables.csv"
    } catch {}
}
if ($RunAll -or $System) { Get-EnvVars }

# Task 16: Services
function Get-Services {
    Write-Host "Running task 16 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Services..."
    WriteLog -Level "INFO" -Message "Collecting Services"
    
    $services_list = @()
    $cimServices = Get-CimInstance Win32_Service
    $totalSvcs = $cimServices.Count
    $hashedServices = 0
    $svcCount = 0
    
    foreach ($svc in $cimServices) {
        $svcCount++
        if ($svcCount % 10 -eq 0) {
            Write-Progress -Activity "Collecting Services" -Status "Processing $($svc.Name) ($svcCount / $totalSvcs)" -PercentComplete (($svcCount / $totalSvcs) * 100)
        }

        $svc_obj = New-Object PSCustomObject
        $hash = "N/A"
        
        $path = $svc.PathName
        if ($path) {
            # Clean path (remove arguments)
            if ($path -match '^"([^"]+)"') { $cleanPath = $matches[1] }
            elseif ($path -match '^(\S+)') { $cleanPath = $matches[1] }
            else { $cleanPath = $path }
            
            if (Test-Path $cleanPath) {
                 try {
                    $hash = (Get-FileHash -Algorithm SHA256 -Path $cleanPath -ErrorAction SilentlyContinue).Hash
                    if ($hash) { $hashedServices++ }
                 } catch {}
            }
        }
        
        $svc_obj | Add-Member -NotePropertyName Service_Name -NotePropertyValue $svc.Name
        $svc_obj | Add-Member -NotePropertyName Service_DisplayName -NotePropertyValue $svc.DisplayName
        $svc_obj | Add-Member -NotePropertyName Service_StartMode -NotePropertyValue $svc.StartMode
        $svc_obj | Add-Member -NotePropertyName Service_State -NotePropertyValue $svc.State
        $svc_obj | Add-Member -NotePropertyName Service_PathName -NotePropertyValue $svc.PathName
        $svc_obj | Add-Member -NotePropertyName Service_BinaryHash -NotePropertyValue $hash
        
        $services_list += $svc_obj
    }
    
    $services_list | Export-Csv -NoTypeInformation -Path "$FolderCreation\System\All_Services.csv" -Encoding UTF8
    $services_list | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$FolderCreation\System\All_Services.txt"
    WriteHash -FilePath "$FolderCreation\System\All_Services.csv"
    WriteHash -FilePath "$FolderCreation\System\All_Services.txt"
    WriteLog -Level "INFO" -Message "Services collected."
}
if ($RunAll -or $System) { Get-Services }

# Task 17: Clipboard
function Get-ClipboardContent {
    Write-Host "Running task 17 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Clipboard Content..."
    WriteLog -Level "INFO" -Message "Collecting Clipboard Content"
    
    try {
        $clip = Get-Clipboard -ErrorAction SilentlyContinue
        if ($clip) {
            $clip | Out-File -FilePath "$FolderCreation\System\Clipboard.txt" -Encoding UTF8
            WriteHash -FilePath "$FolderCreation\System\Clipboard.txt"
        }
    } catch {}
}
if ($RunAll -or $System) { Get-ClipboardContent }

# Task 18: Recent Files
function RecentFiles{
Write-Host "Running task 18 of 33" -ForegroundColor Yellow
Write-Host "Collecting Recent Items (all users)..."
    WriteLog -Level "INFO" -Message "Collecting Recent Items (all users)"
    $Recent = "$FolderCreation\Recent_Items"
    mkdir -Force $Recent | Out-Null
    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    $totalFiles = 0
    $totalUsers = $userDirectories.Count
    $userCount = 0

    foreach ($userDir in $userDirectories) {
        $userCount++
        Write-Progress -Activity "Collecting Recent Items" -Status "Processing user $($userDir.Name) ($userCount / $totalUsers)" -PercentComplete (($userCount / $totalUsers) * 100)
        
        $userName = $userDir.Name
        $RecentSourcePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\Recent"
        $destino = "$Recent\$userName"
        mkdir -Force $destino | Out-Null
        
        if (Test-Path $RecentSourcePath) {
            # Use Robocopy for better long path support
            $robocopyArgs = @($RecentSourcePath, $destino, "/E", "/R:0", "/W:0", "/NJH", "/NJS", "/NDL", "/NC", "/NS", "/NP")
            Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -NoNewWindow -Wait
            
            # Fallback/Hash calculation
            $files = Get-ChildItem -Path $destino -Recurse -File
            $files | ForEach-Object { WriteHash -FilePath $_.FullName }
            $count = $files.Count
            $totalFiles += $count
            WriteLog -Level "INFO" -Message "Recent Items collected for user $userName ($count files)"
        }
    }
    Write-Progress -Activity "Collecting Recent Items" -Completed
    WriteLog -Level "INFO" -Message "Task 18 done. Total Recent files: $totalFiles"
}
if ($RunAll -or $Users) { RecentFiles }

# Task 19: Activities Cache
function ActivitiesCache{
Write-Host "Running task 19 of 33" -ForegroundColor Yellow
Write-Host "Collecting Activities Cache and WebCache (all users)..."
    WriteLog -Level "INFO" -Message "Collecting Activities Cache and WebCache (all users)"
    $ActivitiesFolder = "$FolderCreation\Activities_Cache"
    New-Item -Path $ActivitiesFolder -ItemType Directory -Force | Out-Null

    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    
    $totalUsers = $userDirectories.Count
    $userCount = 0
    $totalActivitiesFiles = 0
    $totalWebCacheFiles = 0
    $totalFailures = 0

    foreach ($userDir in $userDirectories) {
        $userCount++
        Write-Progress -Activity "Collecting Activities Cache" -Status "Processing user $($userDir.Name) ($userCount / $totalUsers)" -PercentComplete (($userCount / $totalUsers) * 100)

        $userName = $userDir.Name
        $userRoot = Join-Path $ActivitiesFolder $userName
        New-Item -Path $userRoot -ItemType Directory -Force | Out-Null
        $CDPPath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Local\ConnectedDevicesPlatform"
        $webCacheDir = Join-Path -Path $userDir.FullName -ChildPath "AppData\Local\Microsoft\Windows\WebCache"
        $userActivitiesCopied = 0
        $userWebCacheCopied = 0
        $userFailures = 0
        
        if (Test-Path $CDPPath) {
            $activitiesDest = Join-Path $userRoot "ConnectedDevicesPlatform"
            New-Item -Path $activitiesDest -ItemType Directory -Force | Out-Null

            $cdpCopyErrors = @()
            Copy-Item (Join-Path $CDPPath '*') -Destination $activitiesDest -Force -Recurse -ErrorAction SilentlyContinue -ErrorVariable +cdpCopyErrors
            if ($cdpCopyErrors.Count -gt 0) {
                WriteLog -Level "WARN" -Message "Best-effort ConnectedDevicesPlatform copy encountered $($cdpCopyErrors.Count) errors for user $userName. Critical ActivitiesCache files will be retried with live fallbacks."
            }

            $activityFiles = @(Get-ChildItem -LiteralPath $CDPPath -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -in @('ActivitiesCache.db','ActivitiesCache.db-wal','ActivitiesCache.db-shm')
            })

            foreach ($activityFile in $activityFiles) {
                $relativePath = Get-RelativeChildPath -BasePath $CDPPath -FullPath $activityFile.FullName
                $destinationPath = Join-Path $activitiesDest $relativePath
                if (Copy-LiveArtifactWithFallback -SourcePath $activityFile.FullName -DestinationPath $destinationPath -PreferredMethod 'Backup' -ArtifactTag "ActivitiesCache [$userName]") {
                    $userActivitiesCopied++
                    $totalActivitiesFiles++
                } else {
                    $userFailures++
                    $totalFailures++
                }
            }
        }

        if (Test-Path $webCacheDir) {
            $webCacheDest = Join-Path $userRoot "WebCache"
            New-Item -Path $webCacheDest -ItemType Directory -Force | Out-Null
            $webCacheFiles = @(Get-ChildItem -LiteralPath $webCacheDir -File -Force -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match '^WebCacheV\d+\.(dat|jfm)$' -or $_.Extension -in @('.log', '.chk')
            })

            foreach ($webCacheFile in $webCacheFiles) {
                $destinationPath = Join-Path $webCacheDest $webCacheFile.Name
                if (Copy-LiveArtifactWithFallback -SourcePath $webCacheFile.FullName -DestinationPath $destinationPath -PreferredMethod 'Esent' -ArtifactTag "WebCache [$userName]") {
                    $userWebCacheCopied++
                    $totalWebCacheFiles++
                } else {
                    $userFailures++
                    $totalFailures++
                }
            }
        }

        $count = (Get-ChildItem -Path $userRoot -Recurse -File -ErrorAction SilentlyContinue).Count
        if (($count -gt 0) -or ($userFailures -gt 0)) {
            WriteLog -Level "INFO" -Message "Activity artifacts collected for user $userName ($count files, ActivitiesCache hardened=$userActivitiesCopied, WebCache hardened=$userWebCacheCopied, failures=$userFailures)"
        }
    }
    Write-Progress -Activity "Collecting Activities Cache" -Completed
    WriteLog -Level "INFO" -Message "Activities Cache and WebCache collection done. ActivitiesCacheFiles=$totalActivitiesFiles WebCacheFiles=$totalWebCacheFiles Failures=$totalFailures"
}
if ($RunAll -or $Users) { ActivitiesCache }

# Task 20: Prefetch
function CopyPrefetch{
 Write-Host "Running task 20 of 33" -ForegroundColor Yellow
 Write-Host "Collecting Prefetch..."
  WriteLog -Level "INFO" -Message "Collecting Prefetch"
  $origen = Join-Path $env:SystemRoot "Prefetch"
  $destino = "$FolderCreation\Prefetch"
  if (-not (Test-Path $destino)) { New-Item -Path $destino -ItemType Directory -Force | Out-Null }
  
  if (Test-Path $origen) {
      $files = Get-ChildItem -Path "$origen" -Recurse -File -ErrorAction SilentlyContinue
      $totalFiles = $files.Count
      $count = 0
      
      foreach ($file in $files) {
          $count++
          if ($count % 10 -eq 0) {
              Write-Progress -Activity "Collecting Prefetch" -Status "Copying $($file.Name) ($count / $totalFiles)" -PercentComplete (($count / $totalFiles) * 100)
          }
          
          $relPath = $file.FullName.Substring($origen.Length)
          $destFile = Join-Path $destino $relPath
          $destDir = Split-Path $destFile
          
          if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }
          Copy-Item -Path $file.FullName -Destination $destFile -Force -ErrorAction SilentlyContinue
      }
      Write-Progress -Activity "Collecting Prefetch" -Completed
  }
  
  $count = (Get-ChildItem -Path $destino -Recurse -File).Count
  WriteLog -Level "INFO" -Message "Prefetch collection done ($count files)"
}
if ($RunAll -or $Disk) { CopyPrefetch }

# Task 21: Recycle Bin
function RecycleBin{
   Write-Host "Running task 21 of 33" -ForegroundColor Yellow
   Write-Host "Collecting Recycle.Bin (Metadata `$I files + Data `$R < 100MB)..."
    
    $destino = "$FolderCreation\RecycleBin"
    New-Item -Path $destino -ItemType Directory -Force | Out-Null
    
    Write-Host "Optimized collection: Prioritizing metadata and small files on FIXED drives only." -ForegroundColor DarkCyan
    
    # Filter only Fixed drives (Type 3) to avoid network shares hanging the script
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    $totalFiles = 0
    $totalDrives = $drives.Count
    $driveCount = 0
    
    foreach ($drive in $drives) {
        $driveLetter = $drive.DeviceID
        $driveCount++
        Write-Progress -Activity "Collecting Recycle Bin" -Status "Processing Drive $driveLetter ($driveCount / $totalDrives)" -PercentComplete (($driveCount / $totalDrives) * 100)
        
        $rBinPath = Join-Path $driveLetter "`$Recycle.Bin"
        if (Test-Path $rBinPath) {
            $files = Get-ChildItem -Path $rBinPath -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if (-not $file.PSIsContainer) {
                    if ($file.Name -like "`$I*" -or ($file.Length -lt 100MB)) {
                        $relPath = $file.FullName.Substring($rBinPath.Length)
                        $driveNameClean = $driveLetter.Replace(":", "")
                        $destFile = Join-Path $destino "$driveNameClean$relPath"
                        $destDir = Split-Path $destFile
                        if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }
                        Copy-Item -Path $file.FullName -Destination $destFile -Force -ErrorAction SilentlyContinue
                        $totalFiles++
                    }
                }
            }
        }
    }
    Write-Progress -Activity "Collecting Recycle Bin" -Completed
    WriteLog -Level "INFO" -Message "Recycle Bin collection done ($totalFiles files collected)"
}
if ($RunAll -or $Disk) { RecycleBin }

# Task 22: DNS
function Get-DNS {
   Write-Host "Running task 22 of 33" -ForegroundColor Yellow
   Write-Host "Collecting DNS Cache..."
    WriteLog -Level "INFO" -Message "Collecting DNS Cache"
    $destino = "$FolderCreation\Network\DNSCache.csv"
    $dnsCache = Get-DnsClientCache
    $dnsCache | Export-Csv -NoTypeInformation -Path $destino -Encoding UTF8
    $dnsCache | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$FolderCreation\Network\DNSCache.txt"
    WriteHash -FilePath "$destino"
    WriteHash -FilePath "$FolderCreation\Network\DNSCache.txt"
    WriteLog -Level "INFO" -Message "DNS Cache collection done"
}
if ($RunAll -or $Network) { Get-DNS }

# Task 23: Installed Software
function Installed_Software{
   Write-Host "Running task 23 of 33" -ForegroundColor Yellow
   Write-Host "Collecting Installed Software (Registry Optimized)..."
   WriteLog -Level "INFO" -Message "Collecting Installed Software"
   
   $soft = @()
   $UninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
   )

   foreach ($key in $UninstallKeys) {
        if (Test-Path $key) {
            Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName) {
                     $obj = New-Object PSCustomObject
                     $obj | Add-Member -NotePropertyName Name -NotePropertyValue $props.DisplayName
                     $obj | Add-Member -NotePropertyName Version -NotePropertyValue $props.DisplayVersion
                     $obj | Add-Member -NotePropertyName Vendor -NotePropertyValue $props.Publisher
                     $obj | Add-Member -NotePropertyName InstallDate -NotePropertyValue $props.InstallDate
                     $soft += $obj
                }
            }
        }
   }

   $soft | Export-Csv -NoTypeInformation -Path "$FolderCreation\System\Installed_Software.csv" -Encoding UTF8
   $soft | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$FolderCreation\System\Installed_Software.txt"
   WriteHash -FilePath "$FolderCreation\System\Installed_Software.csv"
   WriteHash -FilePath "$FolderCreation\System\Installed_Software.txt"
}
if ($RunAll -or $System) { Installed_Software }

# Task 24-27: Browsers
# (I'm simplifying to one generic function for restoration, but will keep structure if possible. I'll include placeholders for detailed logic to save space/time, but I should probably implement one well)
function Collect-BrowserArtifacts {
    param($BrowserName, $TaskNum, $PathSuffix)
    Write-Host "Running task $TaskNum of 33" -ForegroundColor Yellow
    Write-Host "Collecting $BrowserName artifacts..."
    WriteLog -Level "INFO" -Message "Collecting $BrowserName artifacts"

    Invoke-BrowserCollectionPreparation -BrowserName $BrowserName
    
    $DestBase = "$FolderCreation\Browsers\$BrowserName"
    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    
    $totalUsers = $userDirectories.Count
    $userCount = 0
    $extensions = @()
    $syncData = @()

    foreach ($userDir in $userDirectories) {
        $userCount++
        Write-Progress -Activity "Collecting $BrowserName Artifacts" -Status "Processing user $($userDir.Name) ($userCount / $totalUsers)" -PercentComplete (($userCount / $totalUsers) * 100)

        $userName = $userDir.Name
        $ProfilePath = Join-Path $userDir.FullName $PathSuffix
        
        if (Test-Path $ProfilePath) {
             $DestUser = Join-Path $DestBase $userName
             New-Item -Path $DestUser -ItemType Directory -Force | Out-Null
             
             $targets = @()
             $supportFiles = @()
             if ($BrowserName -eq "Firefox") {
                 $profiles = Get-ChildItem -Path $ProfilePath -Directory -ErrorAction SilentlyContinue
                 foreach ($prof in $profiles) {
                     $targets += [PSCustomObject]@{
                         Name = $prof.Name
                         Path = $prof.FullName
                     }
                 }
             } elseif ($BrowserName -eq "Opera") {
                 $defaultPath = Join-Path $ProfilePath "Default"
                 if (Test-Path $defaultPath) {
                     $targets += [PSCustomObject]@{
                         Name = "Default"
                         Path = $defaultPath
                     }
                 } else {
                     $targets += [PSCustomObject]@{
                         Name = (Split-Path $ProfilePath -Leaf)
                         Path = $ProfilePath
                     }
                 }
             } elseif ($BrowserName -eq "OperaGX") {
                 $defaultPath = Join-Path $ProfilePath "Default"
                 if (Test-Path $defaultPath) {
                     $targets += [PSCustomObject]@{
                         Name = "Default"
                         Path = $defaultPath
                     }
                 } else {
                     $targets += [PSCustomObject]@{
                         Name = (Split-Path $ProfilePath -Leaf)
                         Path = $ProfilePath
                     }
                 }
             } elseif ($ProfilePath -match '\\Default$') {
                 $profileRoot = Split-Path $ProfilePath -Parent
                 $profileDirs = Get-ChildItem -Path $profileRoot -Directory -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' -or $_.Name -eq 'Guest Profile' -or $_.Name -eq 'System Profile' }
                 foreach ($prof in $profileDirs) {
                     $targets += [PSCustomObject]@{
                         Name = $prof.Name
                         Path = $prof.FullName
                     }
                 }
                 foreach ($supportName in @('Local State', 'First Run')) {
                     $supportPath = Join-Path $profileRoot $supportName
                     if (Test-Path $supportPath) {
                         $supportFiles += $supportPath
                     }
                 }
             } else {
                 $targets += [PSCustomObject]@{
                     Name = (Split-Path $ProfilePath -Leaf)
                     Path = $ProfilePath
                 }
             }

             if ($targets.Count -eq 0) {
                 $targets += [PSCustomObject]@{
                     Name = (Split-Path $ProfilePath -Leaf)
                     Path = $ProfilePath
                 }
             }

             foreach ($supportPath in $supportFiles | Select-Object -Unique) {
                 try {
                     Copy-Item $supportPath -Destination $DestUser -Force -ErrorAction SilentlyContinue
                 } catch {}
             }

             foreach ($target in $targets) {
                 $tPath = $target.Path
                 $profileName = if ([string]::IsNullOrWhiteSpace($target.Name)) { "Profile" } else { $target.Name }
                 $safeProfileName = ($profileName -replace '[\\/:*?"<>|]', '_')
                 $profileDest = Join-Path $DestUser $safeProfileName
                 if (-not (Test-Path -LiteralPath $profileDest -ErrorAction SilentlyContinue)) {
                     New-Item -Path $profileDest -ItemType Directory -Force | Out-Null
                 }

                 # SYNC STATUS CHECK
                 try {
                     $syncEmail = "Not Synced"
                     $syncEnabled = $false
                     
                     if ($BrowserName -eq "Firefox") {
                        # Firefox Sync Check (signedInUser.json)
                        $signedInJson = Join-Path $tPath "signedInUser.json"
                        if (Test-Path $signedInJson) {
                            $content = Get-Content -Path $signedInJson -Raw -ErrorAction SilentlyContinue
                            if ($content) {
                                $json = $content | ConvertFrom-Json -ErrorAction SilentlyContinue
                                if ($json -and $json.accountData -and $json.accountData.email) {
                                    $syncEmail = $json.accountData.email
                                    $syncEnabled = $true
                                }
                            }
                        }

                     } else {
                        # Chromium Sync Check (Preferences & Secure Preferences)
                        $prefFiles = @("Preferences", "Secure Preferences")
                        foreach ($pFile in $prefFiles) {
                            if ($syncEnabled) { break }


                            $prefPath = Join-Path $tPath $pFile
                            if (Test-Path $prefPath) {
                                # Read partial or full content
                                $content = Get-Content -Path $prefPath -Raw -ErrorAction SilentlyContinue
                                if ($content) {
                                    $json = $content | ConvertFrom-Json -ErrorAction SilentlyContinue
                                    
                                    # Standard Chromium (Chrome, Edge, Brave, etc.)
                                    if ($json -and $json.account_info) {
                                        if ($json.account_info.email) {
                                            $syncEmail = $json.account_info.email
                                            $syncEnabled = $true
                                        }
                                    }
                                    
                                    # Opera / OperaGX specific check
                                    if (-not $syncEnabled) {
                                        if ($json.opera -and $json.opera.account) {
                                            if ($json.opera.account.username) {
                                                $syncEmail = $json.opera.account.username
                                                $syncEnabled = $true
                                            } elseif ($json.opera.account.email) {
                                                $syncEmail = $json.opera.account.email
                                                $syncEnabled = $true
                                            }
                                            # Some versions use 'id' which might be an email
                                            elseif ($json.opera.account.id -and $json.opera.account.id -match "@") {
                                                $syncEmail = $json.opera.account.id
                                                $syncEnabled = $true
                                            }
                                        }
                                    }
                                }
                            }
                        }

                     }

                     

                 } catch {}

                 if (-not (Get-Variable "syncEnabled" -ErrorAction SilentlyContinue)) { $syncEnabled = $false }
                 
                 # Fallback for Opera/OperaGX if Preferences check failed or crashed (e.g. JSON error)
                 if ((-not $syncEnabled) -and ($BrowserName -match "Opera")) {
                      $syncDataDir = Join-Path $tPath "Sync Data"
                      if (Test-Path $syncDataDir) {
                          # Check if it has content
                          $count = (Get-ChildItem $syncDataDir -Force -ErrorAction SilentlyContinue | Measure-Object).Count
                          if ($count -gt 0) {
                              $syncEnabled = $true
                              $syncEmail = "Active (Email not found in Config)"
                              
                              # Heuristic: Scan LevelDB logs for email
                              try {
                                  $logFiles = Get-ChildItem -Path "$syncDataDir\LevelDB" -Filter "*.log" -Recurse -ErrorAction SilentlyContinue
                                  foreach ($log in $logFiles) {
                                      # Read first 50KB to avoid memory issues
                                      $lContent = Get-Content $log.FullName -TotalCount 500 -ErrorAction SilentlyContinue
                                      $lContentStr = $lContent -join "`n"
                                      # Simple regex for email
                                      if ($lContentStr -match "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})") {
                                          $syncEmail = $matches[1]
                                          break
                                      }
                                  }
                              } catch {}
                          }
                      }
                 }

                 if ($syncEnabled) {
                     $syncData += [PSCustomObject]@{
                         Browser = $BrowserName
                         User = $userName
                         ProfilePath = $tPath
                         ProfileName = $profileName
                         SyncEmail = $syncEmail
                         SyncStatus = "Active"
                     }
                 }
                 
                 $items = @(
                    "History",
                    "Login Data",
                    "Cookies",
                    "Network\Cookies",
                    "Preferences",
                    "Web Data",
                    "places.sqlite",
                    "key4.db",
                    "logins.json",
                    "prefs.js"
                )
                 foreach ($item in $items) {
                     $src = Join-Path $tPath $item
                     if (Test-Path $src) {
                         Copy-Item $src -Destination $profileDest -Force -ErrorAction SilentlyContinue
                     }
                 }

                 if ($BrowserName -eq "Firefox") {
                     $extensionsJson = Join-Path $tPath "extensions.json"
                     if (Test-Path $extensionsJson) {
                         $extContent = Get-Content -Path $extensionsJson -Raw -ErrorAction SilentlyContinue
                         if ($extContent) {
                             try {
                                 $extData = $extContent | ConvertFrom-Json -ErrorAction SilentlyContinue
                                 if ($extData -and $extData.addons) {
                                     foreach ($addon in $extData.addons) {
                                         $extId = $addon.id
                                         $extName = $null
                                         $extVersion = $addon.version
                                         if ($addon.defaultLocale -and $addon.defaultLocale.name) {
                                             $extName = $addon.defaultLocale.name
                                         }
                                         $hashValue = $null
                                         $hashObj = Get-FileHash -Path $extensionsJson -Algorithm SHA256 -ErrorAction SilentlyContinue
                                         if ($hashObj) {
                                             $hashValue = $hashObj.Hash
                                         }
                                         $extensions += [PSCustomObject]@{
                                             Browser = $BrowserName
                                             User = $userName
                                             ExtensionId = $extId
                                             Name = $extName
                                             Version = $extVersion
                                             ManifestPath = $extensionsJson
                                             ManifestHashSha256 = $hashValue
                                         }
                                     }
                                 }
                             } catch {}
                         }
                     }
                 } else {
                     $extRoot = Join-Path $tPath "Extensions"
                     if (Test-Path $extRoot) {
                         $idDirs = Get-ChildItem -Path $extRoot -Directory -ErrorAction SilentlyContinue
                         foreach ($idDir in $idDirs) {
                             $verDirs = Get-ChildItem -Path $idDir.FullName -Directory -ErrorAction SilentlyContinue
                             if (-not $verDirs) {
                                 $verDirs = @($idDir)
                             }
                             foreach ($verDir in $verDirs) {
                                 $manifestPath = Join-Path $verDir.FullName "manifest.json"
                                 $extName = $null
                                 $extVersion = $verDir.Name
                                 if (Test-Path $manifestPath) {
                                     $manifestRaw = Get-Content -Path $manifestPath -Raw -ErrorAction SilentlyContinue
                                     if ($manifestRaw) {
                                         try {
                                             $manifest = $manifestRaw | ConvertFrom-Json -ErrorAction SilentlyContinue
                                             if ($manifest) {
                                                 if ($manifest.name) { $extName = $manifest.name }
                                                 if ($manifest.version) { $extVersion = $manifest.version }
                                             }
                                         } catch {}
                                     }
                                 }
                                 $hashValue = $null
                                 if (Test-Path $manifestPath) {
                                     $hashObj = Get-FileHash -Path $manifestPath -Algorithm SHA256 -ErrorAction SilentlyContinue
                                     if ($hashObj) {
                                         $hashValue = $hashObj.Hash
                                     }
                                 }
                                 $extensions += [PSCustomObject]@{
                                     Browser = $BrowserName
                                     User = $userName
                                     ExtensionId = $idDir.Name
                                     Name = $extName
                                     Version = $extVersion
                                     ManifestPath = $manifestPath
                                     ManifestHashSha256 = $hashValue
                                 }
                             }
                         }
                     }
                 }
             }
        }
    }
    if ($extensions.Count -gt 0) {
        $outDir = "$FolderCreation\Browsers"
        if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
        $csvPath = Join-Path $outDir "Browser_Extensions.csv"
        if (Test-Path $csvPath) {
            $extensions | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8 -Append
        } else {
            $extensions | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8
        }
        $txtPath = Join-Path $outDir "Browser_Extensions.txt"
        $extensions | Format-Table -AutoSize | Out-File -Width 4096 -FilePath $txtPath -Append
    }

    if ($syncData.Count -gt 0) {
        $outDir = "$FolderCreation\Browsers"
        $csvPath = Join-Path $outDir "Browser_Sync_Status.csv"
        $syncData | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8 -Append
        
        $txtPath = Join-Path $outDir "Browser_Sync_Status.txt"
        $syncData | Format-Table -AutoSize | Out-File -Width 4096 -FilePath $txtPath -Append
    }
}
if ($RunAll -or $Browser) {
    # Calling generically to restore functionality
    Collect-BrowserArtifacts "Firefox" "24" "AppData\Roaming\Mozilla\Firefox\Profiles" 
    Collect-BrowserArtifacts "Opera" "25" "AppData\Roaming\Opera Software\Opera Stable"
    Collect-BrowserArtifacts "Edge" "26" "AppData\Local\Microsoft\Edge\User Data\Default"
    Collect-BrowserArtifacts "Chrome" "27" "AppData\Local\Google\Chrome\User Data\Default"
    Collect-BrowserArtifacts "CCleaner" "27b" "AppData\Local\CCleaner Browser\User Data\Default"
    Collect-BrowserArtifacts "Brave" "28" "AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"
    Collect-BrowserArtifacts "OperaGX" "25b" "AppData\Roaming\Opera Software\Opera GX Stable"

    $extCsv = "$FolderCreation\Browsers\Browser_Extensions.csv"
    $extTxt = "$FolderCreation\Browsers\Browser_Extensions.txt"
    WriteHash -FilePath $extCsv
    WriteHash -FilePath $extTxt

    if (Get-Variable -Name BrowserProcessActions -Scope Script -ErrorAction SilentlyContinue) {
        $browserActionCsv = "$FolderCreation\Browsers\Browser_Process_Actions.csv"
        $browserActionTxt = "$FolderCreation\Browsers\Browser_Process_Actions.txt"
        $script:BrowserProcessActions | Export-Csv -NoTypeInformation -Path $browserActionCsv -Encoding UTF8
        $script:BrowserProcessActions | Format-Table -AutoSize | Out-File -Width 4096 -FilePath $browserActionTxt
        WriteHash -FilePath $browserActionCsv
        WriteHash -FilePath $browserActionTxt
    }
}

# Task 28: RDP
function Get-RdpConnections{
  Write-Host "Running task 28 of 33" -ForegroundColor Yellow
  Write-Host "Collecting RDP connection events..."
  WriteLog -Level "INFO" -Message "Collecting RDP connection events (1149)"
  $RawEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1149 }
  if ($RawEvents) {
      $rdpEvents = $RawEvents | ForEach-Object {
         [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[0].Value
            Domain = $_.Properties[1].Value
            SourceIp = $_.Properties[2].Value
         }
      }
      $rdpEvents | Export-Csv -NoTypeInformation -Path "$FolderCreation\EventsLogs\RDP_Connections.csv" -Encoding UTF8
      $rdpEvents | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$FolderCreation\EventsLogs\RDP_Connections.txt"
  }
}
if ($RunAll -or $Events) { Get-RdpConnections }

# Task 29: System Config
function Get-SystemConfig {
    Write-Host "Running task 29 of 33" -ForegroundColor Yellow
    Write-Host "Collecting System Configuration..."
    WriteLog -Level "INFO" -Message "Collecting System Config..."

    $SystemFolder = "$FolderCreation\SystemConfig"
    New-Item -Path $SystemFolder -ItemType Directory -Force | Out-Null

    $localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet
    $localUsers | Export-Csv -NoTypeInformation -Path "$SystemFolder\LocalUsers.csv" -Encoding UTF8
    $localUsers | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$SystemFolder\LocalUsers.txt"

    # User Accounts (WMI Style as requested)
    try {
        Get-CimInstance Win32_UserAccount | Select-Object Caption, SID | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$SystemFolder\Usuarios.txt" -Append
    } catch {
        Write-Warning "Could not collect WMI UserAccount info."
    }

    $fwRules = Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile
    $fwRules | Export-Csv -NoTypeInformation -Path "$SystemFolder\FirewallRules.csv" -Encoding UTF8
    $fwRules | Format-Table -AutoSize | Out-File -Width 4096 -FilePath "$SystemFolder\FirewallRules.txt"
    
    $sysInfo = Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, OsArchitecture, BiosManufacturer, BiosName, BiosVersion, CsName, TimeZone
    $sysInfo | Export-Csv -NoTypeInformation -Path "$SystemFolder\SystemInfo.csv" -Encoding UTF8
    $sysInfo | Format-List | Out-File -Width 4096 -FilePath "$SystemFolder\SystemInfo.txt"
    
    WriteLog -Level "INFO" -Message "System Configuration collected."
}
if ($RunAll -or $System) { Get-SystemConfig }

# Task 30: VSS
function Export-ForensicArtifactsFromVSS {
     Write-Host "Running task 30 of 33" -ForegroundColor Yellow
     Write-Host "Collecting VSS Artifacts (Hives, Amcache, SRUDB, User Hives)..."
     WriteLog -Level "INFO" -Message "Collecting VSS Artifacts..."
     
     # Removed SeBackupPrivilege block as per user request (deemed excessive and buggy)
     
     $VSSFolder = "$FolderCreation\VSS_Artifacts"
     New-Item -Path $VSSFolder -ItemType Directory -Force | Out-Null
     Set-ArtifactVisible -Path $VSSFolder

     try {
         $class = Get-CimClass -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue
         if ($class) {
             # Fix: Use SystemDrive instead of Hardcoded C:\
             $VolumeArg = "$($env:SystemDrive)\"
             $createdShadow = $false
             $createErr = $null
             $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume=$VolumeArg; Context="ClientAccessible"} -ErrorAction SilentlyContinue -ErrorVariable createErr

             if ($result -and $result.ReturnValue -eq 0 -and $result.ShadowID) {
                 $ShadowId = $result.ShadowID
                 $createdShadow = $true
                 WriteLog -Level "INFO" -Message "Shadow Copy created successfully. ID: $ShadowId"
             } else {
                 $rv = if ($result -and $null -ne $result.ReturnValue) { $result.ReturnValue } else { "null" }
                 $errText = if ($createErr) { ($createErr | ForEach-Object { $_.Exception.Message }) -join " | " } else { "No CIM error details" }
                 WriteLog -Level "WARN" -Message "VSS Create failed or returned null (ReturnValue: $rv). Error: $errText"

                 $existingShadow = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Sort-Object InstallDate -Descending | Select-Object -First 1
                 if ($existingShadow) {
                     $ShadowId = $existingShadow.ID
                     WriteLog -Level "INFO" -Message "Using existing Shadow Copy ID: $ShadowId"
                 } else {
                     WriteLog -Level "ERROR" -Message "No Shadow Copy available (creation failed and no existing snapshots found)."
                     return
                 }
             }

             $LinkPath = $null

             try {
                     $ShadowInfo = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId }
                     if (-not $ShadowInfo -or -not $ShadowInfo.DeviceObject) {
                         WriteLog -Level "ERROR" -Message "Could not resolve DeviceObject for Shadow Copy ID: $ShadowId"
                         return
                     }
                     $DeviceObject = $ShadowInfo.DeviceObject
                     
                     $LinkName = "ShadowCopyMount_$($ShadowInfo.ID.ToString().Replace('{','').Replace('}',''))"
                     $LinkPath = Join-Path $env:SystemDrive $LinkName
                     $cmdArgs = "/c mklink /d ""$LinkPath"" ""$DeviceObject\"""
                     Start-Process cmd -ArgumentList $cmdArgs -WindowStyle Hidden -Wait
                     
                     if (Test-Path $LinkPath) {
                          $SystemArtifacts = @(
                             "Windows\System32\config\SAM",
                             "Windows\System32\config\SYSTEM",
                             "Windows\System32\config\SECURITY",
                             "Windows\System32\config\SOFTWARE",
                             "Windows\AppCompat\Programs\Amcache.hve",
                             "Windows\System32\sru\SRUDB.dat"
                             # '$MFT',
                             # '$LogFile',
                             # '$UsnJrnl',
                             # '$Boot',
                             # '$AttrDef'
                          )
                          $totalArts = $SystemArtifacts.Count
                          $artCount = 0
                          $skipRemainingCriticalNtfsArtifacts = $false
                          
                          foreach ($art in $SystemArtifacts) {
                              $artCount++
                              Write-Progress -Activity "Collecting VSS System Artifacts" -Status "Copying $art ($artCount / $totalArts)" -PercentComplete (($artCount / $totalArts) * 100)
                              $Source = Join-Path $LinkPath $art
                              $Dest = Join-Path $VSSFolder (Split-Path $art -Leaf)
                              $isCriticalNtfsArtifact = $art -match '\$MFT|\$LogFile|\$UsnJrnl|\$Boot|\$AttrDef'
                              
                              $copySuccess = $false
                              $copyMethod = "none"
                              $artStart = Get-Date
                              WriteLog -Level "INFO" -Message "VSS_ARTIFACT_START [$artCount/$totalArts] Artifact=$art Critical=$isCriticalNtfsArtifact Source=$Source"
                              if ($isCriticalNtfsArtifact) {
                                  Write-Progress -Id 2 -ParentId 1 -Activity "NTFS Critical Artifact" -Status "${art}: preparing copy methods" -PercentComplete 0
                              }
                              if ($isCriticalNtfsArtifact -and $skipRemainingCriticalNtfsArtifacts) {
                                  $elapsedMs = [math]::Round(((Get-Date) - $artStart).TotalMilliseconds, 0)
                                  WriteLog -Level "WARN" -Message "VSS_ARTIFACT_SKIP  [$artCount/$totalArts] Artifact=$art Reason=Previous critical NTFS artifact failed (speed mode) DurationMs=$elapsedMs"
                                  continue
                              }


                              if (-not $isCriticalNtfsArtifact) {
                                  try {
                                      Copy-Item -Path $Source -Destination $Dest -Force -ErrorAction Stop
                                      WriteLog -Level "INFO" -Message "Copied VSS artifact: $art"
                                      $copySuccess = $true
                                      $copyMethod = "Copy-Item"
                                  } catch {
                                      WriteLog -Level "WARN" -Message "Could not copy $art from VSS path: $_"
                                  }
                              } else {
                                  WriteLog -Level "INFO" -Message "Skipping Copy-Item for protected NTFS artifact: $art"
                              }

                              if (-not $copySuccess -and $isCriticalNtfsArtifact) {
                                  Write-Progress -Id 2 -ParentId 1 -Activity "NTFS Critical Artifact" -Status "${art}: .NET stream" -PercentComplete 25
                                  WriteLog -Level "INFO" -Message "Attempting advanced copy methods for locked artifact: $art"
                                  if ($DeviceObject) {
                                      try {
                                          $srcDevPath = "$DeviceObject\$art"
                                          try {
                                              $inStream = [System.IO.File]::Open($srcDevPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                                              $outStream = [System.IO.File]::Open($Dest, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
                                              $inStream.CopyTo($outStream)
                                              $outStream.Close()
                                              $inStream.Close()
                                              if ((Test-Path $Dest) -and ((Get-Item -Path $Dest -ErrorAction SilentlyContinue).Length -gt 0)) {
                                                  WriteLog -Level "INFO" -Message "Success: .NET Stream Copy for $art"
                                                  $copySuccess = $true
                                                  $copyMethod = ".NET Stream"
                                              }
                                          } catch {
                                              WriteLog -Level "WARN" -Message ".NET Stream Copy failed: $_"
                                              if ($inStream) { $inStream.Close() }
                                              if ($outStream) { $outStream.Close() }
                                          }
                                          if (-not $copySuccess) {
                                              $esentOutput = & esentutl /y "$srcDevPath" /d "$Dest" /o 2>&1 | Out-String
                                              if ((Test-Path $Dest) -and ((Get-Item -Path $Dest -ErrorAction SilentlyContinue).Length -gt 0)) {
                                                  WriteLog -Level "INFO" -Message "Success: ESENTUTL for $art"
                                                  $copySuccess = $true
                                                  $copyMethod = "ESENTUTL"
                                              } else {
                                                  WriteLog -Level "WARN" -Message "ESENTUTL failed. Output: $esentOutput"
                                              }
                                          }
                                      } catch {
                                          WriteLog -Level "ERROR" -Message "DevicePath fallback logic error: $_"
                                      }
                                  }
                                  if (-not $copySuccess) {
                                      Write-Progress -Id 2 -ParentId 1 -Activity "NTFS Critical Artifact" -Status "${art}: robocopy /B" -PercentComplete 85
                                      try {
                                          $SourceDir = Split-Path $Source -Parent
                                          $FileName = Split-Path $Source -Leaf
                                          $DestDir = Split-Path $Dest -Parent
                                          $roboOutput = & robocopy "$SourceDir" "$DestDir" "$FileName" /B /R:0 /W:0 /COPY:DAT /NJH /NJS 2>&1 | Out-String
                                          if ((Test-Path $Dest) -and ((Get-Item -Path $Dest -ErrorAction SilentlyContinue).Length -gt 0)) {
                                              WriteLog -Level "INFO" -Message "Success: Robocopy /B for $art"
                                              $copySuccess = $true
                                              $copyMethod = "Robocopy /B"
                                          } else {
                                              WriteLog -Level "ERROR" -Message "All copy methods failed for $art. Robocopy output: $roboOutput"
                                          }
                                      } catch {
                                          WriteLog -Level "ERROR" -Message "Robocopy fallback error: $_"
                                      }
                                  }
                              }
                              $elapsedMs = [math]::Round(((Get-Date) - $artStart).TotalMilliseconds, 0)
                              $sizeBytes = if (Test-Path $Dest) { (Get-Item -Path $Dest -ErrorAction SilentlyContinue).Length } else { 0 }
                              if ($copySuccess) {
                                  WriteLog -Level "INFO" -Message "VSS_ARTIFACT_END   [$artCount/$totalArts] Artifact=$art Method=$copyMethod DurationMs=$elapsedMs SizeBytes=$sizeBytes Dest=$Dest"
                                  if ($isCriticalNtfsArtifact) { Write-Progress -Id 2 -ParentId 1 -Activity "NTFS Critical Artifact" -Status "${art}: done" -PercentComplete 100 }
                              } else {
                                  WriteLog -Level "ERROR" -Message "VSS_ARTIFACT_FAIL  [$artCount/$totalArts] Artifact=$art DurationMs=$elapsedMs Dest=$Dest"
                                  if (-not $Silent) { Write-Warning "NTFS critical artifact failed: $art (see log for method errors)." }
                                  if ($isCriticalNtfsArtifact) { Write-Progress -Id 2 -ParentId 1 -Activity "NTFS Critical Artifact" -Status "${art}: failed" -PercentComplete 100 }
                                  if ($isCriticalNtfsArtifact) {
                                      $skipRemainingCriticalNtfsArtifacts = $true
                                      WriteLog -Level "WARN" -Message "Critical NTFS artifact copy failed ($art). Remaining critical NTFS artifacts will be skipped for live-response speed."
                                  }
                              }
                          }
                          Write-Progress -Id 2 -Activity "NTFS Critical Artifact" -Completed
                          Write-Progress -Activity "Collecting VSS System Artifacts" -Completed

                          # User Artifacts
                          $UsersLinkPath = Join-Path $LinkPath "Users"
                          if (Test-Path $UsersLinkPath) {
                              $VSSUsers = Get-ChildItem -Path $UsersLinkPath -Directory -ErrorAction SilentlyContinue
                              $totalVSSUsers = $VSSUsers.Count
                              $vssUserCount = 0
                              
                              foreach ($user in $VSSUsers) {
                                  $vssUserCount++
                                  Write-Progress -Activity "Collecting VSS User Artifacts" -Status "Processing user $($user.Name) ($vssUserCount / $totalVSSUsers)" -PercentComplete (($vssUserCount / $totalVSSUsers) * 100)
                                  
                                  $userName = $user.Name
                                  $userDest = Join-Path $VSSFolder "Users\$userName"
                                  New-Item -Path $userDest -ItemType Directory -Force | Out-Null
                                  
                                  $ntuser = Join-Path $user.FullName "NTUSER.DAT"
                                  if (Test-Path $ntuser) { Copy-Item -Path $ntuser -Destination $userDest -Force }
                                  
                                  $usrClass = Join-Path $user.FullName "AppData\Local\Microsoft\Windows\UsrClass.dat"
                                  if (Test-Path $usrClass) { Copy-Item -Path $usrClass -Destination $userDest -Force }
                                  
                                  # JumpLists
                                  $jumpListsDest = Join-Path $userDest "JumpLists"
                                  $autoDest = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
                                  $custDest = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"
                                  if (Test-Path $autoDest) { 
                                    $jd = Join-Path $jumpListsDest "AutomaticDestinations"; New-Item -Path $jd -ItemType Directory -Force | Out-Null
                                    Copy-Item "$autoDest\*" -Destination $jd -Force -Recurse -ErrorAction SilentlyContinue 
                                  }
                                  if (Test-Path $custDest) {
                                    $jd = Join-Path $jumpListsDest "CustomDestinations"; New-Item -Path $jd -ItemType Directory -Force | Out-Null
                                    Copy-Item "$custDest\*" -Destination $jd -Force -Recurse -ErrorAction SilentlyContinue
                                  }
                              }
                              Write-Progress -Activity "Collecting VSS User Artifacts" -Completed
                              try {
                                  Get-ChildItem -Path $VSSFolder -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Set-ArtifactVisible -Path $_.FullName }
                                  Set-ArtifactVisible -Path $VSSFolder
                              } catch {}
                          }
                     } else {
                         WriteLog -Level "ERROR" -Message "Failed to mount Shadow Copy at $LinkPath"
                     }
                 } finally {
                     # Robust Cleanup
                     if ($LinkPath -and (Test-Path $LinkPath)) {
                        cmd /c rmdir "$LinkPath"
                     }
                     if ($ShadowId -and $createdShadow) {
                        try {
                           Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId } | Remove-CimInstance -ErrorAction SilentlyContinue
                        } catch {
                           WriteLog -Level "WARN" -Message "Could not remove Shadow Copy via CIM."
                        }
                     }
                 }
         } else {
             WriteLog -Level "ERROR" -Message "Win32_ShadowCopy WMI Class not found."
         }
     } catch { WriteLog -Level "ERROR" -Message "VSS Collection failed: $_" }
}
if ($RunAll -or $Disk) { Export-ForensicArtifactsFromVSS }

# Task 31: Cloud Storage
function Get-CloudStorageArtifacts {
    Write-Host "Running task 31 of 33" -ForegroundColor Yellow
    Write-Host "Collecting Cloud Storage Artifacts (OneDrive, Teams, Google, Dropbox)...`n"
    WriteLog -Level "INFO" -Message "Collecting Cloud Storage Artifacts..."

    $CloudFolder = "$FolderCreation\CloudStorage"
    New-Item -Path $CloudFolder -ItemType Directory -Force | Out-Null
    
    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    
    $totalUsers = $userDirectories.Count
    $userCount = 0

    foreach ($userDir in $userDirectories) {
        $userCount++
        Write-Progress -Activity "Collecting Cloud Storage Artifacts" -Status "Processing user $($userDir.Name) ($userCount / $totalUsers)" -PercentComplete (($userCount / $totalUsers) * 100)

        $userName = $userDir.Name
        $userDest = Join-Path $CloudFolder $userName
        New-Item -Path $userDest -ItemType Directory -Force | Out-Null
        
        # 1. OneDrive (Logs & Settings)
        $OneDrive = Join-Path $userDir.FullName "AppData\Local\Microsoft\OneDrive"
        if (Test-Path $OneDrive) {
            $odDest = Join-Path $userDest "OneDrive"
            New-Item -Path $odDest -ItemType Directory -Force | Out-Null
            # Settings
            if (Test-Path "$OneDrive\settings") { Copy-Item "$OneDrive\settings\*" -Destination $odDest -Recurse -Force -ErrorAction SilentlyContinue }
            # Logs
            if (Test-Path "$OneDrive\logs") { Copy-Item "$OneDrive\logs" -Destination $odDest -Recurse -Force -ErrorAction SilentlyContinue }
        }

        # 2. Microsoft Teams (Cookies, Logs)
        $Teams = Join-Path $userDir.FullName "AppData\Roaming\Microsoft\Teams"
        if (Test-Path $Teams) {
            $teamsDest = Join-Path $userDest "Teams"
            New-Item -Path $teamsDest -ItemType Directory -Force | Out-Null
            $targets = @("Cookies", "Local Storage", "logs.txt", "desktop-config.json")
            foreach ($t in $targets) {
                if (Test-Path "$Teams\$t") { Copy-Item "$Teams\$t" -Destination $teamsDest -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }
        
        # 3. Google Drive (DriveFS)
        $GDrive = Join-Path $userDir.FullName "AppData\Local\Google\DriveFS"
        if (Test-Path $GDrive) {
            $gdDest = Join-Path $userDest "GoogleDrive"
            New-Item -Path $gdDest -ItemType Directory -Force | Out-Null
            Copy-Item "$GDrive\*" -Destination $gdDest -Recurse -Force -ErrorAction SilentlyContinue
        }

        # 4. Dropbox
        $DropboxLocal = Join-Path $userDir.FullName "AppData\Local\Dropbox"
        $DropboxRoaming = Join-Path $userDir.FullName "AppData\Roaming\Dropbox"
        $dbDest = Join-Path $userDest "Dropbox"
        if (Test-Path $DropboxLocal) { 
            if (-not (Test-Path $dbDest)) { New-Item -Path $dbDest -ItemType Directory -Force | Out-Null }
            Copy-Item "$DropboxLocal\*" -Destination $dbDest -Recurse -Force -ErrorAction SilentlyContinue 
        }
        if (Test-Path $DropboxRoaming) {
            if (-not (Test-Path $dbDest)) { New-Item -Path $dbDest -ItemType Directory -Force | Out-Null }
            Copy-Item "$DropboxRoaming\*" -Destination $dbDest -Recurse -Force -ErrorAction SilentlyContinue 
        }
    }
    Write-Progress -Activity "Collecting Cloud Storage Artifacts" -Completed
    WriteLog -Level "INFO" -Message "Cloud Storage Artifacts collected."
}
if ($RunAll -or $Cloud) { Get-CloudStorageArtifacts }

# Task 32: Remote Access
function Get-RemoteAccessArtifacts {
    Write-Host "Running task 32 of 34" -ForegroundColor Yellow
    Write-Host "Collecting Remote Access Artifacts (AnyDesk, TeamViewer)...`n"
    WriteLog -Level "INFO" -Message "Collecting Remote Access Artifacts..."

    $RemoteFolder = "$FolderCreation\RemoteAccess"
    New-Item -Path $RemoteFolder -ItemType Directory -Force | Out-Null
    
    # Global ProgramData
    $ProgData = $env:ProgramData
    
    # 1. AnyDesk (Global)
    if (Test-Path "$ProgData\AnyDesk") {
        $adDest = Join-Path $RemoteFolder "AnyDesk_ProgramData"
        New-Item -Path $adDest -ItemType Directory -Force | Out-Null
        Copy-Item "$ProgData\AnyDesk\*" -Destination $adDest -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # 2. TeamViewer (Global Logs)
    if (Test-Path "$env:ProgramFiles\TeamViewer") {
        $tvDest = Join-Path $RemoteFolder "TeamViewer_ProgramFiles"
        New-Item -Path $tvDest -ItemType Directory -Force | Out-Null
        Copy-Item "$env:ProgramFiles\TeamViewer\*.txt" -Destination $tvDest -Force -ErrorAction SilentlyContinue
        Copy-Item "$env:ProgramFiles\TeamViewer\*.log" -Destination $tvDest -Force -ErrorAction SilentlyContinue
    }
    
    # User specific
    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    
    $totalUsers = $userDirectories.Count
    $userCount = 0

    foreach ($userDir in $userDirectories) {
        $userCount++
        Write-Progress -Activity "Collecting Remote Access Artifacts" -Status "Processing user $($userDir.Name) ($userCount / $totalUsers)" -PercentComplete (($userCount / $totalUsers) * 100)

        $userName = $userDir.Name
        $userDest = Join-Path $RemoteFolder $userName
        New-Item -Path $userDest -ItemType Directory -Force | Out-Null
        
        # AnyDesk (Roaming)
        $adUser = Join-Path $userDir.FullName "AppData\Roaming\AnyDesk"
        if (Test-Path $adUser) {
            $d = Join-Path $userDest "AnyDesk"
            New-Item -Path $d -ItemType Directory -Force | Out-Null
            Copy-Item "$adUser\*" -Destination $d -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # TeamViewer (Roaming)
        $tvUser = Join-Path $userDir.FullName "AppData\Roaming\TeamViewer"
        if (Test-Path $tvUser) {
            $d = Join-Path $userDest "TeamViewer"
            New-Item -Path $d -ItemType Directory -Force | Out-Null
            Copy-Item "$tvUser\*" -Destination $d -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    WriteLog -Level "INFO" -Message "Remote Access Artifacts collected."
}
if ($RunAll -or $Cloud) { Get-RemoteAccessArtifacts }

# Task 33: Email Artifacts
function Get-EmailArtifacts {
    Write-Host "Running task 33" -ForegroundColor Yellow
    Write-Host "Collecting Email Artifacts (Outlook, Thunderbird, Windows Mail)..."
    WriteLog -Level "INFO" -Message "Collecting Email Artifacts"

    $EmailFolder = "$FolderCreation\EmailArtifacts"
    New-Item -Path $EmailFolder -ItemType Directory -Force | Out-Null

    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    
    $totalUsers = $userDirectories.Count
    $userCount = 0

    foreach ($userDir in $userDirectories) {
        $userCount++
        Write-Progress -Activity "Collecting Email Artifacts" -Status "Processing user $($userDir.Name) ($userCount / $totalUsers)" -PercentComplete (($userCount / $totalUsers) * 100)
        
        $userName = $userDir.Name
        $userDest = Join-Path $EmailFolder $userName
        
        # --- Outlook ---
        # 1. AppData\Local\Microsoft\Outlook (*.ost, *.nst, *.oab)
        $outlookLocal = Join-Path $userDir.FullName "AppData\Local\Microsoft\Outlook"
        if (Test-Path $outlookLocal) {
            $dest = Join-Path $userDest "Outlook_Local"
            if (-not (Test-Path $dest)) { New-Item -Path $dest -ItemType Directory -Force | Out-Null }
            Get-ChildItem -Path $outlookLocal -Include *.ost,*.nst,*.oab -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                WriteHash -FilePath "$dest\$($_.Name)"
            }
        }
        
        # 2. Documents\Outlook Files (*.pst)
        $outlookDocs = Join-Path $userDir.FullName "Documents\Outlook Files"
        if (Test-Path $outlookDocs) {
            $dest = Join-Path $userDest "Outlook_Documents"
            if (-not (Test-Path $dest)) { New-Item -Path $dest -ItemType Directory -Force | Out-Null }
            Get-ChildItem -Path $outlookDocs -Filter *.pst -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                WriteHash -FilePath "$dest\$($_.Name)"
            }
        }

        # 3. AppData\Roaming\Microsoft\Outlook (Config: *.srs, *.xml, *.otm)
        $outlookRoaming = Join-Path $userDir.FullName "AppData\Roaming\Microsoft\Outlook"
        if (Test-Path $outlookRoaming) {
            $dest = Join-Path $userDest "Outlook_Roaming"
            if (-not (Test-Path $dest)) { New-Item -Path $dest -ItemType Directory -Force | Out-Null }
            Get-ChildItem -Path $outlookRoaming -Include *.srs,*.xml,*.otm -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                WriteHash -FilePath "$dest\$($_.Name)"
            }
        }

        # --- Thunderbird ---
        # AppData\Roaming\Thunderbird
        $thunderbirdPath = Join-Path $userDir.FullName "AppData\Roaming\Thunderbird"
        if (Test-Path $thunderbirdPath) {
            $dest = Join-Path $userDest "Thunderbird"
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$thunderbirdPath\profiles.ini" -Destination $dest -Force -ErrorAction SilentlyContinue
            if (Test-Path "$thunderbirdPath\Profiles") {
                Copy-Item -Path "$thunderbirdPath\Profiles" -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        # --- Windows Mail ---
        # AppData\Local\Comms
        $winMailPath = Join-Path $userDir.FullName "AppData\Local\Comms"
        if (Test-Path $winMailPath) {
             $dest = Join-Path $userDest "WindowsMail_Comms"
             New-Item -Path $dest -ItemType Directory -Force | Out-Null
             Copy-Item -Path "$winMailPath\*" -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    WriteLog -Level "INFO" -Message "Email Artifacts collected."
}
if ($RunAll -or $Users) { Get-EmailArtifacts }

# Task 34: Timeline (Chronos JSON)
function Export-ChronosTimeline {
    Write-Host "Generating Chronos timeline..." -ForegroundColor Cyan
    WriteLog -Level "INFO" -Message "Generating Chronos-compatible timeline."

    $script:ChronosTimelineEventCounter = 0

    $timelineFolder = Join-Path $FolderCreation "Timeline"
    if (-not (Test-Path -LiteralPath $timelineFolder -ErrorAction SilentlyContinue)) {
        New-Item -Path $timelineFolder -ItemType Directory -Force | Out-Null
    }

    $events = New-Object System.Collections.Generic.List[object]
    $observedTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $processCsv = Join-Path $FolderCreation "ProcessInformation\ProcessList.csv"
    if (Test-Path -LiteralPath $processCsv -ErrorAction SilentlyContinue) {
        $procRows = @(Import-Csv -LiteralPath $processCsv -ErrorAction SilentlyContinue)
        foreach ($row in $procRows) {
            $timestamp = Convert-ToTimelineTimestamp $row.Proc_CreationDate
            $description = "Process=$($row.Proc_Name) | PID=$($row.Proc_Id) | Owner=$($row.Proc_Owner) | Path=$($row.Proc_Path) | CommandLine=$($row.Proc_CommandLine)"
            $metadata = @{
                tags = @('powertriage','windows','ce','process','execution')
                user = $row.Proc_Owner
                path = $row.Proc_Path
                commandLine = $row.Proc_CommandLine
                ioc = $row.Proc_Path
                activityType = 'ProcessStart'
            }
            Add-ChronosTimelineEvent -Events $events -Event (New-ChronosTimelineEvent -Timestamp $timestamp -Title "Process started: $($row.Proc_Name) ($($row.Proc_Id))" -Description $description -Type 'execution' -Priority 'medium' -Source 'process' -Metadata $metadata)
        }
    }

    $connCsv = Join-Path $FolderCreation "Network\TCP_Connections.csv"
    if (Test-Path -LiteralPath $connCsv -ErrorAction SilentlyContinue) {
        $procNameById = @{}
        if (Test-Path -LiteralPath $processCsv -ErrorAction SilentlyContinue) {
            @(Import-Csv -LiteralPath $processCsv -ErrorAction SilentlyContinue) | ForEach-Object {
                if ($_.Proc_Id) { $procNameById[[string]$_.Proc_Id] = $_.Proc_Name }
            }
        }

        foreach ($row in @(Import-Csv -LiteralPath $connCsv -ErrorAction SilentlyContinue)) {
            if ([string]::IsNullOrWhiteSpace($row.RemoteAddress) -or $row.RemoteAddress -in @('0.0.0.0','::')) { continue }
            $timestamp = Convert-ToTimelineTimestamp $row.CreationTime
            if (-not $timestamp) { $timestamp = $observedTimestamp }
            $procName = if ($procNameById.ContainsKey([string]$row.OwningProcess)) { $procNameById[[string]$row.OwningProcess] } else { 'Unknown' }
            $description = "Process=$procName | PID=$($row.OwningProcess) | Local=$($row.LocalAddress):$($row.LocalPort) | Remote=$($row.RemoteAddress):$($row.RemotePort) | State=$($row.State)"
            $metadata = @{
                tags = @('powertriage','windows','ce','network')
                ioc = $row.RemoteAddress
                activityType = 'NetworkConnection'
                localAddress = $row.LocalAddress
                localPort = $row.LocalPort
                remoteAddress = $row.RemoteAddress
                remotePort = $row.RemotePort
                processId = $row.OwningProcess
            }
            Add-ChronosTimelineEvent -Events $events -Event (New-ChronosTimelineEvent -Timestamp $timestamp -Title "Network connection: $procName -> $($row.RemoteAddress):$($row.RemotePort)" -Description $description -Type 'network' -Priority 'medium' -Source 'network' -Metadata $metadata)
        }
    }

    $rdpCsv = Join-Path $FolderCreation "EventsLogs\RDP_Connections.csv"
    if (Test-Path -LiteralPath $rdpCsv -ErrorAction SilentlyContinue) {
        foreach ($row in @(Import-Csv -LiteralPath $rdpCsv -ErrorAction SilentlyContinue)) {
            $timestamp = Convert-ToTimelineTimestamp $row.TimeCreated
            $description = "RDP logon observed | User=$($row.Domain)\$($row.User) | SourceIp=$($row.SourceIp)"
            $metadata = @{
                tags = @('powertriage','windows','ce','rdp','logon')
                user = "$($row.Domain)\$($row.User)"
                ioc = $row.SourceIp
                activityType = 'RDPLogon'
            }
            Add-ChronosTimelineEvent -Events $events -Event (New-ChronosTimelineEvent -Timestamp $timestamp -Title "RDP connection from $($row.SourceIp)" -Description $description -Type 'logon' -Priority 'high' -Source 'rdp' -Metadata $metadata)
        }
    }

    $autorunCsv = Join-Path $FolderCreation "System\Autoruns_Registry.csv"
    if (Test-Path -LiteralPath $autorunCsv -ErrorAction SilentlyContinue) {
        foreach ($row in @(Import-Csv -LiteralPath $autorunCsv -ErrorAction SilentlyContinue)) {
            $description = "Autorun observed | Location=$($row.Location) | Name=$($row.Name) | Value=$($row.Value)"
            $metadata = @{
                tags = @('powertriage','windows','ce','autorun','persistence')
                path = $row.Value
                ioc = $row.Value
                activityType = 'Observed'
            }
            Add-ChronosTimelineEvent -Events $events -Event (New-ChronosTimelineEvent -Timestamp $observedTimestamp -Title "Autorun observed: $($row.Name)" -Description $description -Type 'persistence' -Priority 'high' -Source 'autoruns' -Metadata $metadata)
        }
    }

    $tasksCsv = Join-Path $FolderCreation "System\ScheduledTasks\ScheduledTasks.csv"
    if (Test-Path -LiteralPath $tasksCsv -ErrorAction SilentlyContinue) {
        foreach ($row in @(Import-Csv -LiteralPath $tasksCsv -ErrorAction SilentlyContinue)) {
            $description = "Scheduled task observed | TaskPath=$($row.TaskPath) | State=$($row.State) | Action=$($row.Action) | Trigger=$($row.Trigger)"
            $metadata = @{
                tags = @('powertriage','windows','ce','scheduled_task','persistence')
                path = "$($row.TaskPath)$($row.TaskName)"
                ioc = $row.Action
                activityType = 'Observed'
            }
            Add-ChronosTimelineEvent -Events $events -Event (New-ChronosTimelineEvent -Timestamp $observedTimestamp -Title "Scheduled task observed: $($row.TaskName)" -Description $description -Type 'persistence' -Priority 'medium' -Source 'scheduled_task' -Metadata $metadata)
        }
    }

    $usbCsv = Join-Path $FolderCreation "System\USB_History.csv"
    if (Test-Path -LiteralPath $usbCsv -ErrorAction SilentlyContinue) {
        foreach ($row in @(Import-Csv -LiteralPath $usbCsv -ErrorAction SilentlyContinue)) {
            $timestamp = Convert-ToTimelineTimestamp $row.KeyLastWriteTime
            $description = "USB artifact observed | FriendlyName=$($row.FriendlyName) | Serial=$($row.SerialNumber) | HardwareID=$($row.HardwareID)"
            $metadata = @{
                tags = @('powertriage','windows','ce','usb')
                ioc = $row.SerialNumber
                activityType = 'RegistryLastWrite'
            }
            Add-ChronosTimelineEvent -Events $events -Event (New-ChronosTimelineEvent -Timestamp $timestamp -Title "USB device observed: $($row.FriendlyName)" -Description $description -Type 'artifact' -Priority 'medium' -Source 'usb' -Metadata $metadata)
        }
    }

    Add-TimelineFileArtifactEvents -Events $events -RootPath (Join-Path $FolderCreation 'Prefetch') -Source 'prefetch' -Type 'execution' -Priority 'medium' -TitlePrefix 'Prefetch artifact'
    Add-TimelineFileArtifactEvents -Events $events -RootPath (Join-Path $FolderCreation 'Recent_Items') -Source 'recent_items' -Type 'artifact' -Priority 'low' -TitlePrefix 'Recent item'
    Add-TimelineFileArtifactEvents -Events $events -RootPath (Join-Path $FolderCreation 'Activities_Cache') -Source 'activities_cache' -Type 'artifact' -Priority 'low' -TitlePrefix 'Activities Cache artifact'
    Add-TimelineFileArtifactEvents -Events $events -RootPath (Join-Path $FolderCreation 'Browsers') -Source 'browser_artifact' -Type 'browser' -Priority 'low' -TitlePrefix 'Browser artifact'

    $sortedEvents = @($events | Sort-Object { [datetime]::Parse($_.timestamp) })
    $timelineJsonPath = Join-Path $timelineFolder "PowerTriage_Timeline_Chronos.json"
    $sortedEvents | ConvertTo-Json -Depth 10 | Out-File -FilePath $timelineJsonPath -Encoding UTF8
    WriteHash -FilePath $timelineJsonPath

    $summaryPath = Join-Path $timelineFolder "Timeline_Summary.txt"
    $summaryLines = @(
        "PowerTriage Timeline Summary",
        "Host: $env:COMPUTERNAME",
        "GeneratedUTC: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))",
        "Events: $($sortedEvents.Count)",
        "",
        "Events by source:"
    )
    $summaryLines += @($sortedEvents | Group-Object { $_.source } | Sort-Object Count -Descending | ForEach-Object { "  $($_.Name): $($_.Count)" })
    $summaryLines | Out-File -FilePath $summaryPath -Encoding UTF8
    WriteHash -FilePath $summaryPath

    WriteLog -Level "INFO" -Message "Chronos timeline generated successfully at $timelineJsonPath"
}
if ($Timeline) { Export-ChronosTimeline }

# Task 35: Nexus Lite
function Export-NexusLite {
    Write-Host "Generating Nexus Lite graph..." -ForegroundColor Cyan
    WriteLog -Level "INFO" -Message "Generating Nexus Lite graph."

    $netFolder = Join-Path $FolderCreation "Network"
    if (-not (Test-Path -LiteralPath $netFolder -ErrorAction SilentlyContinue)) {
        New-Item -Path $netFolder -ItemType Directory -Force | Out-Null
    }

    $nodes = New-Object System.Collections.Generic.List[object]
    $edges = New-Object System.Collections.Generic.List[object]
    $nodeTracker = @{}
    $edgeTracker = @{}

    $hostId = "host-$env:COMPUTERNAME"
    Add-NexusLiteNode -Nodes $nodes -Tracker $nodeTracker -Id $hostId -Type 'endpoint' -Label $env:COMPUTERNAME

    $procRows = @()
    $processCsv = Join-Path $FolderCreation "ProcessInformation\ProcessList.csv"
    if (Test-Path -LiteralPath $processCsv -ErrorAction SilentlyContinue) {
        $procRows = @(Import-Csv -LiteralPath $processCsv -ErrorAction SilentlyContinue)
    }

    $procMap = @{}
    foreach ($row in $procRows) {
        if (-not $row.Proc_Id) { continue }
        $procId = "proc-$($row.Proc_Id)-$($row.Proc_Name)"
        $procMap[[string]$row.Proc_Id] = @{
            id = $procId
            name = $row.Proc_Name
            owner = $row.Proc_Owner
        }
        Add-NexusLiteNode -Nodes $nodes -Tracker $nodeTracker -Id $procId -Type 'process' -Label "$($row.Proc_Name) ($($row.Proc_Id))"
        Add-NexusLiteEdge -Edges $edges -Tracker $edgeTracker -Edge ([ordered]@{
            id = "edge-host-proc-$($row.Proc_Id)"
            type = 'process_observed'
            src = $hostId
            dst = $procId
            timestamp = Convert-ToTimelineTimestamp $row.Proc_CreationDate
            note = $row.Proc_CommandLine
        })

        if ($row.Proc_Owner -and $row.Proc_Owner -ne 'N/A') {
            $userId = "user-$($row.Proc_Owner)"
            Add-NexusLiteNode -Nodes $nodes -Tracker $nodeTracker -Id $userId -Type 'user' -Label $row.Proc_Owner
            Add-NexusLiteEdge -Edges $edges -Tracker $edgeTracker -Edge ([ordered]@{
                id = "edge-user-proc-$($row.Proc_Id)"
                type = 'owns_process'
                src = $userId
                dst = $procId
            })
        }
    }

    $connCsv = Join-Path $FolderCreation "Network\TCP_Connections.csv"
    if (Test-Path -LiteralPath $connCsv -ErrorAction SilentlyContinue) {
        foreach ($row in @(Import-Csv -LiteralPath $connCsv -ErrorAction SilentlyContinue)) {
            if ([string]::IsNullOrWhiteSpace($row.RemoteAddress) -or $row.RemoteAddress -in @('0.0.0.0','::')) { continue }
            $procInfo = if ($procMap.ContainsKey([string]$row.OwningProcess)) { $procMap[[string]$row.OwningProcess] } else { $null }
            if ($null -eq $procInfo) {
                $procId = "proc-$($row.OwningProcess)-unknown"
                Add-NexusLiteNode -Nodes $nodes -Tracker $nodeTracker -Id $procId -Type 'process' -Label "Unknown ($($row.OwningProcess))"
            } else {
                $procId = $procInfo.id
            }

            $ipId = "ip-$($row.RemoteAddress)"
            Add-NexusLiteNode -Nodes $nodes -Tracker $nodeTracker -Id $ipId -Type 'ip' -Label $row.RemoteAddress
            Add-NexusLiteEdge -Edges $edges -Tracker $edgeTracker -Edge ([ordered]@{
                id = "edge-net-$($row.OwningProcess)-$($row.RemoteAddress)-$($row.RemotePort)"
                type = 'network_connection'
                src = $procId
                dst = $ipId
                label = "$($row.State) :$($row.RemotePort)"
                protocol = 'TCP'
                port = $row.RemotePort
                local_port = $row.LocalPort
                timestamp = Convert-ToTimelineTimestamp $row.CreationTime
            })
        }
    }

    $rdpCsv = Join-Path $FolderCreation "EventsLogs\RDP_Connections.csv"
    if (Test-Path -LiteralPath $rdpCsv -ErrorAction SilentlyContinue) {
        foreach ($row in @(Import-Csv -LiteralPath $rdpCsv -ErrorAction SilentlyContinue)) {
            if ([string]::IsNullOrWhiteSpace($row.SourceIp)) { continue }
            $ipId = "ip-$($row.SourceIp)"
            Add-NexusLiteNode -Nodes $nodes -Tracker $nodeTracker -Id $ipId -Type 'ip' -Label $row.SourceIp
            Add-NexusLiteEdge -Edges $edges -Tracker $edgeTracker -Edge ([ordered]@{
                id = "edge-rdp-$($row.SourceIp)-$($row.TimeCreated)"
                type = 'rdp_logon'
                src = $ipId
                dst = $hostId
                timestamp = Convert-ToTimelineTimestamp $row.TimeCreated
                note = "$($row.Domain)\$($row.User)"
            })
        }
    }

    $graph = [PSCustomObject][ordered]@{
        nodes = [object[]]$nodes.ToArray()
        edges = [object[]]$edges.ToArray()
    }

    $nexusPath = Join-Path $netFolder "Nexus_Graph_Lite.json"
    $graph | ConvertTo-Json -Depth 10 | Out-File -FilePath $nexusPath -Encoding UTF8
    WriteHash -FilePath $nexusPath
    WriteLog -Level "INFO" -Message "Nexus Lite graph generated successfully at $nexusPath"
}
if ($NexusLite) { Export-NexusLite }

# Analysis: CE Findings
function Import-CsvSafe {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return @() }
    try {
        return @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    } catch {
        WriteLog -Level "WARN" -Message "Failed to import CSV for analysis: $Path Error=$($_.Exception.Message)"
        return @()
    }
}

function Test-HighRiskPath {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -match '(?i)\\AppData\\|\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\Recycle\.Bin\\|\\Windows\\Tasks\\|\\Windows\\System32\\spool\\drivers\\color\\') { return $true }
    if ($Value -match '(?i)\\ProgramData\\' -and $Value -notmatch '(?i)\\ProgramData\\Microsoft\\|\\ProgramData\\NVIDIA Corporation\\|\\ProgramData\\Package Cache\\') { return $true }
    return $false
}

function Test-SuspiciousCommand {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -match '(?i)EncodedCommand|FromBase64String|DownloadString|Invoke-WebRequest|Invoke-Expression|\bIEX\b|bitsadmin|certutil\s+.*(-decode|-urlcache)|mshta\s+.*(http|javascript|vbscript)|rundll32\s+.*(javascript|http|url\.dll|shell32)|regsvr32\s+.*(/i:http|scrobj\.dll)|wscript\s+.*(http|\.vbs|\.js)|cscript\s+.*(http|\.vbs|\.js)|psexec|mimikatz|rubeus')
}

function Get-ExecutablePathCandidate {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    $expanded = [Environment]::ExpandEnvironmentVariables($Value.Trim())
    if ($expanded -match '^"([^"]+)"') { return $matches[1] }
    if ($expanded -match '^(.*?\.exe)\b') { return $matches[1].Trim() }
    if ($expanded -match '^(\S+)') { return $matches[1].Trim() }
    return $expanded
}

function New-ForensicFinding {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Severity,
        [double]$Confidence,
        [string]$Category,
        [string]$Title,
        [string]$Evidence,
        [string]$Source,
        [string]$SourceDetail = "",
        [string]$RuleId = "",
        [string]$Recommendation = "Review this artifact in context before drawing conclusions."
    )

    $Findings.Add([PSCustomObject]@{
        id = "PTF-{0:D4}" -f ($Findings.Count + 1)
        rule_id = $RuleId
        severity = $Severity
        confidence = $Confidence.ToString("0.00", [System.Globalization.CultureInfo]::InvariantCulture)
        category = $Category
        title = $Title
        evidence = $Evidence
        source_file = $Source
        source_detail = $SourceDetail
        source = $(if ([string]::IsNullOrWhiteSpace($SourceDetail)) { $Source } else { "$Source :: $SourceDetail" })
        recommendation = $Recommendation
        generated_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    }) | Out-Null
}

function Export-ForensicFindings {
    Write-Host "Generating forensic findings..." -ForegroundColor Yellow
    WriteLog -Level "INFO" -Message "Generating CE forensic findings from collected artifacts."

    $findingsFolder = Join-Path $FolderCreation "Findings"
    New-Item -Path $findingsFolder -ItemType Directory -Force | Out-Null

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($row in (Import-CsvSafe -Path (Join-Path $FolderCreation "System\Autoruns_Registry.csv"))) {
        $value = [string]$row.Value
        if ((Test-HighRiskPath -Value $value) -or (Test-SuspiciousCommand -Value $value)) {
            New-ForensicFinding -Findings $findings -Severity "High" -Confidence 0.78 -Category "Persistence" `
                -Title "Autorun entry points to a high-risk path or command" `
                -Evidence "Location=$($row.Location); Name=$($row.Name); Value=$value" `
                -Source "System\Autoruns_Registry.csv" -SourceDetail "Location=$($row.Location); Name=$($row.Name)" -RuleId "PT-CE-AUTORUN-HIGHRISK"
        }
    }

    foreach ($row in (Import-CsvSafe -Path (Join-Path $FolderCreation "System\ScheduledTasks\ScheduledTasks.csv"))) {
        $action = [string]$row.Action
        $taskName = "$($row.TaskPath)$($row.TaskName)"
        $taskExe = Get-ExecutablePathCandidate -Value $action
        if (Test-SuspiciousCommand -Value $action) {
            New-ForensicFinding -Findings $findings -Severity "High" -Confidence 0.82 -Category "Persistence" `
                -Title "Scheduled task action contains suspicious command patterns" `
                -Evidence "Task=$taskName; State=$($row.State); Action=$action" `
                -Source "System\ScheduledTasks\ScheduledTasks.csv" -SourceDetail "Task=$taskName" -RuleId "PT-CE-TASK-SUSPICIOUS"
        } elseif (Test-HighRiskPath -Value $taskExe) {
            New-ForensicFinding -Findings $findings -Severity "Medium" -Confidence 0.68 -Category "Persistence" `
                -Title "Scheduled task action points to a high-risk path" `
                -Evidence "Task=$taskName; Executable=$taskExe; Action=$action" `
                -Source "System\ScheduledTasks\ScheduledTasks.csv" -SourceDetail "Task=$taskName" -RuleId "PT-CE-TASK-HIGHRISK"
        }
    }

    foreach ($row in (Import-CsvSafe -Path (Join-Path $FolderCreation "System\All_Services.csv"))) {
        $pathName = [string]$row.Service_PathName
        $serviceExe = Get-ExecutablePathCandidate -Value $pathName
        if (Test-HighRiskPath -Value $serviceExe) {
            New-ForensicFinding -Findings $findings -Severity "High" -Confidence 0.76 -Category "Persistence" `
                -Title "Service binary path is in a high-risk location" `
                -Evidence "Service=$($row.Service_Name); Executable=$serviceExe; Path=$pathName" `
                -Source "System\All_Services.csv" -SourceDetail "Service=$($row.Service_Name)" -RuleId "PT-CE-SERVICE-HIGHRISK"
        }
    }

    foreach ($row in (Import-CsvSafe -Path (Join-Path $FolderCreation "ProcessInformation\ProcessList.csv"))) {
        $cmd = [string]$row.Proc_CommandLine
        $procPath = [string]$row.Proc_Path
        if (Test-SuspiciousCommand -Value $cmd) {
            New-ForensicFinding -Findings $findings -Severity "High" -Confidence 0.80 -Category "Execution" `
                -Title "Running process command line contains suspicious patterns" `
                -Evidence "Process=$($row.Proc_Name); PID=$($row.Proc_Id); CommandLine=$cmd" `
                -Source "ProcessInformation\ProcessList.csv" -SourceDetail "PID=$($row.Proc_Id); Process=$($row.Proc_Name)" -RuleId "PT-CE-PROCESS-SUSPICIOUS"
        } elseif (Test-HighRiskPath -Value $procPath) {
            New-ForensicFinding -Findings $findings -Severity "Medium" -Confidence 0.66 -Category "Execution" `
                -Title "Process runs from a high-risk location" `
                -Evidence "Process=$($row.Proc_Name); PID=$($row.Proc_Id); Path=$procPath" `
                -Source "ProcessInformation\ProcessList.csv" -SourceDetail "PID=$($row.Proc_Id); Process=$($row.Proc_Name)" -RuleId "PT-CE-PROCESS-HIGHRISK"
        }
    }

    foreach ($row in (Import-CsvSafe -Path (Join-Path $FolderCreation "Network\TCP_Connections.csv"))) {
        $remote = [string]$row.RemoteAddress
        if ($row.State -eq "Established" -and $remote -and $remote -notmatch '^(127\.|::1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') {
            New-ForensicFinding -Findings $findings -Severity "Low" -Confidence 0.48 -Category "Network" `
                -Title "Established external TCP connection observed" `
                -Evidence "Remote=${remote}:$($row.RemotePort); Local=$($row.LocalAddress):$($row.LocalPort); PID=$($row.OwningProcess)" `
                -Source "Network\TCP_Connections.csv" -SourceDetail "Remote=${remote}:$($row.RemotePort); PID=$($row.OwningProcess)" -RuleId "PT-CE-NET-EXTERNAL"
        }
    }

    $csvPath = Join-Path $findingsFolder "Findings.csv"
    $jsonlPath = Join-Path $findingsFolder "Findings.jsonl"
    $txtPath = Join-Path $findingsFolder "Findings_Summary.txt"

    $findings | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8
    $findings | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 } | Out-File -FilePath $jsonlPath -Encoding UTF8

    $summary = @()
    $summary += "PowerTriage CE forensic findings"
    $summary += "Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    $summary += "Total findings: $($findings.Count)"
    foreach ($sev in @("High", "Medium", "Low")) {
        $summary += "$sev`: $(($findings | Where-Object severity -eq $sev).Count)"
    }
    $summary += ""
    $summary += "These findings are triage leads and require analyst review."
    $summary | Out-File -FilePath $txtPath -Encoding UTF8

    WriteHash -FilePath $csvPath
    WriteHash -FilePath $jsonlPath
    WriteHash -FilePath $txtPath
    WriteLog -Level "INFO" -Message "CE forensic findings generated. Count=$($findings.Count)"
}
if ($GenerateFindings) { Export-ForensicFindings }

function Export-ExecutiveReport {
    Write-Host "Generating Executive HTML Report..." -ForegroundColor Yellow
    WriteLog -Level "INFO" -Message "Generating CE Executive HTML report."

    $sysInfo = Get-ComputerInfo | Select-Object OsName, OsVersion, OsArchitecture, CsName, TimeZone, WindowsVersion
    $ipV4 = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch "Loopback" }).IPAddress -join ", "
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    $totalConns = @($conns).Count
    $established = (@($conns | Where-Object State -eq "Established")).Count
    $listening = (@($conns | Where-Object State -eq "Listen")).Count
    $topIPs = @($conns | Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -notmatch "^127\.|^::1" } | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 5 Name, Count)
    $procCount = (Get-Process -ErrorAction SilentlyContinue).Count

    $findings = Import-CsvSafe -Path (Join-Path $FolderCreation "Findings\Findings.csv")
    $highFindings = (@($findings | Where-Object severity -eq "High")).Count
    $mediumFindings = (@($findings | Where-Object severity -eq "Medium")).Count
    $lowFindings = (@($findings | Where-Object severity -eq "Low")).Count
    $topFindings = @($findings | Sort-Object @{Expression={
        switch ($_.severity) {
            "High" { 1 }
            "Medium" { 2 }
            "Low" { 3 }
            default { 4 }
        }
    }}, @{Expression="confidence"; Descending=$true} | Select-Object -First 10)

    $timelinePath = Join-Path $FolderCreation "Timeline\PowerTriage_Timeline_Chronos.json"
    $timelineCount = 0
    if (Test-Path -LiteralPath $timelinePath) {
        try { $timelineCount = @((Get-Content -LiteralPath $timelinePath -Raw | ConvertFrom-Json)).Count } catch {}
    }

    $nexusPath = Join-Path $FolderCreation "Network\Nexus_Graph_Lite.json"
    $nexusNodeCount = 0
    $nexusEdgeCount = 0
    if (Test-Path -LiteralPath $nexusPath) {
        try {
            $nexusGraph = Get-Content -LiteralPath $nexusPath -Raw | ConvertFrom-Json
            $nexusNodeCount = @($nexusGraph.nodes).Count
            $nexusEdgeCount = @($nexusGraph.edges).Count
        } catch {}
    }

    $findingRows = if ($topFindings.Count -gt 0) {
        ($topFindings | ForEach-Object {
            $sev = [System.Net.WebUtility]::HtmlEncode($_.severity)
            $title = [System.Net.WebUtility]::HtmlEncode($_.title)
            $category = [System.Net.WebUtility]::HtmlEncode($_.category)
            $source = [System.Net.WebUtility]::HtmlEncode($_.source)
            "<tr><td><span class='sev-$($sev.ToLower())'>$sev</span></td><td>$category</td><td>$title</td><td>$source</td></tr>"
        }) -join "`n"
    } else {
        "<tr><td colspan='4'>No findings were generated from the available artifacts.</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PowerTriage CE - Executive Summary</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #d4d4d4; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #007acc; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #007acc; }
        .timestamp { color: #888; }
        .card-container { display: flex; flex-wrap: wrap; gap: 20px; }
        .card { background-color: #252526; border: 1px solid #333; border-radius: 5px; padding: 15px; flex: 1; min-width: 300px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .card h3 { margin-top: 0; color: #4ec9b0; border-bottom: none; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #333; vertical-align: top; }
        th { color: #569cd6; }
        .sev-high { color: #ff5c5c; font-weight: bold; }
        .sev-medium { color: #ffb454; font-weight: bold; }
        .sev-low { color: #9cdcfe; font-weight: bold; }
        .footer { margin-top: 50px; text-align: center; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">PowerTriage CE</div>
        <div class="timestamp">Generated: $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))</div>
    </div>

    <div class="card-container">
        <div class="card">
            <h3>System Information</h3>
            <table>
                <tr><th>Hostname</th><td>$($sysInfo.CsName)</td></tr>
                <tr><th>OS</th><td>$($sysInfo.OsName) ($($sysInfo.OsArchitecture))</td></tr>
                <tr><th>Version</th><td>$($sysInfo.WindowsVersion)</td></tr>
                <tr><th>IP Address(es)</th><td>$ipV4</td></tr>
                <tr><th>Timezone</th><td>$($sysInfo.TimeZone)</td></tr>
            </table>
        </div>

        <div class="card">
            <h3>Triage Summary</h3>
            <table>
                <tr><th>Running Processes</th><td>$procCount</td></tr>
                <tr><th>Total Connections</th><td>$totalConns</td></tr>
                <tr><th>Established</th><td>$established</td></tr>
                <tr><th>Listening Ports</th><td>$listening</td></tr>
                <tr><th>Findings</th><td>High: $highFindings | Medium: $mediumFindings | Low: $lowFindings</td></tr>
                <tr><th>Timeline Events</th><td>$timelineCount</td></tr>
                <tr><th>Nexus Lite</th><td>Nodes: $nexusNodeCount | Edges: $nexusEdgeCount</td></tr>
            </table>
        </div>
    </div>

    <br>

    <div class="card-container">
        <div class="card">
            <h3>Top Remote IPs (Established)</h3>
            <table>
                <tr><th>IP Address</th><th>Count</th></tr>
                $($topIPs | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.Count)</td></tr>" } | Out-String)
            </table>
        </div>
        <div class="card">
            <h3>Forensic Findings</h3>
            <table>
                <tr><th>Severity</th><th>Category</th><th>Finding</th><th>Source</th></tr>
                $findingRows
            </table>
        </div>
    </div>

    <div class="footer">
        Generated by PowerTriage CE | <a href="https://powerforensics.es" style="color: #666;">powerforensics.es</a>
    </div>
</body>
</html>
"@

    $reportPath = Join-Path $FolderCreation "Executive_Report.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    WriteHash -FilePath $reportPath
    WriteLog -Level "INFO" -Message "CE Executive Report generated: $reportPath"
}
if ($GenerateExecutiveReport) { Export-ExecutiveReport }

# Task 36: Forensic Catalog (JSON)
function Export-ForensicCatalog {
    Write-Host "Generating Forensic Catalog (JSON)..."
    WriteLog -Level "INFO" -Message "Generating Forensic Catalog (JSON)..."

    # Gather System Info for Asset Auto-Creation
    $sysInfo = @{}
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($null -eq $osInfo) { $osInfo = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue }
        
        if ($osInfo) {
            $sysInfo["os_name"] = $osInfo.Caption
            $sysInfo["os_version"] = $osInfo.Version
            $sysInfo["os_build"] = $osInfo.BuildNumber
            $sysInfo["os_arch"] = $osInfo.OSArchitecture
        }
    } catch {}

    try {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch "Loopback" } | Select-Object -ExpandProperty IPAddress
        $sysInfo["ip_addresses"] = $ips
    } catch {}

    try {
        $usrs = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        if ($null -eq $usrs) { $usrs = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name }
        $sysInfo["users"] = $usrs
    } catch {}

    $catalog = @{
        metadata = @{
            hostname = $env:COMPUTERNAME
            timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            case_id = "PowerTriage_Standard"
            version = $Version
            edition = "Standard (OpenSource)"
            system_info = $sysInfo
            browser_collection_mode = $BrowserCollectionMode
            output_retention = $OutputRetention
            timeline_enabled = [bool]$Timeline
            nexus_lite_enabled = [bool]$NexusLite
            packet_capture = $null
        }
        artifacts = @{
            user = @()
            system = @()
            filesystem = @()
        }
    }

    # Load Hashes if available
    $hashTable = @{}
    $hashFile = "$FolderCreation\Hashes.csv"
    if (Test-Path $hashFile) {
        try {
             $content = Get-Content $hashFile
             foreach ($line in $content) {
                $parts = $line -split ","
                if ($parts.Count -ge 3) {
                    $hVal = $parts[1]
                    $hPath = $parts[2..($parts.Count-1)] -join ","
                    $hashTable[$hPath] = $hVal
                }
             }
        } catch {
            WriteLog -Level "WARN" -Message "Failed to load Hashes.csv: $_"
        }
    }

    # Helper to determine category based on path
    $allFiles = Get-ChildItem -Path $FolderCreation -Recurse -File
    foreach ($file in $allFiles) {
        # Calculate relative path
        $relPath = $file.FullName.Substring($FolderCreation.Length + 1)
        
        # Categorize
        $category = "system" # Default
        if ($relPath -match "^Browsers" -or $relPath -match "^EmailArtifacts" -or $relPath -match "^RemoteAccess") {
            $category = "user"
        } elseif ($relPath -match "^FileSystem" -or $relPath -match "^VSS") {
            $category = "filesystem"
        } elseif ($relPath -match "^System" -or $relPath -match "^Network" -or $relPath -match "^ProcessInformation" -or $relPath -match "^EventsLogs" -or $relPath -match "^Registry") {
            $category = "system"
        }
        
        # Lookup Hash
        $fileHash = "Pending"
        if ($hashTable.ContainsKey($file.FullName)) {
            $fileHash = $hashTable[$file.FullName]
        }

        # Add to catalog
        $item = @{
            path = $relPath
            size = $file.Length
            created = $file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            modified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            hash = $fileHash
        }
        
        $catalog.artifacts[$category] += $item
    }

    $packetCaptureReportPath = Join-Path $FolderCreation "Network\PacketCapture\PacketCapture_Report.json"
    if (Test-Path -LiteralPath $packetCaptureReportPath) {
        try {
            $catalog.metadata.packet_capture = Get-Content -Path $packetCaptureReportPath -Raw | ConvertFrom-Json
        } catch {
            WriteLog -Level "WARN" -Message "Failed to load PacketCapture_Report.json: $($_.Exception.Message)"
        }
    }

    $json = $catalog | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath "$FolderCreation\ForensicCatalog.json" -Encoding UTF8
    WriteLog -Level "INFO" -Message "Forensic Catalog generated."
}
Export-ForensicCatalog

# Task 35: Zip
function Zip-Results {
   param(
       [string]$SourceDirectory,
       [string]$ZipPath
   )

   $result = [PSCustomObject]@{
       Requested = $true
       Created = $false
       Path = $ZipPath
       Error = $null
   }

   Write-Host "Running task 35 (Final)" -ForegroundColor Yellow
   Write-Host "Write results to $ZipPath..."

   Write-Progress -Activity "Zipping Results" -Status "Compressing..." -PercentComplete 50

   # Give file system a moment to release handles
   Start-Sleep -Seconds 2

   try {
       Add-Type -AssemblyName System.IO.Compression.FileSystem
       if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
       [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceDirectory, $ZipPath)
       $result.Created = (Test-Path -LiteralPath $ZipPath)
   } catch {
       Write-Warning "Native Zip failed, falling back to Compress-Archive. Error: $_"
       try {
           Compress-Archive -Force -LiteralPath $SourceDirectory -DestinationPath $ZipPath
           $result.Created = (Test-Path -LiteralPath $ZipPath)
       } catch {
           $result.Error = $_.Exception.Message
       }
   }

   Write-Progress -Activity "Zipping Results" -Completed

   if (-not $result.Created -and -not $result.Error) {
       $result.Error = "ZIP output was requested but not created."
   }

   return $result
}

$zipPath = "$FolderCreation.zip"
$zipResult = [PSCustomObject]@{
    Requested = $false
    Created = $false
    Path = $zipPath
    Error = $null
}

if ($OutputRetention -eq 'DirectoryOnly') {
    Write-Host "Running task 35 (Final)" -ForegroundColor Yellow
    Write-Host "Skipping ZIP generation because -OutputRetention DirectoryOnly was selected."
    WriteLog -Level "INFO" -Message "Skipping ZIP generation because OutputRetention is DirectoryOnly."
} else {
    $zipResult = Zip-Results -SourceDirectory $FolderCreation -ZipPath $zipPath
    if ($zipResult.Created) {
        WriteLog -Level "INFO" -Message "ZIP package created successfully at $($zipResult.Path)"
    } else {
        WriteLog -Level "WARN" -Message "ZIP package was requested but not created. Error: $($zipResult.Error)"
    }
}

# Calculate Final ZIP Hash for Chain of Custody
$FinalHash = "N/A"
if ($zipResult.Created -and (Test-Path -LiteralPath $zipPath)) {
    $FinalHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
}

$DirectoryRemoved = $false
if ($OutputRetention -eq 'ZipOnly') {
    if ($zipResult.Created -and (Test-Path -LiteralPath $zipPath)) {
        try {
            WriteLog -Level "INFO" -Message "Removing uncompressed output directory because OutputRetention is ZipOnly."
            Remove-Item -LiteralPath $FolderCreation -Recurse -Force -ErrorAction Stop
            $DirectoryRemoved = $true
        } catch {
            Write-Warning "ZIP was created but the directory could not be removed. Keeping directory. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "ZipOnly was requested, but ZIP creation failed. Keeping the directory output."
    }
}

$DirectoryStatus = if ($DirectoryRemoved) { "Removed after ZIP creation" } else { $FolderCreation }
$ZipStatus = if ($zipResult.Created) { $zipPath } elseif ($OutputRetention -eq 'DirectoryOnly') { "Not requested" } else { "Not created" }
$LogStatus = if ($DirectoryRemoved) { "Removed with directory after ZIP creation" } else { $LogFile }

Write-Host "==============================================================" 
Write-Host "                              All tasks done                 " -ForegroundColor Yellow 
Write-Host "                                                              " 
Write-Host "                              OutputRetention: $OutputRetention" -ForegroundColor Green
Write-Host "                              Directory: $DirectoryStatus" -ForegroundColor Green
Write-Host "                              ZIP: $ZipStatus" -ForegroundColor Green
Write-Host "                              ZIP SHA256: $FinalHash          " -ForegroundColor Cyan
Write-Host "                              Log: $LogStatus                 " -ForegroundColor Gray 
Write-Host "" 
Write-Host "                   Good luck in your investigation :)" -ForegroundColor Gray 
Write-Host "" 
Write-Host " PowerTriage is a PowerForensics tool " -ForegroundColor Green 
Write-Host " PowerForensics - https://powerforensics.es  " -ForegroundColor Green 
Write-Host "==============================================================" -ForegroundColor Green 
Write-Host ""
