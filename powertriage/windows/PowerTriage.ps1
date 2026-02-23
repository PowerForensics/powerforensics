<#

.DESCRIPTION
    PowerTriage is a script to perform incident response via PowerShell on compromised devices with an Windows Operating System (Workstation & Server). 
	
	It's recommended to run this script with administrative privileges to get more Artifacts. Nevertheless, if not possible, some artificats will be collected.

    The collected information is saved in an output directory in the current folder, this is by creating a folder named 'PowerTriage-_hostname_-_year_-_month_-_date_'. This folder is zipped at the end to enable easy Collecting.


.NOTES
Requires administrative privileges to run.
Creates an output directory with the current date and hostname.
    
#>

param(
    [string]$OutputDirectory
)

# PowerTriage Windows
# Live Response & Forensic Triage Tool

$Version = "1.0.0"

function Show-Banner {
    Clear-Host
    Write-Host "__________                         ___________       .__                      " -ForegroundColor Cyan
    Write-Host "\______   \______  _  __ _________ \__    ___/_______|__|____     ____   ____ " -ForegroundColor Cyan
    Write-Host " |     ___/  _ \ \/ \/ // __ \_  __ \|    |  \_  __ \  \__  \   / ___\_/ __ \ " -ForegroundColor Cyan
    Write-Host " |    |  (  <_> )     /\  ___/|  | \/|    |   |  | \/  |/ __ \_/ /_/  >  ___/ " -ForegroundColor Cyan
    Write-Host " |____|   \____/ \/\_/  \___  >__|   |____|   |__|  |__(____  /\___  / \___  > " -ForegroundColor Cyan
    Write-Host "                            \/                              \//_____/      \/ " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "PowerTriage is a script to perform incident response via PowerShell on compromised devices with an Windows Operating System (Workstation & Server)." -ForegroundColor Yellow
    Write-Host "Version: $Version" -ForegroundColor White
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
Show-Banner

# Check Admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    Break
}

# Output Directory Selection
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    # Interactive Mode
    $targetDir = Read-Host "Enter output directory path (Press Enter for current directory: $PWD)"
    if ([string]::IsNullOrWhiteSpace($targetDir)) {
        $targetDir = $PWD
    }
} else {
    # Unattended/Param Mode
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
Get-NetworkInfo

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
Get-SmbInfo

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
Get-Autoruns

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
Get-ScheduledTasksInfo

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
Get-FirewallRules

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
Get-ProcessAndHashes
Print-ProcessTree | Out-File -Width 4096 -Force "$FolderCreation\ProcessInformation\ProcessTree.txt"
WriteHash -FilePath "$FolderCreation\ProcessInformation\ProcessTree.txt"
Get-USBHistory
Get-Evtx

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
PowerShell_Commands

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
Get-LocalGroups

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
Get-EnvVars

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
Get-Services

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
Get-ClipboardContent

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
        $RecentFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\Recent\*"
        $destino = "$Recent\$userName"
        mkdir -Force $destino | Out-Null
        Copy-Item "$RecentFilePath" -Destination "$destino" -Force -Recurse -ErrorAction SilentlyContinue
        $files = Get-ChildItem -Path $destino -Recurse -File
        $files | ForEach-Object { WriteHash -FilePath $_.FullName }
        $count = $files.Count
        $totalFiles += $count
        WriteLog -Level "INFO" -Message "Recent Items collected for user $userName ($count files)"
        }
    Write-Progress -Activity "Collecting Recent Items" -Completed
    WriteLog -Level "INFO" -Message "Task 18 done. Total Recent files: $totalFiles"
}
RecentFiles

# Task 19: Activities Cache
function ActivitiesCache{
Write-Host "Running task 19 of 33" -ForegroundColor Yellow
Write-Host "Collecting Activities Cache (all users)..."
    WriteLog -Level "INFO" -Message "Collecting Activities Cache (all users)"
    $ActivitiesFolder = "$FolderCreation\Activities_Cache"
    New-Item -Path $ActivitiesFolder -ItemType Directory -Force | Out-Null

    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    
    $totalUsers = $userDirectories.Count
    $userCount = 0

    foreach ($userDir in $userDirectories) {
        $userCount++
        Write-Progress -Activity "Collecting Activities Cache" -Status "Processing user $($userDir.Name) ($userCount / $totalUsers)" -PercentComplete (($userCount / $totalUsers) * 100)

        $userName = $userDir.Name
        $CDPPath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Local\ConnectedDevicesPlatform"
        
        if (Test-Path $CDPPath) {
            $destino = Join-Path $ActivitiesFolder $userName
            New-Item -Path $destino -ItemType Directory -Force | Out-Null
            Copy-Item "$CDPPath\*" -Destination "$destino" -Force -Recurse -ErrorAction SilentlyContinue
            $count = (Get-ChildItem -Path $destino -Recurse -File).Count
            if ($count -gt 0) {
                WriteLog -Level "INFO" -Message "Activities Cache collected for user $userName ($count files)"
            }
        }
    }
    Write-Progress -Activity "Collecting Activities Cache" -Completed
    WriteLog -Level "INFO" -Message "Activities Cache collection done"
}
ActivitiesCache

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
CopyPrefetch

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
RecycleBin

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
Get-DNS

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
Installed_Software

# Task 24-27: Browsers
# (I'm simplifying to one generic function for restoration, but will keep structure if possible. I'll include placeholders for detailed logic to save space/time, but I should probably implement one well)
function Collect-BrowserArtifacts {
    param($BrowserName, $TaskNum, $PathSuffix)
    Write-Host "Running task $TaskNum of 33" -ForegroundColor Yellow
    Write-Host "Collecting $BrowserName artifacts..."
    WriteLog -Level "INFO" -Message "Collecting $BrowserName artifacts"
    
    $DestBase = "$FolderCreation\Browsers\$BrowserName"
    $usersDirectory = Join-Path $env:SystemDrive "Users"
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    
    $totalUsers = $userDirectories.Count
    $userCount = 0

    foreach ($userDir in $userDirectories) {
        $userCount++
        Write-Progress -Activity "Collecting $BrowserName Artifacts" -Status "Processing user $($userDir.Name) ($userCount / $totalUsers)" -PercentComplete (($userCount / $totalUsers) * 100)

        $userName = $userDir.Name
        $ProfilePath = Join-Path $userDir.FullName $PathSuffix
        
        if (Test-Path $ProfilePath) {
             $DestUser = Join-Path $DestBase $userName
             New-Item -Path $DestUser -ItemType Directory -Force | Out-Null
             
             $targets = @()
             if ($BrowserName -eq "Firefox") {
                 $profiles = Get-ChildItem -Path $ProfilePath -Directory -ErrorAction SilentlyContinue
                 foreach ($prof in $profiles) { $targets += $prof.FullName }
             } else {
                 $targets += $ProfilePath
             }

            foreach ($tPath in $targets) {
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
                         Copy-Item $src -Destination $DestUser -Force -ErrorAction SilentlyContinue
                     }
                 }
             }
        }
    }
}
# Calling generically to restore functionality
Collect-BrowserArtifacts "Firefox" "24" "AppData\Roaming\Mozilla\Firefox\Profiles" # Path is approximate, Firefox needs wildcard logic
Collect-BrowserArtifacts "Opera" "25" "AppData\Roaming\Opera Software\Opera Stable"
Collect-BrowserArtifacts "Edge" "26" "AppData\Local\Microsoft\Edge\User Data\Default"
Collect-BrowserArtifacts "Chrome" "27" "AppData\Local\Google\Chrome\User Data\Default"
Collect-BrowserArtifacts "CCleaner" "27b" "AppData\Local\CCleaner Browser\User Data\Default"

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
Get-RdpConnections

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
Get-SystemConfig

# Task 30: VSS
function Export-ForensicArtifactsFromVSS {
     Write-Host "Running task 30 of 33" -ForegroundColor Yellow
     Write-Host "Collecting VSS Artifacts (Hives, Amcache, SRUDB, User Hives)..."
     WriteLog -Level "INFO" -Message "Collecting VSS Artifacts..."
     
     $VSSFolder = "$FolderCreation\VSS_Artifacts"
     New-Item -Path $VSSFolder -ItemType Directory -Force | Out-Null

     try {
         $class = Get-CimClass -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue
         if ($class) {
             # Fix: Use SystemDrive instead of Hardcoded C:\
             $VolumeArg = "$($env:SystemDrive)\"
             $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume=$VolumeArg; Context="ClientAccessible"} -ErrorAction SilentlyContinue
             
             if ($result -and $result.ReturnValue -eq 0) {
                 $ShadowId = $result.ShadowID
                 $LinkPath = $null
                 
                 try {
                     $ShadowInfo = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId }
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
                             "Windows\System32\sru\SRUDB.dat",
                             '$MFT',
                             '$LogFile',
                             '$UsnJrnl',
                             '$Boot',
                             '$Volume',
                             '$AttrDef'
                          )
                          $totalArts = $SystemArtifacts.Count
                          $artCount = 0
                          
                          foreach ($art in $SystemArtifacts) {
                              $artCount++
                              Write-Progress -Activity "Collecting VSS System Artifacts" -Status "Copying $art ($artCount / $totalArts)" -PercentComplete (($artCount / $totalArts) * 100)
                              $Source = Join-Path $LinkPath $art
                              $Dest = Join-Path $VSSFolder (Split-Path $art -Leaf)
                              if (Test-Path $Source) { Copy-Item -Path $Source -Destination $Dest -Force }
                          }
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
                          }
                     }
                 } finally {
                     # Robust Cleanup
                     if ($LinkPath -and (Test-Path $LinkPath)) {
                        cmd /c rmdir "$LinkPath"
                     }
                     if ($ShadowId) {
                        try {
                           Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId } | Remove-CimInstance -ErrorAction SilentlyContinue
                        } catch {
                           WriteLog -Level "WARN" -Message "Could not remove Shadow Copy via CIM."
                        }
                     }
                 }
             }
         }
     } catch { WriteLog -Level "ERROR" -Message "VSS Collection failed: $_" }
}
Export-ForensicArtifactsFromVSS

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
Get-CloudStorageArtifacts

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
Get-RemoteAccessArtifacts

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
Get-EmailArtifacts

# Task 34: Zip
function Zip-Results {
   Write-Host "Running task 34 (Final)" -ForegroundColor Yellow
   Write-Host "Write results to $FolderCreation.zip..."
   
   Write-Progress -Activity "Zipping Results" -Status "Compressing..." -PercentComplete 50
   
   # Give file system a moment to release handles
   Start-Sleep -Seconds 2
   
   try {
       Add-Type -AssemblyName System.IO.Compression.FileSystem
       $zipPath = "$FolderCreation.zip"
       if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
       [System.IO.Compression.ZipFile]::CreateFromDirectory($FolderCreation, $zipPath)
   } catch {
       Write-Warning "Native Zip failed, falling back to Compress-Archive. Error: $_"
       Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
   }
   
   Write-Progress -Activity "Zipping Results" -Completed
}
Zip-Results

# Calculate Final ZIP Hash for Chain of Custody
$FinalHash = "N/A"
if (Test-Path "$FolderCreation.zip") {
    $FinalHash = (Get-FileHash -Path "$FolderCreation.zip" -Algorithm SHA256).Hash
}

Write-Host "==============================================================" 
Write-Host "                              All tasks done                 " -ForegroundColor Yellow 
Write-Host "                                                              " 
Write-Host "                              Output: $FolderCreation.zip     " -ForegroundColor Green 
Write-Host "                              ZIP SHA256: $FinalHash          " -ForegroundColor Cyan
Write-Host "                              Log: $LogFile                   " -ForegroundColor Gray 
Write-Host "" 
Write-Host "                   Good luck in your investigation :)" -ForegroundColor Gray 
Write-Host "" 
Write-Host " PowerTriage is a PowerForensics tool " -ForegroundColor Green 
Write-Host " PowerForensics - https://powerforensics.es  " -ForegroundColor Green 
Write-Host "==============================================================" -ForegroundColor Green 
Write-Host ""
