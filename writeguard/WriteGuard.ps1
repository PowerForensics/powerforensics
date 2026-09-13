<#
.SYNOPSIS
    WriteGuard - DFIR Mode
.DESCRIPTION
    Utilidad segura para activar o desactivar la proteccion logica de escritura en Windows
    antes de conectar dispositivos de almacenamiento externos o evidencias forenses,
    reduciendo el riesgo de contaminacion accidental del disco.
    
    Parte del ecosistema PowerForensics.
    Mas informacion: https://powerforensics.es
.AUTHOR
    PowerForensics (https://powerforensics.es)
.LINK
    https://powerforensics.es
.EXAMPLE
    .\WriteGuard.ps1
    Abre la interfaz grafica por defecto.
.EXAMPLE
    .\WriteGuard.ps1 -Lock
    Activa la proteccion logica de escritura.
.EXAMPLE
    .\WriteGuard.ps1 -PrepareForensicHost
    Activa WriteProtect y deshabilita automount de volumenes.
.EXAMPLE
    .\WriteGuard.ps1 -SelfCheck
    Verifica si el host esta realmente preparado antes de conectar la evidencia.
.EXAMPLE
    .\WriteGuard.ps1 -GUI -Language en
    Abre la interfaz grafica en ingles. Los idiomas admitidos son es y en.
.NOTES
    ADVERTENCIA FORENSE:
    Esta proteccion logica NO sustituye a un write blocker fisico certificado.
    Ayuda a reducir escrituras accidentales del sistema operativo sobre dispositivos conectados.
#>

param (
    [switch]$Lock,
    [switch]$Unlock,
    [switch]$Status,
    [switch]$PrepareForensicHost,
    [switch]$RestoreHost,
    [switch]$SelfCheck,
    [switch]$GUI,
    [ValidateSet("es", "en")]
    [string]$Language
)

# --- Configuracion global ---
$global:LogFile = Join-Path -Path $PSScriptRoot -ChildPath "WriteGuard.log"
$global:RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
$global:RegName = "WriteProtect"
$global:MountMgrRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mountmgr"
$global:MountMgrRegName = "NoAutoMount"

if ([string]::IsNullOrWhiteSpace($Language)) {
    $Language = if ($PSUICulture -like "es*") { "es" } else { "en" }
}
$script:Language = $Language.ToLowerInvariant()

# Textos visibles en Windows Forms. Los identificadores del log se mantienen
# independientes del idioma para facilitar su análisis y correlación.
$script:UiStrings = @{
    es = @{
        UacMessage = "Esta herramienta requiere privilegios de Administrador para modificar el Registro de Windows y gestionar los discos físicos.`n`nAl pulsar Aceptar, Windows solicitará permisos de elevación (UAC)."
        UacTitle = "Privilegios requeridos"
        UacFailure = "No se pudieron obtener privilegios de administrador. El script se cerrará."
        ErrorTitle = "Error"
        InformationTitle = "Información"
        WarningTitle = "Aviso"
        AdminCheckName = "Privilegios de Administrador"
        AdminCheckOk = "La sesión está elevada."
        AdminCheckError = "La sesión no está elevada."
        WriteProtectEnabled = "WriteProtect=1."
        WriteProtectDisabled = "WriteProtect=0."
        AutomountDisabled = "NoAutoMount=1."
        AutomountEnabled = "NoAutoMount=0."
        UnknownState = "Estado desconocido."
        ExternalCheckName = "Discos externos candidatos ya conectados"
        ExternalCheckNone = "No se detectan discos externos candidatos compatibles."
        ExternalCheckFound = "Se han detectado {0} disco(s) externo(s) candidato(s) compatible(s)."
        SelfCheckHeader = "SELF-CHECK DEL HOST FORENSE"
        ExternalDetected = "Discos externos candidatos detectados actualmente:"
        DisconnectBefore = "Desconéctalos antes de conectar la evidencia que vas a adquirir."
        SelfCheckReady = "RESULTADO FINAL: HOST PREPARADO. Ya puedes conectar la evidencia."
        SelfCheckNotReady = "RESULTADO FINAL: HOST NO PREPARADO. Corrige los puntos marcados antes de conectar la evidencia."
        SelfCheckTitle = "Self-Check del Host"
        DiskNoName = "Sin nombre"
        DiskUnknown = "N/D"
        EvidenceTitle = "Gestión de Evidencia"
        CloseHashFirst = "Cancela el cálculo de hash antes de cerrar la ventana."
        ProcessRunningTitle = "Proceso en curso"
        EvidenceInstruction = "Selecciona un disco para documentar sus metadatos o calcular su hash:"
        NoCandidates = "No se han detectado discos externos candidatos compatibles. La herramienta oculta discos de sistema/arranque por seguridad."
        RegisterMetadata = "1. Registrar metadatos en el log"
        MetadataLogged = "Metadatos registrados en el log."
        SelectDisk = "Selecciona primero un disco."
        CalculateHash = "2. Calcular hash SHA256"
        OfflineDisk = "3. Poner disco Offline"
        OfflineBlocked = "Por seguridad, solo se permite poner Offline discos externos compatibles que no sean de sistema ni de arranque."
        OperationBlockedTitle = "Operación bloqueada"
        OfflineSuccess = "El disco {0} se ha puesto Offline. Cierra las herramientas que lo estuvieran utilizando y sigue el procedimiento de extracción segura del dispositivo. El estado Offline no equivale a una expulsión certificada."
        OfflineSuccessTitle = "Disco puesto Offline"
        RemovableOfflineUnsupported = "El disco {0} es un pendrive o medio extraíble y Windows no permite pasarlo a estado Offline.`n`nCon automount deshabilitado y el bloqueo lógico activo se reduce el riesgo de escritura accidental, pero no se elimina. Evita abrir el volumen en Explorer y utiliza el procedimiento de extracción segura admitido por el dispositivo."
        SafeRemovalTitle = "Extracción del dispositivo"
        OfflineFailure = "No se pudo poner el disco Offline: {0}"
        Canceling = "Cancelando..."
        CancelHash = "Cancelar hash"
        HashReading = "Leyendo el disco físico {0} y calculando SHA256..."
        HashCanceled = "Cálculo de hash cancelado."
        CanceledTitle = "Cancelado"
        HashCompleted = "Hash SHA256 calculado y registrado:`n{0}"
        CompletedTitle = "Completado"
        HashFailure = "Error al calcular el hash."
        MainWindowTitle = "WriteGuard - Modo DFIR"
        MainHeading = "Control de bloqueo lógico de escritura"
        StatusReady = "HOST FORENSE PREPARADO"
        StatusProtected = "PROTECCIÓN LÓGICA ACTIVADA"
        StatusWritable = "ESCRITURA PERMITIDA"
        StatusPartial = "ESTADO PARCIAL O DESCONOCIDO"
        Processing = "Procesando, espera un momento..."
        LockButton = "1. Activar protección lógica"
        UnlockButton = "2. Desactivar protección lógica"
        PrepareButton = "3. Preparar host forense"
        RestoreButton = "4. Restaurar host"
        SelfCheckButton = "5. Self-Check del Host"
        DisksButton = "6. Ver discos detectados"
        EvidenceButton = "7. Gestión de Evidencia (metadatos y hash)"
        ExitButton = "8. Salir"
        AboutButton = "9. Acerca de"
        LanguageLabel = "Idioma:"
        LogLabel = "Log: {0}"
        LockSuccess = "Protección lógica de escritura activada. Esta medida reduce el riesgo de contaminación accidental, pero no sustituye a un write blocker físico certificado. Para máxima seguridad forense, prepara el host antes de conectar la evidencia y evita abrir el volumen en Explorer."
        LockFailure = "Error al activar la protección lógica de escritura."
        UnlockSuccess = "Protección lógica de escritura desactivada."
        UnlockFailure = "Error al desactivar la protección lógica de escritura."
        PrepareFailure = "Hubo errores al preparar el host. Revisa el log."
        RestoreSuccess = "Host restaurado correctamente. Escritura permitida y automount habilitado."
        RestoreFailure = "Hubo errores al restaurar el host. Revisa el log."
        DisksTitle = "Discos detectados"
        NoDisks = "No se encontraron discos o hubo un error al obtener la información."
        AboutText = "WriteGuard - DFIR Mode`n`nHerramienta desarrollada para el ecosistema PowerForensics.`nVisítanos en: https://powerforensics.es`n`nAviso: esta protección lógica no sustituye a un bloqueador físico certificado."
        AboutTitle = "Acerca de PowerForensics"
    }
    en = @{
        UacMessage = "This tool requires Administrator privileges to modify the Windows Registry and manage physical disks.`n`nWhen you click OK, Windows will request elevation through UAC."
        UacTitle = "Administrator privileges required"
        UacFailure = "Administrator privileges could not be obtained. The script will close."
        ErrorTitle = "Error"
        InformationTitle = "Information"
        WarningTitle = "Warning"
        AdminCheckName = "Administrator privileges"
        AdminCheckOk = "The session is elevated."
        AdminCheckError = "The session is not elevated."
        WriteProtectEnabled = "WriteProtect=1."
        WriteProtectDisabled = "WriteProtect=0."
        AutomountDisabled = "NoAutoMount=1."
        AutomountEnabled = "NoAutoMount=0."
        UnknownState = "Unknown state."
        ExternalCheckName = "Connected external candidate disks"
        ExternalCheckNone = "No compatible external candidate disks were detected."
        ExternalCheckFound = "{0} compatible external candidate disk(s) detected."
        SelfCheckHeader = "FORENSIC HOST SELF-CHECK"
        ExternalDetected = "External candidate disks currently detected:"
        DisconnectBefore = "Disconnect them before connecting the evidence to be acquired."
        SelfCheckReady = "FINAL RESULT: HOST READY. You may now connect the evidence."
        SelfCheckNotReady = "FINAL RESULT: HOST NOT READY. Correct the marked items before connecting the evidence."
        SelfCheckTitle = "Host Self-Check"
        DiskNoName = "Unnamed"
        DiskUnknown = "N/A"
        EvidenceTitle = "Evidence Management"
        CloseHashFirst = "Cancel the hash calculation before closing this window."
        ProcessRunningTitle = "Process running"
        EvidenceInstruction = "Select a disk to document its metadata or calculate its hash:"
        NoCandidates = "No compatible external candidate disks were detected. System and boot disks are hidden for safety."
        RegisterMetadata = "1. Record metadata in the log"
        MetadataLogged = "Metadata recorded in the log."
        SelectDisk = "Select a disk first."
        CalculateHash = "2. Calculate SHA256 hash"
        OfflineDisk = "3. Set disk Offline"
        OfflineBlocked = "For safety, only compatible external disks that are not system or boot disks may be set Offline."
        OperationBlockedTitle = "Operation blocked"
        OfflineSuccess = "Disk {0} has been set Offline. Close any tools that were using it and follow the device safe-removal procedure. Offline status is not equivalent to certified ejection."
        OfflineSuccessTitle = "Disk set Offline"
        RemovableOfflineUnsupported = "Disk {0} is a removable drive and Windows does not allow it to be set Offline.`n`nDisabling automount and enabling logical write protection reduces, but does not eliminate, the risk of accidental writes. Do not open the volume in Explorer and use the removal procedure supported by the device."
        SafeRemovalTitle = "Device removal"
        OfflineFailure = "The disk could not be set Offline: {0}"
        Canceling = "Canceling..."
        CancelHash = "Cancel hash"
        HashReading = "Reading physical disk {0} and calculating SHA256..."
        HashCanceled = "Hash calculation canceled."
        CanceledTitle = "Canceled"
        HashCompleted = "SHA256 hash calculated and recorded:`n{0}"
        CompletedTitle = "Completed"
        HashFailure = "Error calculating the hash."
        MainWindowTitle = "WriteGuard - DFIR Mode"
        MainHeading = "Logical write protection control"
        StatusReady = "FORENSIC HOST READY"
        StatusProtected = "LOGICAL WRITE PROTECTION ENABLED"
        StatusWritable = "WRITING ENABLED"
        StatusPartial = "PARTIAL OR UNKNOWN STATE"
        Processing = "Processing, please wait..."
        LockButton = "1. Enable logical protection"
        UnlockButton = "2. Disable logical protection"
        PrepareButton = "3. Prepare forensic host"
        RestoreButton = "4. Restore host"
        SelfCheckButton = "5. Host Self-Check"
        DisksButton = "6. View detected disks"
        EvidenceButton = "7. Evidence Management (metadata and hash)"
        ExitButton = "8. Exit"
        AboutButton = "9. About"
        LanguageLabel = "Language:"
        LogLabel = "Log: {0}"
        LockSuccess = "Logical write protection has been enabled. This reduces the risk of accidental contamination, but it does not replace a certified physical write blocker. For maximum forensic safety, prepare the host before connecting evidence and do not open the volume in Explorer."
        LockFailure = "Error enabling logical write protection."
        UnlockSuccess = "Logical write protection has been disabled."
        UnlockFailure = "Error disabling logical write protection."
        PrepareFailure = "Errors occurred while preparing the host. Review the log."
        RestoreSuccess = "The host was restored successfully. Writing is enabled and automount is enabled."
        RestoreFailure = "Errors occurred while restoring the host. Review the log."
        DisksTitle = "Detected disks"
        NoDisks = "No disks were found, or disk information could not be retrieved."
        AboutText = "WriteGuard - DFIR Mode`n`nA tool developed for the PowerForensics ecosystem.`nVisit us at: https://powerforensics.es`n`nNotice: logical protection does not replace a certified physical write blocker."
        AboutTitle = "About PowerForensics"
    }
}

function Get-UiText {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [object[]]$Values
    )

    $text = $script:UiStrings[$script:Language][$Key]
    if ($null -eq $text) {
        $text = $script:UiStrings.en[$Key]
    }
    if ($null -eq $text) {
        return "[$Key]"
    }
    if ($null -ne $Values -and $Values.Count -gt 0) {
        return ($text -f $Values)
    }
    return $text
}

# Cargar ensamblados de GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Funciones Base ---

function Write-Log {
    param (
        [string]$Action,
        [string]$OldValue = "N/A",
        [string]$NewValue = "N/A",
        [string]$Result,
        [string]$ErrorMsg = ""
    )
    $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $User = [Environment]::UserName
    $Computer = [Environment]::MachineName
    
    $LogEntry = "[$Date] | User: $User | Host: $Computer | Action: $Action | Old: $OldValue | New: $NewValue | Result: $Result"
    if ($ErrorMsg) {
        $LogEntry += " | Error: $ErrorMsg"
    }
    
    try {
        Add-Content -Path $global:LogFile -Value $LogEntry -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning "No se pudo escribir en el log: $($_.Exception.Message)"
    }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-AsAdmin {
    if (-not (Test-IsAdmin)) {
        Write-Log -Action "Elevacion requerida" -Result "Reiniciando como Administrador"
        $argList = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", ('"{0}"' -f $PSCommandPath)
        )
        if ($Lock) { $argList += "-Lock" }
        if ($Unlock) { $argList += "-Unlock" }
        if ($Status) { $argList += "-Status" }
        if ($PrepareForensicHost) { $argList += "-PrepareForensicHost" }
        if ($RestoreHost) { $argList += "-RestoreHost" }
        if ($SelfCheck) { $argList += "-SelfCheck" }
        if ($GUI) { $argList += "-GUI" }
        $argList += @("-Language", $script:Language)
        $msg = Get-UiText -Key UacMessage
        [System.Windows.Forms.MessageBox]::Show($msg, (Get-UiText -Key UacTitle), "OK", "Warning") | Out-Null
        
        try {
            Start-Process powershell -Verb RunAs -ArgumentList $argList
            exit
        } catch {
            Write-Log -Action "Elevacion" -Result "Fallo" -ErrorMsg $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key UacFailure), (Get-UiText -Key ErrorTitle), "OK", "Error") | Out-Null
            exit
        }
    }
}

function Get-WriteProtectStatus {
    try {
        if (Test-Path -Path $global:RegPath) {
            $value = Get-ItemProperty -Path $global:RegPath -Name $global:RegName -ErrorAction Stop
            if ($null -ne $value.$global:RegName) {
                if ($value.$global:RegName -eq 1) {
                    return 1
                } elseif ($value.$global:RegName -eq 0) {
                    return 0
                }
            }
        }
        return -1 # Desconocido o no existe
    } catch {
        return -1
    }
}

function Get-AutomountStatus {
    try {
        if (-not (Test-Path -Path $global:MountMgrRegPath)) {
            return -1
        }

        $value = Get-ItemProperty -Path $global:MountMgrRegPath -Name $global:MountMgrRegName -ErrorAction SilentlyContinue
        if ($null -eq $value) {
            return 0
        }

        if ($value.$global:MountMgrRegName -eq 1) {
            return 1
        }

        return 0
    } catch {
        return -1
    }
}

function Invoke-DiskpartScript {
    param (
        [string[]]$Commands
    )

    try {
        $inputString = $Commands -join [Environment]::NewLine
        $output = $inputString | diskpart 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        return [pscustomobject]@{
            Success  = ($exitCode -eq 0)
            ExitCode = $exitCode
            Output   = $output.Trim()
        }
    } catch {
        return [pscustomobject]@{
            Success  = $false
            ExitCode = -1
            Output   = $_.Exception.Message
        }
    }
}

function Set-WriteProtectStatus {
    param (
        [int]$Value
    )
    $oldValue = Get-WriteProtectStatus
    try {
        $parentPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
        $subKey = "StorageDevicePolicies"
        
        # Crear la clave StorageDevicePolicies si no existe
        if (-not (Test-Path -Path "$parentPath\$subKey")) {
            New-Item -Path $parentPath -Name $subKey -Force | Out-Null
        }
        
        # Modificar el valor del registro
        Set-ItemProperty -Path $global:RegPath -Name $global:RegName -Value $Value -Type DWord -Force -ErrorAction Stop
        
        # Verificar lectura para confirmar que el valor escrito coincide
        $newValue = Get-WriteProtectStatus
        if ($newValue -eq $Value) {
            Write-Log -Action "Set-WriteProtectStatus" -OldValue $oldValue -NewValue $newValue -Result "Exito"
            return $true
        } else {
            Write-Log -Action "Set-WriteProtectStatus" -OldValue $oldValue -NewValue $newValue -Result "Fallo al verificar tras escritura"
            return $false
        }
    } catch {
        Write-Log -Action "Set-WriteProtectStatus" -OldValue $oldValue -NewValue "N/A" -Result "Error" -ErrorMsg $_.Exception.Message
        return $false
    }
}

function Get-HostProtectionSummary {
    $writeProtect = Get-WriteProtectStatus
    $automount = Get-AutomountStatus

    return [pscustomobject]@{
        WriteProtect = $writeProtect
        Automount    = $automount
    }
}

function New-SelfCheckItem {
    param (
        [string]$Name,
        [string]$State,
        [string]$Detail
    )

    return [pscustomobject]@{
        Name   = $Name
        State  = $State
        Detail = $Detail
    }
}

function Get-HostSelfCheckResult {
    $summary = Get-HostProtectionSummary
    $candidateDisks = Get-ForensicCandidateDisks
    $checks = @()

    $isAdmin = Test-IsAdmin
    $checks += New-SelfCheckItem -Name (Get-UiText -Key AdminCheckName) -State $(if ($isAdmin) { "OK" } else { "ERROR" }) -Detail $(if ($isAdmin) { Get-UiText -Key AdminCheckOk } else { Get-UiText -Key AdminCheckError })

    $writeProtectOk = ($summary.WriteProtect -eq 1)
    $checks += New-SelfCheckItem -Name "WriteProtect" -State $(if ($writeProtectOk) { "OK" } else { "ERROR" }) -Detail $(if ($writeProtectOk) { Get-UiText -Key WriteProtectEnabled } elseif ($summary.WriteProtect -eq 0) { Get-UiText -Key WriteProtectDisabled } else { Get-UiText -Key UnknownState })

    $automountOk = ($summary.Automount -eq 1)
    $checks += New-SelfCheckItem -Name "Automount" -State $(if ($automountOk) { "OK" } else { "ERROR" }) -Detail $(if ($automountOk) { Get-UiText -Key AutomountDisabled } elseif ($summary.Automount -eq 0) { Get-UiText -Key AutomountEnabled } else { Get-UiText -Key UnknownState })

    $noExternalDisks = ($candidateDisks.Count -eq 0)
    $checks += New-SelfCheckItem -Name (Get-UiText -Key ExternalCheckName) -State $(if ($noExternalDisks) { "OK" } else { "WARN" }) -Detail $(if ($noExternalDisks) { Get-UiText -Key ExternalCheckNone } else { Get-UiText -Key ExternalCheckFound -Values @($candidateDisks.Count) })

    $ready = ($isAdmin -and $writeProtectOk -and $automountOk -and $noExternalDisks)

    return [pscustomobject]@{
        Ready          = $ready
        Summary        = $summary
        CandidateDisks = $candidateDisks
        Checks         = $checks
    }
}

function Format-SelfCheckReport {
    param (
        $Result
    )

    $lines = @(
        (Get-UiText -Key SelfCheckHeader),
        ""
    )

    foreach ($check in $Result.Checks) {
        $lines += "[{0}] {1}: {2}" -f $check.State, $check.Name, $check.Detail
    }

    if ($Result.CandidateDisks.Count -gt 0) {
        $lines += ""
        $lines += Get-UiText -Key ExternalDetected
        foreach ($disk in $Result.CandidateDisks) {
            $lines += " - {0}" -f (Format-DiskDisplay -Disk $disk)
        }
        $lines += Get-UiText -Key DisconnectBefore
    }

    $lines += ""
    if ($Result.Ready) {
        $lines += Get-UiText -Key SelfCheckReady
    } else {
        $lines += Get-UiText -Key SelfCheckNotReady
    }

    return ($lines -join [Environment]::NewLine)
}

function Show-SelfCheckReport {
    param (
        $Result,
        [switch]$AsGui
    )

    if ($null -eq $Result) {
        $Result = Get-HostSelfCheckResult
    }

    $report = Format-SelfCheckReport -Result $Result
    $checkSummary = "WP={0}; AM={1}; EXT={2}" -f $Result.Summary.WriteProtect, $Result.Summary.Automount, $Result.CandidateDisks.Count
    Write-Log -Action "Self-Check" -OldValue "N/A" -NewValue $checkSummary -Result $(if ($Result.Ready) { "Ready" } else { "NotReady" })

    if ($AsGui) {
        $icon = if ($Result.Ready) { "Information" } else { "Warning" }
        [System.Windows.Forms.MessageBox]::Show($report, (Get-UiText -Key SelfCheckTitle), "OK", $icon) | Out-Null
    } else {
        if ($Result.Ready) {
            Write-Host "`n$report`n" -ForegroundColor Green
        } else {
            Write-Host "`n$report`n" -ForegroundColor Yellow
        }
    }

    return $Result.Ready
}

function Enable-LogicalWriteBlock {
    Write-Host "Activando proteccion logica de escritura..." -ForegroundColor Cyan
    $success = Set-WriteProtectStatus -Value 1
    if ($success) {
        Write-Host "`n================================================================================" -ForegroundColor Green
        Write-Host "Proteccion logica de escritura activada. Esta medida reduce el riesgo de" -ForegroundColor Green
        Write-Host "contaminacion accidental, pero no sustituye a un write blocker fisico certificado." -ForegroundColor Green
        Write-Host "Para maxima seguridad forense, conecte la evidencia despues de activar esta" -ForegroundColor Green
        Write-Host "opcion y documente el procedimiento." -ForegroundColor Green
        Write-Host "================================================================================`n" -ForegroundColor Green
    } else {
        Write-Host "Error al activar la proteccion logica de escritura." -ForegroundColor Red
    }
}

function Disable-LogicalWriteBlock {
    Write-Host "Desactivando proteccion logica de escritura..." -ForegroundColor Cyan
    $success = Set-WriteProtectStatus -Value 0
    if ($success) {
        Write-Host "Proteccion logica de escritura desactivada. Escritura permitida." -ForegroundColor Yellow
    } else {
        Write-Host "Error al desactivar la proteccion logica de escritura." -ForegroundColor Red
    }
}

function Disable-Automount {
    $oldValue = Get-AutomountStatus
    try {
        Write-Log -Action "Disable-Automount" -Result "Iniciando"
        $result = Invoke-DiskpartScript -Commands @("automount disable", "automount scrub")
        $newValue = Get-AutomountStatus

        if ($result.Success -and $newValue -eq 1) {
            Write-Log -Action "Disable-Automount" -OldValue $oldValue -NewValue $newValue -Result "Exito"
            return $true
        }

        $errorMsg = "DiskPart ExitCode=$($result.ExitCode). Output: $($result.Output)"
        Write-Log -Action "Disable-Automount" -OldValue $oldValue -NewValue $newValue -Result "Fallo al verificar" -ErrorMsg $errorMsg
        return $false
    } catch {
        Write-Log -Action "Disable-Automount" -OldValue $oldValue -NewValue "N/A" -Result "Error" -ErrorMsg $_.Exception.Message
        return $false
    }
}

function Enable-Automount {
    $oldValue = Get-AutomountStatus
    try {
        Write-Log -Action "Enable-Automount" -Result "Iniciando"
        $result = Invoke-DiskpartScript -Commands @("automount enable")
        $newValue = Get-AutomountStatus

        if ($result.Success -and $newValue -eq 0) {
            Write-Log -Action "Enable-Automount" -OldValue $oldValue -NewValue $newValue -Result "Exito"
            return $true
        }

        $errorMsg = "DiskPart ExitCode=$($result.ExitCode). Output: $($result.Output)"
        Write-Log -Action "Enable-Automount" -OldValue $oldValue -NewValue $newValue -Result "Fallo al verificar" -ErrorMsg $errorMsg
        return $false
    } catch {
        Write-Log -Action "Enable-Automount" -OldValue $oldValue -NewValue "N/A" -Result "Error" -ErrorMsg $_.Exception.Message
        return $false
    }
}

function Prepare-ForensicHost {
    Write-Host "Preparando host forense..." -ForegroundColor Cyan
    $blockSuccess = Set-WriteProtectStatus -Value 1
    $automountSuccess = Disable-Automount
    
    if ($blockSuccess -and $automountSuccess) {
        Write-Host "`n================================================================================" -ForegroundColor Green
        Write-Host "Host preparado para adquisicion logica: WriteProtect activado y automount" -ForegroundColor Green
        Write-Host "deshabilitado. Se recomienda conectar ahora la evidencia, verificar el estado" -ForegroundColor Green
        Write-Host "del disco y adquirir imagen con herramienta forense." -ForegroundColor Green
        Write-Host "================================================================================`n" -ForegroundColor Green
    } else {
        Write-Host "Hubo errores al preparar el host forense. Revise el log." -ForegroundColor Red
    }
    Show-Status
    [void](Show-SelfCheckReport -Result (Get-HostSelfCheckResult))
}

function Restore-Host {
    Write-Host "Restaurando host a estado normal..." -ForegroundColor Cyan
    $blockSuccess = Set-WriteProtectStatus -Value 0
    $automountSuccess = Enable-Automount
    
    if ($blockSuccess -and $automountSuccess) {
        Write-Host "Host restaurado correctamente. Escritura permitida y automount habilitado." -ForegroundColor Green
    } else {
        Write-Host "Hubo errores al restaurar el host. Revise el log." -ForegroundColor Red
    }
    Show-Status
}

function Get-DiskSummary {
    try {
        $disks = Get-Disk | Select-Object Number, FriendlyName, BusType, OperationalStatus, IsReadOnly, IsOffline, IsSystem, IsBoot, Size
        return $disks
    } catch {
        Write-Warning "Error al obtener discos: $($_.Exception.Message)"
        return $null
    }
}

function Test-IsForensicCandidateDisk {
    param (
        $Disk
    )

    if ($null -eq $Disk) {
        return $false
    }

    if ($Disk.IsSystem -or $Disk.IsBoot) {
        return $false
    }

    $externalBusTypes = @("USB", "SD", "MMC", "FireWire", "1394")
    return $externalBusTypes -contains [string]$Disk.BusType
}

function Get-ForensicCandidateDisks {
    try {
        return @(Get-Disk | Where-Object { Test-IsForensicCandidateDisk -Disk $_ })
    } catch {
        Write-Warning "Error al enumerar discos candidatos: $($_.Exception.Message)"
        return @()
    }
}

function Format-DiskDisplay {
    param (
        $Disk
    )

    $sizeGB = [math]::Round($Disk.Size / 1GB, 2)
    $status = if ($Disk.IsOffline) { "Offline" } else { "Online" }
    $readOnly = if ($Disk.IsReadOnly) { "RO" } else { "RW" }
    $model = if ([string]::IsNullOrWhiteSpace($Disk.FriendlyName)) { Get-UiText -Key DiskNoName } else { $Disk.FriendlyName }
    $serial = if ([string]::IsNullOrWhiteSpace($Disk.SerialNumber)) { Get-UiText -Key DiskUnknown } else { $Disk.SerialNumber }
    return "Disk $($Disk.Number): $model - SN: $serial - $sizeGB GB [$status | $readOnly | $($Disk.BusType)]"
}

function Get-PhysicalDriveHash {
    param (
        [int]$DiskNumber,
        $ProgressBar
    )
    $stream = $null
    $sha256 = $null
    try {
        $path = "\\.\PhysicalDrive$DiskNumber"
        $diskInfo = Get-Disk -Number $DiskNumber -ErrorAction Stop
        $totalBytes = $diskInfo.Size
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        
        $bufferSize = 4MB
        $buffer = New-Object byte[] $bufferSize
        $readBytes = 0
        
        while (($read = $stream.Read($buffer, 0, $bufferSize)) -gt 0) {
            if ($script:CancelHash) {
                Write-Log -Action "Hash Calculation" -Result "Cancelado por el usuario"
                return $null
            }
            $sha256.TransformBlock($buffer, 0, $read, $buffer, 0) | Out-Null
            $readBytes += $read
            
            if ($ProgressBar -and $totalBytes -gt 0) {
                $percent = [math]::Round(($readBytes / $totalBytes) * 100)
                if ($percent -ne $ProgressBar.Value) {
                    $ProgressBar.Value = $percent
                    [System.Windows.Forms.Application]::DoEvents()
                }
            }
        }
        
        $sha256.TransformFinalBlock($buffer, 0, 0) | Out-Null
        $hashBytes = $sha256.Hash
        $hashString = [BitConverter]::ToString($hashBytes).Replace("-", "").ToUpper()
        return $hashString
    } catch {
        Write-Warning "Error calculando hash: $($_.Exception.Message)"
        return $null
    } finally {
        if ($stream) {
            $stream.Dispose()
        }
        if ($sha256) {
            $sha256.Dispose()
        }
    }
}

function Write-EvidenceLog {
    param (
        [int]$DiskNumber,
        [string]$FriendlyName,
        [string]$SerialNumber,
        [string]$Size,
        [string]$Hash = "N/A"
    )
    $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $User = [Environment]::UserName
    $Computer = [Environment]::MachineName
    $LogEntry = "[$Date] | User: $User | Host: $Computer | EVIDENCIA | Disk: $DiskNumber | Model: $FriendlyName | SN: $SerialNumber | Size: $Size | SHA256: $Hash"
    try {
        Add-Content -Path $global:LogFile -Value $LogEntry -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning "No se pudo escribir la evidencia en el log: $($_.Exception.Message)"
    }
}

function Show-EvidenceManager {
    $script:CancelHash = $false
    $script:IsHashing = $false

    $formEv = New-Object System.Windows.Forms.Form
    $formEv.Text = Get-UiText -Key EvidenceTitle
    $formEv.Size = New-Object System.Drawing.Size(600,420)
    $formEv.StartPosition = "CenterParent"
    $formEv.FormBorderStyle = "FixedDialog"
    $formEv.MaximizeBox = $false

    $formEv.Add_FormClosing({
        if ($script:IsHashing) {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key CloseHashFirst), (Get-UiText -Key ProcessRunningTitle), "OK", "Warning") | Out-Null
            $_.Cancel = $true
        }
    })
    
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = Get-UiText -Key EvidenceInstruction
    $lblInfo.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
    $lblInfo.Location = New-Object System.Drawing.Point(20, 20)
    $lblInfo.Size = New-Object System.Drawing.Size(550, 40)
    $formEv.Controls.Add($lblInfo)
    
    $lbDisks = New-Object System.Windows.Forms.ListBox
    $lbDisks.Location = New-Object System.Drawing.Point(20, 65)
    $lbDisks.Size = New-Object System.Drawing.Size(540, 105)
    $lbDisks.DisplayMember = "Display"
    $disks = Get-ForensicCandidateDisks
    foreach ($d in $disks) {
        $lbDisks.Items.Add([pscustomobject]@{
            Display = (Format-DiskDisplay -Disk $d)
            Number  = $d.Number
        }) | Out-Null
    }
    $formEv.Controls.Add($lbDisks)

    if ($lbDisks.Items.Count -eq 0) {
        $lblInfo.Text = Get-UiText -Key NoCandidates
    }
    
    $btnDoc = New-Object System.Windows.Forms.Button
    $btnDoc.Text = Get-UiText -Key RegisterMetadata
    $btnDoc.Location = New-Object System.Drawing.Point(20, 185)
    $btnDoc.Size = New-Object System.Drawing.Size(260, 35)
    $btnDoc.Add_Click({
        if ($lbDisks.SelectedItem) {
            $num = $lbDisks.SelectedItem.Number
            $d = Get-Disk -Number $num
            $sizeStr = "$([math]::Round($d.Size / 1GB, 2)) GB"
            Write-EvidenceLog -DiskNumber $num -FriendlyName $d.FriendlyName -SerialNumber $d.SerialNumber -Size $sizeStr
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key MetadataLogged), (Get-UiText -Key InformationTitle), "OK", "Information") | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key SelectDisk), (Get-UiText -Key WarningTitle), "OK", "Warning") | Out-Null
        }
    })
    $formEv.Controls.Add($btnDoc)

    $btnHash = New-Object System.Windows.Forms.Button
    $btnHash.Text = Get-UiText -Key CalculateHash
    $btnHash.Location = New-Object System.Drawing.Point(300, 185)
    $btnHash.Size = New-Object System.Drawing.Size(260, 35)
    $formEv.Controls.Add($btnHash)

    $btnOffline = New-Object System.Windows.Forms.Button
    $btnOffline.Text = Get-UiText -Key OfflineDisk
    $btnOffline.Location = New-Object System.Drawing.Point(20, 230)
    $btnOffline.Size = New-Object System.Drawing.Size(540, 35)
    $btnOffline.Add_Click({
        if ($lbDisks.SelectedItem) {
            $num = $lbDisks.SelectedItem.Number
            $disk = Get-Disk -Number $num -ErrorAction SilentlyContinue
            if (-not (Test-IsForensicCandidateDisk -Disk $disk)) {
                Write-Log -Action "Set-DiskOffline" -OldValue "Disk=$num" -NewValue "N/A" -Result "BlockedNotCandidate"
                [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key OfflineBlocked), (Get-UiText -Key OperationBlockedTitle), "OK", "Warning") | Out-Null
                return
            }

            try {
                $oldOfflineState = $disk.IsOffline
                Set-Disk -Number $num -IsOffline $true -ErrorAction Stop
                Write-Log -Action "Set-DiskOffline" -OldValue "Disk=$num; IsOffline=$oldOfflineState" -NewValue "Disk=$num; IsOffline=True" -Result "Success"
                [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key OfflineSuccess -Values @($num)), (Get-UiText -Key OfflineSuccessTitle), "OK", "Information") | Out-Null
                $formEv.Close()
                Show-EvidenceManager
            } catch {
                if ($_.Exception.Message -match "Removable media cannot be set to offline" -or $_.Exception.Message -match "medio extraible") {
                    Write-Log -Action "Set-DiskOffline" -OldValue "Disk=$num" -NewValue "Unchanged" -Result "UnsupportedRemovable" -ErrorMsg $_.Exception.Message
                    $msgRemovable = Get-UiText -Key RemovableOfflineUnsupported -Values @($num)
                    [System.Windows.Forms.MessageBox]::Show($msgRemovable, (Get-UiText -Key SafeRemovalTitle), "OK", "Information") | Out-Null
                } else {
                    Write-Log -Action "Set-DiskOffline" -OldValue "Disk=$num" -NewValue "Unknown" -Result "Error" -ErrorMsg $_.Exception.Message
                    [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key OfflineFailure -Values @($_.Exception.Message)), (Get-UiText -Key ErrorTitle), "OK", "Error") | Out-Null
                }
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key SelectDisk), (Get-UiText -Key WarningTitle), "OK", "Warning") | Out-Null
        }
    })
    $formEv.Controls.Add($btnOffline)

    $pbHash = New-Object System.Windows.Forms.ProgressBar
    $pbHash.Location = New-Object System.Drawing.Point(20, 285)
    $pbHash.Size = New-Object System.Drawing.Size(540, 25)
    $pbHash.Style = "Continuous"
    $pbHash.Minimum = 0
    $pbHash.Maximum = 100
    $pbHash.Value = 0
    $pbHash.Visible = $false
    $formEv.Controls.Add($pbHash)

    $lblHashStatus = New-Object System.Windows.Forms.Label
    $lblHashStatus.Location = New-Object System.Drawing.Point(20, 315)
    $lblHashStatus.Size = New-Object System.Drawing.Size(540, 20)
    $lblHashStatus.Text = ""
    $lblHashStatus.TextAlign = "MiddleCenter"
    $formEv.Controls.Add($lblHashStatus)

    $btnHash.Add_Click({
        if ($script:IsHashing) {
            $script:CancelHash = $true
            $btnHash.Text = Get-UiText -Key Canceling
            $btnHash.Enabled = $false
            return
        }

        if ($lbDisks.SelectedItem) {
            $num = $lbDisks.SelectedItem.Number
            $d = Get-Disk -Number $num
            $sizeStr = "$([math]::Round($d.Size / 1GB, 2)) GB"
            
            $script:CancelHash = $false
            $script:IsHashing = $true

            $formEv.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            $btnHash.Text = Get-UiText -Key CancelHash
            $btnDoc.Enabled = $false
            $btnOffline.Enabled = $false
            
            $pbHash.Visible = $true
            $pbHash.Value = 0
            $lblHashStatus.Text = Get-UiText -Key HashReading -Values @($num)
            [System.Windows.Forms.Application]::DoEvents()
            
            $hash = Get-PhysicalDriveHash -DiskNumber $num -ProgressBar $pbHash
            
            $script:IsHashing = $false
            $btnHash.Text = Get-UiText -Key CalculateHash
            $btnHash.Enabled = $true
            $btnDoc.Enabled = $true
            $btnOffline.Enabled = $true
            $formEv.Cursor = [System.Windows.Forms.Cursors]::Default
            $pbHash.Visible = $false
            $lblHashStatus.Text = ""
            
            if ($script:CancelHash) {
                [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key HashCanceled), (Get-UiText -Key CanceledTitle), "OK", "Information") | Out-Null
            } elseif ($hash) {
                Write-EvidenceLog -DiskNumber $num -FriendlyName $d.FriendlyName -SerialNumber $d.SerialNumber -Size $sizeStr -Hash $hash
                [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key HashCompleted -Values @($hash)), (Get-UiText -Key CompletedTitle), "OK", "Information") | Out-Null
            } else {
                [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key HashFailure), (Get-UiText -Key ErrorTitle), "OK", "Error") | Out-Null
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key SelectDisk), (Get-UiText -Key WarningTitle), "OK", "Warning") | Out-Null
        }
    })

    $formEv.ShowDialog() | Out-Null
}

function Show-Status {
    $summary = Get-HostProtectionSummary
    Write-Host "`n--- ESTADO ACTUAL ---" -ForegroundColor Cyan
    if ($summary.WriteProtect -eq 1) {
        Write-Host "PROTECCION LOGICA ACTIVADA (Solo lectura)" -ForegroundColor Green
    } elseif ($summary.WriteProtect -eq 0) {
        Write-Host "ESCRITURA PERMITIDA" -ForegroundColor Red
    } else {
        Write-Host "ESTADO DESCONOCIDO (Clave no encontrada o valor invalido)" -ForegroundColor Yellow
    }
    if ($summary.Automount -eq 1) {
        Write-Host "AUTOMOUNT DESHABILITADO" -ForegroundColor Green
    } elseif ($summary.Automount -eq 0) {
        Write-Host "AUTOMOUNT HABILITADO" -ForegroundColor Yellow
    } else {
        Write-Host "AUTOMOUNT EN ESTADO DESCONOCIDO" -ForegroundColor Yellow
    }
    Write-Host "---------------------`n" -ForegroundColor Cyan
}

function Show-GUI {

    $form = New-Object System.Windows.Forms.Form
    $form.Text = Get-UiText -Key MainWindowTitle
    $form.Size = New-Object System.Drawing.Size(500,680)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = Get-UiText -Key MainHeading
    $lblTitle.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $lblTitle.Location = New-Object System.Drawing.Point(20, 20)
    $lblTitle.Size = New-Object System.Drawing.Size(450, 30)
    $lblTitle.TextAlign = "MiddleCenter"
    $form.Controls.Add($lblTitle)

    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
    $lblStatus.Location = New-Object System.Drawing.Point(20, 60)
    $lblStatus.Size = New-Object System.Drawing.Size(450, 40)
    $lblStatus.TextAlign = "MiddleCenter"
    $lblStatus.BorderStyle = "FixedSingle"
    $form.Controls.Add($lblStatus)

    function Update-StatusUI {
        $summary = Get-HostProtectionSummary
        if ($summary.WriteProtect -eq 1 -and $summary.Automount -eq 1) {
            $lblStatus.Text = Get-UiText -Key StatusReady
            $lblStatus.ForeColor = [System.Drawing.Color]::White
            $lblStatus.BackColor = [System.Drawing.Color]::Green
        } elseif ($summary.WriteProtect -eq 1) {
            $lblStatus.Text = Get-UiText -Key StatusProtected
            $lblStatus.ForeColor = [System.Drawing.Color]::White
            $lblStatus.BackColor = [System.Drawing.Color]::DarkGoldenrod
        } elseif ($summary.WriteProtect -eq 0 -and $summary.Automount -eq 0) {
            $lblStatus.Text = Get-UiText -Key StatusWritable
            $lblStatus.ForeColor = [System.Drawing.Color]::White
            $lblStatus.BackColor = [System.Drawing.Color]::Red
        } else {
            $lblStatus.Text = Get-UiText -Key StatusPartial
            $lblStatus.ForeColor = [System.Drawing.Color]::Black
            $lblStatus.BackColor = [System.Drawing.Color]::Orange
        }
    }

    function Set-UIBusy {
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $lblStatus.Text = Get-UiText -Key Processing
        $lblStatus.BackColor = [System.Drawing.Color]::LightGray
        $lblStatus.ForeColor = [System.Drawing.Color]::Black
        $form.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] } | ForEach-Object { $_.Enabled = $false }
        [System.Windows.Forms.Application]::DoEvents()
    }

    function Set-UIReady {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $form.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] } | ForEach-Object { $_.Enabled = $true }
        Update-StatusUI
        [System.Windows.Forms.Application]::DoEvents()
    }

    $btnLock = New-Object System.Windows.Forms.Button
    $btnLock.Text = Get-UiText -Key LockButton
    $btnLock.Location = New-Object System.Drawing.Point(50, 120)
    $btnLock.Size = New-Object System.Drawing.Size(380, 35)
    $btnLock.Add_Click({
        Set-UIBusy
        $success = Set-WriteProtectStatus -Value 1
        Set-UIReady
        if ($success) {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key LockSuccess), (Get-UiText -Key InformationTitle), "OK", "Information") | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key LockFailure), (Get-UiText -Key ErrorTitle), "OK", "Error") | Out-Null
        }
    })
    $form.Controls.Add($btnLock)

    $btnUnlock = New-Object System.Windows.Forms.Button
    $btnUnlock.Text = Get-UiText -Key UnlockButton
    $btnUnlock.Location = New-Object System.Drawing.Point(50, 165)
    $btnUnlock.Size = New-Object System.Drawing.Size(380, 35)
    $btnUnlock.Add_Click({
        Set-UIBusy
        $success = Set-WriteProtectStatus -Value 0
        Set-UIReady
        if ($success) {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key UnlockSuccess), (Get-UiText -Key InformationTitle), "OK", "Information") | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key UnlockFailure), (Get-UiText -Key ErrorTitle), "OK", "Error") | Out-Null
        }
    })
    $form.Controls.Add($btnUnlock)

    $btnPrepare = New-Object System.Windows.Forms.Button
    $btnPrepare.Text = Get-UiText -Key PrepareButton
    $btnPrepare.Location = New-Object System.Drawing.Point(50, 210)
    $btnPrepare.Size = New-Object System.Drawing.Size(380, 35)
    $btnPrepare.Add_Click({
        Set-UIBusy
        $blockSuccess = Set-WriteProtectStatus -Value 1
        $automountSuccess = Disable-Automount
        $selfCheckResult = $null
        if ($blockSuccess -and $automountSuccess) {
            $selfCheckResult = Get-HostSelfCheckResult
        }
        Set-UIReady
        if ($blockSuccess -and $automountSuccess) {
            [void](Show-SelfCheckReport -Result $selfCheckResult -AsGui)
        } else {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key PrepareFailure), (Get-UiText -Key ErrorTitle), "OK", "Error") | Out-Null
        }
    })
    $form.Controls.Add($btnPrepare)

    $btnRestore = New-Object System.Windows.Forms.Button
    $btnRestore.Text = Get-UiText -Key RestoreButton
    $btnRestore.Location = New-Object System.Drawing.Point(50, 255)
    $btnRestore.Size = New-Object System.Drawing.Size(380, 35)
    $btnRestore.Add_Click({
        Set-UIBusy
        $blockSuccess = Set-WriteProtectStatus -Value 0
        $automountSuccess = Enable-Automount
        Set-UIReady
        if ($blockSuccess -and $automountSuccess) {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key RestoreSuccess), (Get-UiText -Key InformationTitle), "OK", "Information") | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key RestoreFailure), (Get-UiText -Key ErrorTitle), "OK", "Error") | Out-Null
        }
    })
    $form.Controls.Add($btnRestore)

    $btnSelfCheck = New-Object System.Windows.Forms.Button
    $btnSelfCheck.Text = Get-UiText -Key SelfCheckButton
    $btnSelfCheck.Location = New-Object System.Drawing.Point(50, 300)
    $btnSelfCheck.Size = New-Object System.Drawing.Size(380, 35)
    $btnSelfCheck.Add_Click({
        Set-UIBusy
        $selfCheckResult = Get-HostSelfCheckResult
        Set-UIReady
        [void](Show-SelfCheckReport -Result $selfCheckResult -AsGui)
    })
    $form.Controls.Add($btnSelfCheck)

    $btnDisks = New-Object System.Windows.Forms.Button
    $btnDisks.Text = Get-UiText -Key DisksButton
    $btnDisks.Location = New-Object System.Drawing.Point(50, 345)
    $btnDisks.Size = New-Object System.Drawing.Size(380, 35)
    $btnDisks.Add_Click({
        Set-UIBusy
        $disks = Get-DiskSummary
        Set-UIReady
        if ($disks) {
            $diskStr = $disks | Out-String
            [System.Windows.Forms.MessageBox]::Show($diskStr, (Get-UiText -Key DisksTitle), "OK", "Information") | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key NoDisks), (Get-UiText -Key InformationTitle), "OK", "Warning") | Out-Null
        }
    })
    $form.Controls.Add($btnDisks)

    $btnEvid = New-Object System.Windows.Forms.Button
    $btnEvid.Text = Get-UiText -Key EvidenceButton
    $btnEvid.Location = New-Object System.Drawing.Point(50, 390)
    $btnEvid.Size = New-Object System.Drawing.Size(380, 35)
    $btnEvid.Add_Click({
        Show-EvidenceManager
    })
    $form.Controls.Add($btnEvid)

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = Get-UiText -Key ExitButton
    $btnExit.Location = New-Object System.Drawing.Point(50, 435)
    $btnExit.Size = New-Object System.Drawing.Size(380, 35)
    $btnExit.Add_Click({
        $form.Close()
    })
    $form.Controls.Add($btnExit)

    $btnAbout = New-Object System.Windows.Forms.Button
    $btnAbout.Text = Get-UiText -Key AboutButton
    $btnAbout.Location = New-Object System.Drawing.Point(50, 480)
    $btnAbout.Size = New-Object System.Drawing.Size(380, 35)
    $btnAbout.Add_Click({
        [System.Windows.Forms.MessageBox]::Show((Get-UiText -Key AboutText), (Get-UiText -Key AboutTitle), "OK", "Information") | Out-Null
    })
    $form.Controls.Add($btnAbout)

    $lblLanguage = New-Object System.Windows.Forms.Label
    $lblLanguage.Text = Get-UiText -Key LanguageLabel
    $lblLanguage.Location = New-Object System.Drawing.Point(120, 532)
    $lblLanguage.Size = New-Object System.Drawing.Size(90, 25)
    $lblLanguage.TextAlign = "MiddleRight"
    $form.Controls.Add($lblLanguage)

    $cmbLanguage = New-Object System.Windows.Forms.ComboBox
    $cmbLanguage.DropDownStyle = "DropDownList"
    $cmbLanguage.Location = New-Object System.Drawing.Point(220, 532)
    $cmbLanguage.Size = New-Object System.Drawing.Size(140, 25)
    [void]$cmbLanguage.Items.Add("Español")
    [void]$cmbLanguage.Items.Add("English")
    $cmbLanguage.SelectedIndex = if ($script:Language -eq "es") { 0 } else { 1 }
    $form.Controls.Add($cmbLanguage)

    $lblFooter = New-Object System.Windows.Forms.Label
    $lblFooter.Text = "(c) PowerForensics Ecosystem"
    $lblFooter.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Italic)
    $lblFooter.Location = New-Object System.Drawing.Point(20, 565)
    $lblFooter.Size = New-Object System.Drawing.Size(450, 20)
    $lblFooter.TextAlign = "MiddleCenter"
    $lblFooter.ForeColor = [System.Drawing.Color]::Gray
    $form.Controls.Add($lblFooter)

    $lblLog = New-Object System.Windows.Forms.Label
    $lblLog.Text = Get-UiText -Key LogLabel -Values @($global:LogFile)
    $lblLog.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Regular)
    $lblLog.Location = New-Object System.Drawing.Point(20, 585)
    $lblLog.Size = New-Object System.Drawing.Size(450, 30)
    $lblLog.TextAlign = "MiddleCenter"
    $lblLog.ForeColor = [System.Drawing.Color]::DarkGray
    $form.Controls.Add($lblLog)

    $lblAuthor = New-Object System.Windows.Forms.Label
    $lblAuthor.Text = "By Jesús D. Angosto"
    $lblAuthor.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
    $lblAuthor.Location = New-Object System.Drawing.Point(20, 615)
    $lblAuthor.Size = New-Object System.Drawing.Size(450, 18)
    $lblAuthor.TextAlign = "MiddleCenter"
    $lblAuthor.ForeColor = [System.Drawing.Color]::SteelBlue
    $form.Controls.Add($lblAuthor)

    function Apply-MainLanguage {
        $form.Text = Get-UiText -Key MainWindowTitle
        $lblTitle.Text = Get-UiText -Key MainHeading
        $btnLock.Text = Get-UiText -Key LockButton
        $btnUnlock.Text = Get-UiText -Key UnlockButton
        $btnPrepare.Text = Get-UiText -Key PrepareButton
        $btnRestore.Text = Get-UiText -Key RestoreButton
        $btnSelfCheck.Text = Get-UiText -Key SelfCheckButton
        $btnDisks.Text = Get-UiText -Key DisksButton
        $btnEvid.Text = Get-UiText -Key EvidenceButton
        $btnExit.Text = Get-UiText -Key ExitButton
        $btnAbout.Text = Get-UiText -Key AboutButton
        $lblLanguage.Text = Get-UiText -Key LanguageLabel
        $lblLog.Text = Get-UiText -Key LogLabel -Values @($global:LogFile)
        Update-StatusUI
    }

    $cmbLanguage.Add_SelectedIndexChanged({
        $script:Language = if ($cmbLanguage.SelectedIndex -eq 0) { "es" } else { "en" }
        Apply-MainLanguage
    })

    # Inicializar UI
    Apply-MainLanguage
    $form.ShowDialog() | Out-Null
}

# --- Logica principal ---

# Verificar elevacion antes de continuar
Restart-AsAdmin

# Procesar parametros CLI
if ($Lock) {
    Enable-LogicalWriteBlock
    Show-Status
} elseif ($Unlock) {
    Disable-LogicalWriteBlock
    Show-Status
} elseif ($Status) {
    Show-Status
} elseif ($PrepareForensicHost) {
    Prepare-ForensicHost
} elseif ($RestoreHost) {
    Restore-Host
} elseif ($SelfCheck) {
    [void](Show-SelfCheckReport -Result (Get-HostSelfCheckResult))
} elseif ($GUI) {
    Show-GUI
} else {
    # Por defecto, abrir GUI
    Show-GUI
}


