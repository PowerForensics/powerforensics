<#
.SYNOPSIS
Forge - PowerForensics Evidence Processor
"Forge convierte evidencias crudas en investigaciones estructuradas."
"Forge turns raw evidence into structured investigation."

.DESCRIPTION
Procesa logs crudos (actualmente CloudTrail) y los transforma en formatos
consumibles por Chronos (Timeline) y Nexus (Graph), generando además un
resumen ejecutivo automático.

Roadmap:
- AWS CloudTrail (Implementado)
- Azure Monitor / Activity Logs (Planned)
- Office 365 Unified Audit Log (Planned)
- Google Cloud Audit Logs (Planned)

.PARAMETER InputPath
Ruta al archivo JSON de logs (CloudTrail).

.PARAMETER OutChronos
Ruta de salida para el JSON de Chronos.

.PARAMETER OutNexus
Ruta de salida para el JSON de Nexus.
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$InputPath,

  [string]$OutChronos = "chronos_from_cloudtrail.json",
  [string]$OutNexus   = "nexus_from_cloudtrail.json",
  [string]$OutSummary = "executive_summary_from_cloudtrail.txt",

  [string]$CaseId = "DFIR-AWS-CASE-001",
  [string]$Author = "System",
  [string]$LogType = "CloudTrail"
)

Write-Host "PowerForensics · Forge (Community - CloudTrail)" -ForegroundColor Cyan
Write-Host "Forge convierte evidencias crudas en investigaciones estructuradas." -ForegroundColor Cyan
Write-Host "" 

function To-Slug([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return "unknown" }
  $t = $s.ToLowerInvariant()
  $t = ($t -replace '[^a-z0-9]+','-').Trim('-')
  if ($t.Length -gt 64) { $t = $t.Substring(0,64) }
  return $t
}

function New-Node([hashtable]$NodesById, [string]$Id, [string]$Type, [string]$Label) {
  if (-not $NodesById.ContainsKey($Id)) {
    $NodesById[$Id] = [ordered]@{ id=$Id; type=$Type; label=$Label }
  }
}

function New-Edge([System.Collections.Generic.List[object]]$Edges, [hashtable]$EdgesByKey, [object]$edgeObj) {
  # Dedup por (type|src|dst|timestamp|note|method|protocol|eventName)
  $keyParts = @(
    $edgeObj.type, $edgeObj.src, $edgeObj.dst,
    $(if($edgeObj.timestamp){$edgeObj.timestamp}else{""}),
    $(if($edgeObj.note){$edgeObj.note}else{""}), $(if($edgeObj.method){$edgeObj.method}else{""}),
    $(if($edgeObj.protocol){$edgeObj.protocol}else{""}), $(if($edgeObj.eventName){$edgeObj.eventName}else{""})
  )
  $key = ($keyParts -join "|")
  if (-not $EdgesByKey.ContainsKey($key)) {
    $EdgesByKey[$key] = $true
    
    # Convert input object to standard Hashtable to avoid [ordered] issues
    $finalEdge = @{}
    if ($edgeObj -is [System.Collections.IDictionary]) {
        foreach($k in $edgeObj.Keys) { $finalEdge[$k] = $edgeObj[$k] }
    } else {
        # Fallback if it's a PSObject
        foreach($p in $edgeObj.PSObject.Properties) { $finalEdge[$p.Name] = $p.Value }
    }
    
    $Edges.Add($finalEdge) | Out-Null
  }
}

function Parse-CloudTrailEvents($raw) {
  if ($null -eq $raw) { return @() }
  if ($raw.PSObject.Properties.Name -contains "Records") { return @($raw.Records) }
  if ($raw -is [System.Collections.IEnumerable]) { return @($raw) }
  return @($raw)
}

function Guess-Priority($eventName, $eventSource, $isFailedLogin, $isNoMfa, $isPrivEsc, $isAccessKey, $isDataAccess) {
  if ($isPrivEsc -or $isAccessKey) { return "critical" }
  if ($isDataAccess) { return "critical" }
  if ($isFailedLogin -or $isNoMfa) { return "high" }
  if ($eventName -match '^List|^Describe|^GetCallerIdentity') { return "medium" }
  return "low"
}

function Guess-Type($eventName, $isLogin, $isDataAccess, $isPrivEsc, $isAccessKey) {
  if ($isLogin -or $isPrivEsc -or $isAccessKey -or $isDataAccess) { return "alert" }
  if ($eventName -match '^List|^Describe') { return "analysis" }
  return "analysis"
}

function Guess-Mitre($eventName, $eventSource, $isLogin, $isFailedLogin, $isNoMfa, $isPrivEsc, $isAccessKey, $isDataAccess) {
  if ($isLogin -and $isFailedLogin) {
    return @{ tactics=@("Credential Access"); techniques=@("T1110") } # Brute Force (genérico)
  }
  if ($isLogin -and $isNoMfa) {
    return @{ tactics=@("Initial Access"); techniques=@("T1078") } # Valid Accounts (genérico)
  }
  if ($eventName -match '^ListUsers') {
    return @{ tactics=@("Discovery"); techniques=@("T1087.004") } # Cloud Account Discovery (aprox)
  }
  if ($eventName -match '^ListBuckets') {
    return @{ tactics=@("Discovery"); techniques=@("T1619") } # Cloud Storage Object Discovery (aprox)
  }
  if ($eventName -match '^DescribeInstances') {
    return @{ tactics=@("Discovery"); techniques=@("T1580") } # Cloud Infrastructure Discovery
  }
  if ($isPrivEsc) {
    return @{ tactics=@("Privilege Escalation"); techniques=@("T1098") } # Account Manipulation (aprox)
  }
  if ($isAccessKey) {
    return @{ tactics=@("Credential Access"); techniques=@("T1552") } # Unsecured Credentials (aprox)
  }
  if ($isDataAccess) {
    return @{ tactics=@("Collection","Exfiltration"); techniques=@("T1530") } # Data from Cloud Storage
  }
  return @{ tactics=@(); techniques=@() }
}

# --------- Load ----------
if (-not (Test-Path -LiteralPath $InputPath)) {
  throw "Input file not found: $InputPath"
}
$rawText = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8
$rawJson = $rawText | ConvertFrom-Json -ErrorAction Stop
$events  = Parse-CloudTrailEvents $rawJson

# --------- Build Chronos + Nexus ----------
$nodesById = @{}
$edges = New-Object System.Collections.Generic.List[object]
$edgesByKey = @{}

$chronos = New-Object System.Collections.Generic.List[object]

# Track for summary
$summary = [ordered]@{
  timeStart = $null
  timeEnd   = $null
  suspiciousUser = $null
  suspiciousIPs  = New-Object System.Collections.Generic.HashSet[string]
  failedLogins    = 0
  noMfaLogins     = 0
  discoveryEvents = 0
  privEscEvents   = 0
  accessKeyEvents = 0
  dataAccessCount = 0
  bucketsAccessed = New-Object System.Collections.Generic.HashSet[string]
  objectsAccessed = 0
  keyEvents = New-Object System.Collections.Generic.List[string]
}

# helper: parse time
function Parse-Time([string]$t) {
  if ([string]::IsNullOrWhiteSpace($t)) { return $null }
  try { return [DateTimeOffset]::Parse($t) } catch { return $null }
}

# Add a generic "cloud" node to anchor relationships
New-Node $nodesById "cloud-aws" "cloud" "AWS"

# Sort events by eventTime
$eventsSorted = $events | Sort-Object { Parse-Time $_.eventTime }

$idx = 0
foreach ($e in $eventsSorted) {
  $idx++

  $eventTime = [string]$e.eventTime
  $dt = Parse-Time $eventTime
  if ($dt -ne $null) {
    if ($summary.timeStart -eq $null) { $summary.timeStart = $dt }
    $summary.timeEnd = $dt
  }

  $eventName   = [string]$e.eventName
  $eventSource = [string]$e.eventSource
  $srcIP       = [string]$e.sourceIPAddress

  $userName = $null
  if ($e.userIdentity -and ($e.userIdentity.PSObject.Properties.Name -contains "userName")) {
    $userName = [string]$e.userIdentity.userName
  }
  if ([string]::IsNullOrWhiteSpace($userName)) { $userName = "unknown" }

  $isLogin = ($eventName -eq "ConsoleLogin" -and $eventSource -eq "signin.amazonaws.com")
  $isFailedLogin = ($isLogin -and ($e.PSObject.Properties.Name -contains "errorMessage") -and -not [string]::IsNullOrWhiteSpace([string]$e.errorMessage))
  $mfaUsed = $null
  if ($e.additionalEventData -and ($e.additionalEventData.PSObject.Properties.Name -contains "MFAUsed")) {
    $mfaUsed = [string]$e.additionalEventData.MFAUsed
  }
  $isNoMfa = ($isLogin -and $mfaUsed -eq "No")

  $isDiscovery = ($eventName -match '^List|^Describe|^GetCallerIdentity')
  $isPrivEsc   = ($eventName -match 'AttachUserPolicy|PutUserPolicy|AttachGroupPolicy|PutRolePolicy|UpdateAssumeRolePolicy|CreatePolicyVersion')
  $isAccessKey = ($eventName -match 'CreateAccessKey|UpdateAccessKey|CreateLoginProfile')
  $isDataAccess= ($eventSource -eq "s3.amazonaws.com" -and $eventName -match 'GetObject|ListObjects|GetObjectVersion')

  if ($summary.suspiciousUser -eq $null -and ($isNoMfa -or $isPrivEsc -or $isAccessKey -or $isDataAccess)) {
    $summary.suspiciousUser = $userName
  }

  if (-not [string]::IsNullOrWhiteSpace($srcIP)) {
    $summary.suspiciousIPs.Add($srcIP) | Out-Null
  }
  if ($isFailedLogin) { $summary.failedLogins++ }
  if ($isNoMfa) { $summary.noMfaLogins++ }
  if ($isDiscovery) { $summary.discoveryEvents++ }
  if ($isPrivEsc) { $summary.privEscEvents++ }
  if ($isAccessKey) { $summary.accessKeyEvents++ }

  # ---------- Nexus nodes ----------
  $userId = "user-" + (To-Slug $userName)
  New-Node $nodesById $userId "user" $userName

  if (-not [string]::IsNullOrWhiteSpace($srcIP)) {
    $ipId = "ip-" + (To-Slug $srcIP)
    New-Node $nodesById $ipId "ip" $srcIP
    # edge: user observed from IP
    New-Edge $edges $edgesByKey ([ordered]@{
      id = "e-$idx-uip"
      type = "observed_from"
      src = $userId
      dst = $ipId
      timestamp = $eventTime
      eventName = $eventName
      note = "$eventSource"
    })
  }

  # service node
  if (-not [string]::IsNullOrWhiteSpace($eventSource)) {
    $svcId = "svc-" + (To-Slug $eventSource)
    New-Node $nodesById $svcId "cloud_service" $eventSource
    New-Edge $edges $edgesByKey ([ordered]@{
      id="e-$idx-usvc"
      type="api_call"
      src=$userId
      dst=$svcId
      timestamp=$eventTime
      eventName=$eventName
    })
  }

  # Specific artifacts
  $bucketName = $null
  $objKey = $null
  if ($e.requestParameters) {
    if ($e.requestParameters.PSObject.Properties.Name -contains "bucketName") { $bucketName = [string]$e.requestParameters.bucketName }
    if ($e.requestParameters.PSObject.Properties.Name -contains "key") { $objKey = [string]$e.requestParameters.key }
    if ($e.requestParameters.PSObject.Properties.Name -contains "policyArn") {
      $policyArn = [string]$e.requestParameters.policyArn
      if (-not [string]::IsNullOrWhiteSpace($policyArn)) {
        $polId = "policy-" + (To-Slug $policyArn)
        New-Node $nodesById $polId "policy" $policyArn
        if ($isPrivEsc) {
          New-Edge $edges $edgesByKey ([ordered]@{
            id="e-$idx-pol"
            type="privilege_escalation"
            src=$userId
            dst=$polId
            timestamp=$eventTime
            eventName=$eventName
            note="Policy attached"
          })
        } else {
          New-Edge $edges $edgesByKey ([ordered]@{
            id="e-$idx-pol2"
            type="policy_change"
            src=$userId
            dst=$polId
            timestamp=$eventTime
            eventName=$eventName
          })
        }
      }
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($bucketName)) {
    $bId = "bucket-" + (To-Slug $bucketName)
    New-Node $nodesById $bId "cloud_resource" $bucketName

    if ($isDataAccess) {
      $summary.dataAccessCount++
      $summary.bucketsAccessed.Add($bucketName) | Out-Null
      $edgeType = "data_access"
      New-Edge $edges $edgesByKey ([ordered]@{
        id="e-$idx-s3"
        type=$edgeType
        src=$userId
        dst=$bId
        timestamp=$eventTime
        eventName=$eventName
        protocol="AWS-API"
      })
    } elseif ($eventName -match '^ListBuckets') {
      New-Edge $edges $edgesByKey ([ordered]@{
        id="e-$idx-s3list"
        type="discovery"
        src=$userId
        dst=$bId
        timestamp=$eventTime
        eventName=$eventName
        note="S3 bucket discovery"
      })
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($bucketName) -and -not [string]::IsNullOrWhiteSpace($objKey)) {
    $oId = "s3obj-" + (To-Slug ($bucketName + "/" + $objKey))
    New-Node $nodesById $oId "file" ($bucketName + "/" + $objKey)

    if ($isDataAccess) {
      $summary.objectsAccessed++
      New-Edge $edges $edgesByKey ([ordered]@{
        id="e-$idx-obj"
        type="object_access"
        src=("bucket-" + (To-Slug $bucketName))
        dst=$oId
        timestamp=$eventTime
        eventName=$eventName
      })
    }
  }

  if ($isAccessKey) {
    $akId = "accesskey-" + (To-Slug ($userName + "-" + $eventTime))
    New-Node $nodesById $akId "credential" ("AccessKey for " + $userName)
    New-Edge $edges $edgesByKey ([ordered]@{
      id="e-$idx-ak"
      type="credential_creation"
      src=$userId
      dst=$akId
      timestamp=$eventTime
      eventName=$eventName
      note="CreateAccessKey"
    })
  }

  # ---------- Chronos event ----------
  $prio = Guess-Priority $eventName $eventSource $isFailedLogin $isNoMfa $isPrivEsc $isAccessKey $isDataAccess
  $ctype = Guess-Type $eventName $isLogin $isDataAccess $isPrivEsc $isAccessKey
  $mitre = Guess-Mitre $eventName $eventSource $isLogin $isFailedLogin $isNoMfa $isPrivEsc $isAccessKey $isDataAccess

  $titleParts = @()
  if ($isLogin) {
    if ($isFailedLogin) { $titleParts += "ConsoleLogin FAILED" } else { $titleParts += "ConsoleLogin" }
    if ($mfaUsed) { $titleParts += "MFA:$mfaUsed" }
  } else {
    $titleParts += $eventName
  }
  $titleParts += "($userName)"

  $desc = "CloudTrail: $eventSource / $eventName. SourceIP: $srcIP."
  if ($isFailedLogin -and $e.errorMessage) { $desc += " Error: $($e.errorMessage)." }
  if ($bucketName) { $desc += " Bucket: $bucketName." }
  if ($objKey) { $desc += " Key: $objKey." }

  $chronosId = "aws-" + (To-Slug $eventTime) + "-" + $idx.ToString("000")
  $chronosEvent = [ordered]@{
    id = $chronosId
    title = ($titleParts -join " ")
    description = $desc
    timestamp = $eventTime
    type = $ctype
    priority = $prio
    asset = "AWS"
    source = "CloudTrail"
    author = $Author
    caseId = $CaseId
    metadata = [ordered]@{
      tags = @(
        "AWS","CloudTrail",
        $(if($isLogin){"Auth"}else{""}),
        $(if($isDiscovery){"Discovery"}else{""}),
        $(if($isPrivEsc){"PrivEsc"}else{""}),
        $(if($isAccessKey){"AccessKey"}else{""}),
        $(if($isDataAccess){"DataAccess"}else{""})
      ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
      ioc = $(if($isDataAccess -and $bucketName){ "$bucketName/$objKey" } elseif($srcIP){ $srcIP } else { $eventName })
      mitre = $mitre
      # Opcional: puente a Nexus (IDs)
      nexus = [ordered]@{
        nodes = @($userId) + $(if($srcIP){ @("ip-" + (To-Slug $srcIP)) } else { @() })
      }
    }
  }

  $chronos.Add($chronosEvent) | Out-Null

  # Track key events for summary narrative
  if ($prio -in @("high","critical")) {
    $summary.keyEvents.Add(("{0} {1} {2} {3}" -f $eventTime, $eventName, $eventSource, $userName)) | Out-Null
  }
}

# Build final Nexus object
Write-Host "Nodes count: $($nodesById.Values.Count)"
Write-Host "Edges count: $($edges.Count)"
$nexusOut = @{}
$nexusOut["nodes"] = @($nodesById.Values)
try {
    $nexusOut["edges"] = $edges.ToArray()
} catch {
    Write-Host "Error adding edges: $_"
}

# --------- Executive summary (auto narrative) ----------
$timeStartStr = if($summary.timeStart){ $summary.timeStart.ToString("u") } else { "unknown" }
$timeEndStr   = if($summary.timeEnd){ $summary.timeEnd.ToString("u") } else { "unknown" }
$userSus = if($summary.suspiciousUser){ $summary.suspiciousUser } else { "unknown" }
$ipList = ($summary.suspiciousIPs | Sort-Object) -join ", "
$buckets = ($summary.bucketsAccessed | Sort-Object) -join ", "

$summaryText = @()
$summaryText += "PowerForensics · Forge (Community - CloudTrail)"
$summaryText += "Forge convierte evidencias crudas en investigaciones estructuradas."
$summaryText += ""
$summaryText += "Executive Summary (CloudTrail -> DFIR narrative)"
$summaryText += "CaseId: $CaseId"
$summaryText += "Time window (UTC): $timeStartStr  to  $timeEndStr"
$summaryText += ""
$summaryText += "High-level narrative:"
$summaryText += "- Potential compromise activity was observed in AWS CloudTrail involving user '$userSus'."
if ($summary.failedLogins -gt 0) { $summaryText += "- Authentication anomalies: $($summary.failedLogins) failed login attempt(s) detected." }
if ($summary.noMfaLogins -gt 0) { $summaryText += "- Risk factor: $($summary.noMfaLogins) ConsoleLogin event(s) without MFA were observed." }
if ($summary.discoveryEvents -gt 0) { $summaryText += "- Post-auth discovery: $($summary.discoveryEvents) enumeration event(s) (List*/Describe*) detected." }
if ($summary.privEscEvents -gt 0) { $summaryText += "- Privilege escalation indicators: $($summary.privEscEvents) IAM policy/permission modification event(s) detected." }
if ($summary.accessKeyEvents -gt 0) { $summaryText += "- Credential materialization: $($summary.accessKeyEvents) access key creation/management event(s) detected." }
if ($summary.dataAccessCount -gt 0) { $summaryText += "- Data access/exfiltration indicators: $($summary.dataAccessCount) S3 object access event(s) detected." }
if ($summary.objectsAccessed -gt 0) { $summaryText += "- Objects accessed: $($summary.objectsAccessed). Buckets involved: $buckets" }
if (-not [string]::IsNullOrWhiteSpace($ipList)) { $summaryText += "- Source IPs observed: $ipList" }
$summaryText += ""
$summaryText += "Notable events (high/critical):"
if ($summary.keyEvents.Count -gt 0) {
  $summaryText += ($summary.keyEvents | Select-Object -First 20 | ForEach-Object { "  - $_" })
} else {
  $summaryText += "  - (none)"
}
$summaryText += ""
$summaryText += "Outputs generated:"
$summaryText += "- $OutChronos"
$summaryText += "- $OutNexus"
$summaryText += ""

# --------- Write outputs ----------
($chronos | ConvertTo-Json -Depth 20) | Out-File -LiteralPath $OutChronos -Encoding UTF8
($nexusOut | ConvertTo-Json -Depth 20) | Out-File -LiteralPath $OutNexus -Encoding UTF8
($summaryText -join "`r`n") | Out-File -LiteralPath $OutSummary -Encoding UTF8

Write-Host "OK - Generated:"
Write-Host "  Chronos: $OutChronos"
Write-Host "  Nexus:   $OutNexus"
Write-Host "  Summary: $OutSummary"
