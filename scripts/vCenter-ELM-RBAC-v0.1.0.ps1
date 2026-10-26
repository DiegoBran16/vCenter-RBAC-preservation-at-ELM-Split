#requires -Version 7.0
<#
.SYNOPSIS
    vCenter 8 ELM RBAC - interactive PRE / CURRENT / recovery / POST.
.DESCRIPTION
    Candidate v0.1.0. Collects roles, Global ACL (MOB) and Inventory permissions
    (GetAllPermissions MOB cross-check + AuthorizationManager API). Produces
    versioned evidence and compares PRE with CURRENT or POST using saved CSVs.
    Restore requires read-only identity preflight, one explicit reviewed batch approval, excludes protected built-in principals, and never modifies DRIFT.
    Does NOT perform the ELM split. PowerShell syntax must be checked with Parser.ParseFile; test in HOL / non-production first.
.EXAMPLE
    pwsh -NoProfile -File .\vCenter-ELM-RBAC-v0.1.0.ps1
.EXAMPLE
    .\vCenter-ELM-RBAC-v0.1.0.ps1 -Action PRE -Server vc01.example.local -EvidenceId vc01
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu','Setup','PRE','CURRENT','Compare','Restore','POST')]
    [string]$Action = 'Menu',
    [string]$Server,
    [string]$EvidenceId,
    [string]$WorkDir = '',
    [string]$LocalSsoDomain = 'vsphere.local',
    [switch]$AllowUntrustedCertificate
)
# By default, evidence is stored beside this script (portable across clients).
if ([string]::IsNullOrWhiteSpace($WorkDir)) { $WorkDir = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($WorkDir)) { throw 'Unable to determine WorkDir; specify -WorkDir.' }
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$Script:BuildVersion = '0.1.0-sso-identity-candidate'
$Script:TranscriptStarted = $false
$Script:VIConnection = $null
$Script:SkipCertificateChecks = [bool]$AllowUntrustedCertificate
$Script:CertificateOverrideApplied = $false
$Script:PreviousCertificateAction = $null
$Script:SsoAdminConnection = $null

function Say([string]$Text, [string]$Color = 'Cyan') {
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Text) -ForegroundColor $Color
}
function Stop-If([bool]$Condition, [string]$Message) {
    if ($Condition) { throw $Message }
}
function Confirm-Exact([string]$Message, [string]$Expected) {
    Say $Message 'Yellow'
    return ((Read-Host "Type EXACTLY [$Expected] to continue") -ceq $Expected)
}
function Get-CleanText([string]$Markup) {
    return [System.Net.WebUtility]::HtmlDecode([regex]::Replace($Markup, '(?s)<[^>]+>', '')).Trim()
}
function Get-Field([string]$Html, [string]$Field) {
    $pattern = '(?is)<td\b[^>]*>\s*' + [regex]::Escape($Field) + '\s*</td>\s*<td\b[^>]*>.*?</td>\s*<td\b[^>]*>(.*?)</td>'
    $matches = [regex]::Matches($Html, $pattern)
    if ($matches.Count -ne 1) { throw "MOB field [$Field] is not unique ($($matches.Count))." }
    return (Get-CleanText $matches[0].Groups[1].Value)
}
function Get-PrincipalFields([string]$Entry) {
    $nested = [regex]::Match($Entry, '(?is)<td\b[^>]*>\s*principal\s*</td>.*?<table\b[^>]*>(.*?)</table>')
    Stop-If (-not $nested.Success) 'MOB principal table is missing.'
    $p = Get-Field $nested.Groups[1].Value 'name'
    $g = Get-Field $nested.Groups[1].Value 'group'
    Stop-If ([string]::IsNullOrWhiteSpace($p) -or $g -notin @('true','false')) 'MOB principal/group metadata is incomplete.'
    return [pscustomobject]@{ Name = $p; IsGroup = [bool]::Parse($g) }
}
function Get-RoleIdFromEntry([string]$Entry) {
    $roles = [regex]::Match($Entry, '(?is)<td\b[^>]*>\s*roles\s*</td>.*?<ul\b[^>]*>(.*?)</ul>')
    Stop-If (-not $roles.Success) 'MOB roles list not found.'
    $ids = [regex]::Matches($roles.Groups[1].Value, '(?is)<li\b[^>]*>\s*(-?\d+)\s*</li>')
    Stop-If ($ids.Count -ne 1) "MOB expected exactly one RoleId; received $($ids.Count)."
    return [string]$ids[0].Groups[1].Value
}
function Get-MobEntries([string]$Html, [string]$Label) {
    $pattern = '(?is)<li\b[^>]*>\s*<table\b[^>]*summary=["'']Table of properties for this Data Object["''][^>]*>(.*?)</table>\s*</li>'
    $entries = [regex]::Matches($Html, $pattern)
    if ($entries.Count -eq 0) {
        throw "${Label}: no parsable MOB entries. Do not assume permissions are empty; check the response format."
    }
    return $entries
}
function Enable-SessionCertificateBypass {
    if (-not $Script:CertificateOverrideApplied) {
        $currentSession = Get-PowerCLIConfiguration -Scope Session -ErrorAction Stop
        $Script:PreviousCertificateAction = [string]$currentSession.InvalidCertificateAction
        if ([string]::IsNullOrWhiteSpace($Script:PreviousCertificateAction)) {
            $Script:PreviousCertificateAction = 'Unset'
        }
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false -ErrorAction Stop | Out-Null
        $Script:CertificateOverrideApplied = $true
    }
    $Script:SkipCertificateChecks = $true
    Say 'WARNING: Untrusted certificates are accepted for this run only. Verify the server identity out of band.' 'Yellow'
}
function Disable-SessionCertificateBypass {
    if ($Script:CertificateOverrideApplied) {
        try {
            Set-PowerCLIConfiguration -InvalidCertificateAction $Script:PreviousCertificateAction -Scope Session -Confirm:$false -ErrorAction Stop | Out-Null
            Say "Restored PowerCLI Session certificate policy: $($Script:PreviousCertificateAction)" 'Green'
        } catch {
            Say "WARNING: Unable to restore PowerCLI Session certificate policy. Manually restore it: $($_.Exception.Message)" 'Red'
        }
    }
}
function Is-CertificateFailure([string]$Message) {
    return ($Message -match '(?i)(invalid server certificate|certificate (chain|validation|verify|trust)|untrusted|remote certificate|SSL/TLS.*(trust|authority)|trust relationship|certificate authority)')
}
function Ask-ForCertificateBypass([string]$Context, [string]$FailureMessage) {
    Say "Certificate validation failed while accessing ${Context}: $FailureMessage" 'Yellow'
    Say 'Recommended fix: use a valid vCenter certificate and install the trusted CA chain in Windows.' 'Yellow'
    if (-not (Confirm-Exact 'For a controlled lab ONLY, temporarily bypass certificate validation for this run?' 'IGNORE')) {
        throw 'Certificate is not trusted. No TLS bypass was authorized; operation stopped.'
    }
    Enable-SessionCertificateBypass
}
function Invoke-ELMMob([string]$HostName, [string]$Method, [pscredential]$Credential, [hashtable]$Body = @{}) {
    $url = "https://$HostName/invsvc/mob3/?moid=authorizationService&method=AuthorizationService.$Method"
    $getParams = @{ Uri=$url; Credential=$Credential; Method='GET'; SessionVariable='elmMobSession'; ErrorAction='Stop' }
    if ($Script:SkipCertificateChecks) { $getParams.SkipCertificateCheck = $true }
    try {
        $first = Invoke-WebRequest @getParams
    } catch {
        if ($Script:SkipCertificateChecks -or -not (Is-CertificateFailure $_.Exception.Message)) { throw }
        Ask-ForCertificateBypass -Context "MOB $Method on $HostName" -FailureMessage $_.Exception.Message
        $getParams.SkipCertificateCheck = $true
        $first = Invoke-WebRequest @getParams
    }
    Stop-If ($first.StatusCode -ne 200) "${Method}: GET HTTP $($first.StatusCode)."
    $nonce = [regex]::Match($first.Content, 'name="vmware-session-nonce"\s+type="hidden"\s+value="([^"]+)"')
    Stop-If (-not $nonce.Success) "${Method}: MOB session nonce not found."
    $postBody = @{ 'vmware-session-nonce'=$nonce.Groups[1].Value }
    foreach ($k in $Body.Keys) { $postBody[$k] = $Body[$k] }
    $postParams = @{ Uri=$url; WebSession=$elmMobSession; Method='POST'; Body=$postBody; ContentType='application/x-www-form-urlencoded'; ErrorAction='Stop' }
    if ($Script:SkipCertificateChecks) { $postParams.SkipCertificateCheck = $true }
    $response = Invoke-WebRequest @postParams
    Stop-If ($response.StatusCode -ne 200) "${Method}: POST HTTP $($response.StatusCode)."
    if ($Body.Count -gt 0 -and $response.Content -match '(?is)(<h[123]>\s*(fault|exception)|methodfault|invalidargument)') {
        throw "${Method}: potential MOB fault in response. Independent verification is required."
    }
    return [string]$response.Content
}
function Initialize-PowerCLI {
    Stop-If ($PSVersionTable.PSVersion.Major -lt 7) 'PowerShell 7 is required. Open pwsh (install using winget install --id Microsoft.PowerShell).'
    $mod = Get-Module -ListAvailable -Name VCF.PowerCLI | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $mod) {
        Say 'VCF.PowerCLI is not installed. Run Setup first.' 'Yellow'
        throw 'VCF.PowerCLI module is missing.'
    }
    Import-Module VCF.PowerCLI -ErrorAction Stop
    $required = @('Connect-VIServer','Disconnect-VIServer','Get-VIRole','Get-VIPrivilege','New-VIRole','Get-View','Get-VIAccount','Get-VIObjectByVIView','New-VIPermission')
    foreach ($cmd in $required) {
        Stop-If (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) "Required cmdlet not available: $cmd"
    }
    Say "PowerShell $($PSVersionTable.PSVersion) / PowerCLI $($mod.Version)" 'Green'
    if ($AllowUntrustedCertificate -and -not $Script:CertificateOverrideApplied) {
        Enable-SessionCertificateBypass
    }
}
function Install-Prerequisites {
    Say 'WINDOWS / POWERSHELL SETUP'
    Say "Detected PowerShell: $($PSVersionTable.PSVersion)"
    $mod = Get-Module -ListAvailable VCF.PowerCLI | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $mod) {
        Say 'Target version: VCF.PowerCLI 9.1.1.25718932.'
        Say '-AllowClobber handles overlapping cmdlets; -SkipPublisherCheck bypasses old/new publisher signature conflicts.' 'Yellow'
        if (-not (Confirm-Exact 'Confirm that you trust PowerShell Gallery and authorize installing with the publisher check bypassed.' 'INSTALL')) {
            Say 'Installation skipped.' 'Yellow'; return
        }
        Install-Module -Name VCF.PowerCLI -RequiredVersion '9.1.1.25718932' -Scope CurrentUser -Repository PSGallery -AllowClobber -SkipPublisherCheck -Force -ErrorAction Stop
    }
    Initialize-PowerCLI
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    Say "Working directory ready: $WorkDir" 'Green'
    Say 'William Lam GlobalPermissions.ps1 was a useful reference but is NOT loaded: its parser may repeat permission definitions.' 'Yellow'
    Say 'Reference: https://github.com/lamw/vmware-scripts/blob/master/powershell/GlobalPermissions.ps1'
    Say 'SETUP COMPLETED.' 'Green'
}
function Get-Context([switch]$Offline) {
    if (-not $Offline) {
        Initialize-PowerCLI
        if ([string]::IsNullOrWhiteSpace($Server)) { $script:Server = Read-Host 'vCenter FQDN (e.g., vc01.example.local)' }
        Stop-If ([string]::IsNullOrWhiteSpace($Server)) 'vCenter FQDN is required.'
    }
    if ([string]::IsNullOrWhiteSpace($EvidenceId)) { $script:EvidenceId = Read-Host 'Evidence ID (e.g., vc01)' }
    Stop-If ($EvidenceId -notmatch '^[a-zA-Z0-9_-]+$') 'EvidenceId permits only letters, numbers, underscores and hyphens.'
    $root = Join-Path $WorkDir $EvidenceId
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    return $root
}
function Connect-ELM {
    Say "Connecting to $Server"
    try {
        $Script:VIConnection = Connect-VIServer -Server $Server -ErrorAction Stop
    } catch {
        if ($Script:SkipCertificateChecks -or -not (Is-CertificateFailure $_.Exception.Message)) { throw }
        Ask-ForCertificateBypass -Context "vCenter $Server" -FailureMessage $_.Exception.Message
        Say "Retrying connection to $Server with the approved temporary certificate exception..." 'Yellow'
        $Script:VIConnection = Connect-VIServer -Server $Server -ErrorAction Stop
    }
    Say "Connected: $($Script:VIConnection.Name)" 'Green'
    Say 'Requesting MOB credentials (passwords are not stored in CSV or logs).'
    $mobCredential = Get-Credential -Message "MOB credentials for $Server"
    return [pscustomobject]@{ Server=$Script:VIConnection; MobCredential=$mobCredential }
}
function Get-GlobalRows([string]$HostName, [pscredential]$MobCredential, [hashtable]$RoleMap, [string]$InstanceUuid) {
    Say '1/4 Querying Global ACL through MOB...'
    $html = Invoke-ELMMob -HostName $HostName -Method 'GetGlobalAccessControlList' -Credential $MobCredential
    $entries = @(Get-MobEntries $html 'Global ACL')
    $results = @(
        foreach ($entry in $entries) {
            $data = $entry.Groups[1].Value
            $principal = Get-PrincipalFields $data
            $id = Get-RoleIdFromEntry $data
            $propText = Get-Field $data 'propagate'
            Stop-If ($propText -notin @('true','false')) "Invalid Propagate value for $($principal.Name)"
            Stop-If (-not $RoleMap.ContainsKey($id)) "Global RoleId $id not found in Get-VIRole."
            $prop = [bool]::Parse($propText)
            $p = [string]$principal.Name
            $r = [string]$RoleMap[$id]
            [pscustomobject]@{
                vCenter=$HostName; InstanceUuid=$InstanceUuid; Principal=$p; IsGroup=$principal.IsGroup
                RoleName=$r; RoleId=$id; Propagate=$prop; EntityName='Global'
                EntityId=''; EntityType='GlobalAcl'; PermissionType='Global'
                Definition='urn:acl:global:permissions'
                IdentityKey="global|$($p.ToLowerInvariant())|$($principal.IsGroup.ToString().ToLowerInvariant())"
                AssignmentKey="$($r.ToLowerInvariant())|$($prop.ToString().ToLowerInvariant())"
                CrossCheckStatus='COLLECTED'
            }
        }
    )
    Say "Global ACL: $($results.Count) entries" 'Green'
    return $results
}
function Get-MobDiscovery([string]$HostName, [pscredential]$MobCredential) {
    Say '2/4 Querying GetAllPermissions to classify Global and Inventory...'
    $html = Invoke-ELMMob -HostName $HostName -Method 'GetAllPermissions' -Credential $MobCredential
    $entries = @(Get-MobEntries $html 'GetAllPermissions')

    # vCenter 8 MOB may render many ACL <li><table> entries under one document.
    # The <td>document</td> is then rendered AFTER the entire permissions list,
    # not after every individual ACL entry. An entry-by-entry tail lookup fails
    # with 'ambiguous document (0)' or can assign the same Definition repeatedly.
    # Parse complete document-scoped groups instead. Fail closed for unfamiliar HTML.
    $documentPattern = '(?is)<td\b[^>]*>\s*document\s*</td>\s*<td\b[^>]*>.*?</td>\s*<td\b[^>]*>(.*?)</td>'
    $documents = [regex]::Matches($html, $documentPattern)
    Stop-If ($documents.Count -eq 0) 'GetAllPermissions: document fields were not found. Do not assume empty permissions.'
    Say "GetAllPermissions: $($entries.Count) ACL entries / $($documents.Count) document groups identified."

    $rows = [System.Collections.Generic.List[object]]::new()
    $nextEntry = 0
    $previousDocEnd = 0
    foreach ($doc in $documents) {
        $definition = Get-CleanText $doc.Groups[1].Value
        Stop-If ($definition -ne 'urn:acl:global:permissions' -and $definition -notlike 'urn:vmomi:*') "GetAllPermissions: unrecognized document Definition: $definition"
        $groupCount = 0
        while ($nextEntry -lt $entries.Count -and $entries[$nextEntry].Index -lt $doc.Index) {
            $entry = $entries[$nextEntry]
            Stop-If ($entry.Index -lt $previousDocEnd) "GetAllPermissions: overlapping document and ACL entry $nextEntry."
            $principal = Get-PrincipalFields $entry.Groups[1].Value
            $id = Get-RoleIdFromEntry $entry.Groups[1].Value
            $rows.Add([pscustomobject]@{
                Principal=$principal.Name; IsGroup=$principal.IsGroup
                RoleId=$id; Definition=$definition
            })
            $nextEntry++
            $groupCount++
        }
        Stop-If ($groupCount -eq 0) "GetAllPermissions: document group $definition contains no matching ACL entries. Check MOB HTML layout."
        $previousDocEnd = $doc.Index + $doc.Length
    }
    Stop-If ($nextEntry -ne $entries.Count) "GetAllPermissions: $($entries.Count - $nextEntry) ACL entries do not belong to a parsed document group."
    Stop-If ($rows.Count -ne $entries.Count) 'GetAllPermissions: not every ACL entry was assigned exactly once.'

    $dups = @($rows | Group-Object Principal,IsGroup,RoleId,Definition | Where-Object Count -gt 1)
    if ($dups.Count -gt 0) {
        $dups | Select-Object Count,Name | Format-Table -AutoSize
        throw 'GetAllPermissions: duplicate identities remain after document-scoped parsing. Stop; do not deduplicate.'
    }
    Say "GetAllPermissions: $($rows.Count) uniquely classified entries" 'Green'
    return $rows.ToArray()
}
function Get-LiveSnapshot([object]$Connection) {
    $vc = $Connection.Server
    $instance = Get-View -Server $vc -Id ServiceInstance -ErrorAction Stop
    $uuid = [string]$instance.Content.About.InstanceUuid
    Stop-If ([string]::IsNullOrWhiteSpace($uuid)) 'InstanceUuid is empty.'
    Say "vCenter UUID: $uuid"
    $roleObjs = @(Get-VIRole -Server $vc -ErrorAction Stop)
    Stop-If ($roleObjs.Count -eq 0) 'No roles were retrieved.'
    $roleMap = @{}
    $roleRows = @(
        foreach ($role in $roleObjs) {
            $id = [string]$role.ExtensionData.RoleId
            Stop-If ([string]::IsNullOrWhiteSpace($id) -or $roleMap.ContainsKey($id)) "Duplicate or empty RoleId: $id"
            $roleMap[$id] = [string]$role.Name
            [pscustomobject]@{
                vCenter=$vc.Name; RoleName=[string]$role.Name; RoleId=$id
                IsSystem=[bool]$role.IsSystem; Description=[string]$role.Description
                PrivilegeCount=@($role.PrivilegeList).Count
                Privileges=(@($role.PrivilegeList) | Sort-Object -Unique) -join ';'
            }
        }
    )
    Say "Roles read: $($roleRows.Count)" 'Green'
    $globalRows = @(Get-GlobalRows -HostName $vc.Name -MobCredential $Connection.MobCredential -RoleMap $roleMap -InstanceUuid $uuid)
    $mobRows = @(Get-MobDiscovery -HostName $vc.Name -MobCredential $Connection.MobCredential)
    $mobGlobal = @($mobRows | Where-Object Definition -eq 'urn:acl:global:permissions')
    $mobInventory = @($mobRows | Where-Object Definition -like 'urn:vmomi:*')
    Stop-If ($mobGlobal.Count -ne $globalRows.Count) "Global ACL ($($globalRows.Count)) != GetAllPermissions ($($mobGlobal.Count))."
    foreach ($g in $globalRows) {
        $matching = @($mobGlobal | Where-Object {
            $_.Principal -eq $g.Principal -and $_.IsGroup -eq $g.IsGroup -and $_.RoleId -eq $g.RoleId
        })
        Stop-If ($matching.Count -ne 1) "Global permission could not be validated against two sources: $($g.Principal)"
        $g.CrossCheckStatus = 'VERIFIED'
    }
    Say '3/4 Reading AuthorizationManager.RetrieveAllPermissions()...'
    $authMgr = Get-View -Server $vc -Id $instance.Content.AuthorizationManager -ErrorAction Stop
    $apiRows = @($authMgr.RetrieveAllPermissions())
    $rootValue = [string]$instance.Content.RootFolder.Value
    $inventoryRows = @(
        foreach ($m in $mobInventory) {
            $found = @($apiRows | Where-Object {
                $v = $_
                $definition = "urn:vmomi:$($v.Entity.Type):$($v.Entity.Value):$uuid"
                $v.Principal -eq $m.Principal -and [bool]$v.Group -eq $m.IsGroup -and
                [string]$v.RoleId -eq $m.RoleId -and $definition -eq $m.Definition
            })
            # RetrieveAllPermissions() can return repeated representations of the
            # exact same permission (Broadcom KB 369938 gives an example).
            # MOB has already identified one Inventory assignment for this
            # principal / group flag / role / object. Those attributes are
            # constrained by the query above. Propagate is the remaining
            # metadata field that MUST agree before we can use one API record.
            # No Global or Inventory permission is removed from the evidence:
            # the source-of-truth MOB Inventory entry is exported once, and
            # Global ACL entries are exported independently.
            if ($found.Count -gt 1) {
                $propagateVariants = @($found | Group-Object -Property Propagate)
                if ($propagateVariants.Count -eq 1) {
                    $matchingGlobalAcl = @($globalRows | Where-Object {
                        $_.Principal -eq $m.Principal -and
                        $_.IsGroup -eq $m.IsGroup -and
                        $_.RoleId -eq $m.RoleId -and
                        $_.Propagate -eq [bool]$found[0].Propagate
                    })
                    Say "INFO: AuthorizationManager returned $($found.Count) equivalent representations for Inventory $($m.Principal) / $($m.Definition); Propagate=$([bool]$found[0].Propagate). Using one metadata instance for this one MOB Inventory assignment." 'Yellow'
                    if ($matchingGlobalAcl.Count -gt 0) {
                        Say "INFO: $($matchingGlobalAcl.Count) Global ACL assignment(s) also exist for this principal/role. They remain separate Global evidence records." 'Yellow'
                    }
                    $found = @($found[0])
                } else {
                    Say "CONFLICT: duplicate API matches disagree on Propagate ($($propagateVariants.Count) distinct values). Manual review required." 'Red'
                }
            }
            if ($found.Count -ne 1) {
                Say "INVENTORY MATCH DIAGNOSTIC: exact API matches=$($found.Count)" 'Yellow'
                Say "  MOB: Principal=$($m.Principal); IsGroup=$($m.IsGroup); RoleId=$($m.RoleId); Definition=$($m.Definition)" 'Yellow'
                $relatedApi = @($apiRows | Where-Object {
                    $_.Principal -eq $m.Principal -and
                    [string]$_.Entity.Type -eq (($m.Definition -split ':', 5)[2]) -and
                    [string]$_.Entity.Value -eq (($m.Definition -split ':', 5)[3])
                })
                Say "  API rows with matching principal and inventory entity: $($relatedApi.Count)" 'Yellow'
                foreach ($candidate in @($relatedApi | Select-Object -First 25)) {
                    Say "    API candidate: IsGroup=$([bool]$candidate.Group); RoleId=$([string]$candidate.RoleId); Propagate=$([bool]$candidate.Propagate); Entity=$([string]$candidate.Entity.Type):$([string]$candidate.Entity.Value)" 'Yellow'
                }
                if ($relatedApi.Count -gt 25) { Say '    More than 25 related candidates; output truncated.' 'Yellow' }
                $relatedGlobal = @($globalRows | Where-Object { $_.Principal -eq $m.Principal })
                Say "  Global ACL rows for same principal: $($relatedGlobal.Count)" 'Yellow'
                foreach ($candidate in @($relatedGlobal | Select-Object -First 10)) {
                    Say "    Global ACL: IsGroup=$($candidate.IsGroup); RoleId=$($candidate.RoleId); Propagate=$($candidate.Propagate)" 'Yellow'
                }
                throw "Inventory metadata not uniquely resolved ($($found.Count) exact matches). Review diagnostic output; do not deduplicate or accept an incomplete PRE backup."
            }
            $v = $found[0]
            $entityType = [string]$v.Entity.Type
            $entityValue = [string]$v.Entity.Value
            Stop-If ([string]::IsNullOrWhiteSpace($entityValue) -or [string]::IsNullOrWhiteSpace($entityType)) 'Empty MoRef.'
            $entityId = "$entityType-$entityValue"
            $entityView = Get-View -Server $vc -Id $entityId -Property Name -ErrorAction Stop
            $entityName = [string]$entityView.Name
            Stop-If ([string]::IsNullOrWhiteSpace($entityName)) "Object $entityId has no retrievable name."
            $roleId = [string]$v.RoleId
            Stop-If (-not $roleMap.ContainsKey($roleId)) "Unresolved Inventory RoleId: $roleId"
            $roleName = [string]$roleMap[$roleId]
            $principal = [string]$v.Principal
            $isGroup = [bool]$v.Group
            $propagate = [bool]$v.Propagate
            [pscustomobject]@{
                vCenter=$vc.Name; InstanceUuid=$uuid; Principal=$principal; IsGroup=$isGroup
                RoleName=$roleName; RoleId=$roleId; Propagate=$propagate
                EntityName=$entityName; EntityId=$entityId; EntityType=$entityType
                PermissionType='Inventory'; Definition=$m.Definition
                IdentityKey="inventory|$($principal.ToLowerInvariant())|$($isGroup.ToString().ToLowerInvariant())|$($entityType.ToLowerInvariant())|$($entityValue.ToLowerInvariant())"
                AssignmentKey="$($roleName.ToLowerInvariant())|$($propagate.ToString().ToLowerInvariant())"
                CrossCheckStatus='VERIFIED'
            }
        }
    )
    # API may mirror some Global permissions on the vCenter RootFolder.
    # Any *unmatched* API row must be an exact root mirror or is an error.
    foreach ($v in $apiRows) {
        $definition = "urn:vmomi:$($v.Entity.Type):$($v.Entity.Value):$uuid"
        $isInventory = @($mobInventory | Where-Object {
            $_.Principal -eq $v.Principal -and $_.IsGroup -eq [bool]$v.Group -and
            $_.RoleId -eq [string]$v.RoleId -and $_.Definition -eq $definition
        }).Count -eq 1
        if ($isInventory) { continue }
        $asGlobal = @($globalRows | Where-Object {
            $_.Principal -eq $v.Principal -and $_.IsGroup -eq [bool]$v.Group -and
            $_.RoleId -eq [string]$v.RoleId -and $_.Propagate -eq [bool]$v.Propagate
        })
        Stop-If ($asGlobal.Count -ne 1 -or [string]$v.Entity.Value -ne $rootValue) "API permission is neither Inventory nor a Global Root mirror: $($v.Principal) / $definition"
    }
    $all = @($globalRows) + @($inventoryRows)
    $duplicateIdentity = @($all | Group-Object IdentityKey | Where-Object Count -gt 1)
    Stop-If ($duplicateIdentity.Count -gt 0) 'Duplicate identities. Do not deduplicate; investigate.'
    Stop-If ($all.Count -ne $mobRows.Count) 'Totals do not match MOB.'
    Stop-If (@($all | Where-Object CrossCheckStatus -ne 'VERIFIED').Count -gt 0) 'Some rows are not VERIFIED.'
    Say "4/4 VALIDATED: Global=$($globalRows.Count) Inventory=$($inventoryRows.Count) Total=$($all.Count)" 'Green'
    return [pscustomobject]@{ UUID=$uuid; Roles=$roleRows; Permissions=$all; GlobalCount=$globalRows.Count; InventoryCount=$inventoryRows.Count }
}
function Assert-Integrity([object]$Snapshot) {
    $rows = @($Snapshot.Permissions)
    Stop-If ($rows.Count -eq 0) 'Snapshot has no permissions.'
    Stop-If (@($rows | Group-Object IdentityKey | Where-Object Count -gt 1).Count -gt 0) 'CSV: duplicate identities.'
    foreach ($r in $rows) {
        Stop-If ($r.CrossCheckStatus -ne 'VERIFIED') "CSV: unverified row $($r.Principal)"
        Stop-If ([string]$r.InstanceUuid -ne [string]$Snapshot.UUID) 'CSV: inconsistent InstanceUuid.'
        Stop-If ($r.IsGroup -notin @('True','False') -or $r.Propagate -notin @('True','False')) 'CSV: invalid Boolean fields.'
        $p = ([string]$r.Principal).ToLowerInvariant()
        $g = ([string]$r.IsGroup).ToLowerInvariant()
        $expected = if ($r.PermissionType -eq 'Global') {
            Stop-If ($r.Definition -ne 'urn:acl:global:permissions') 'CSV: invalid Global Definition.'
            "global|$p|$g"
        } elseif ($r.PermissionType -eq 'Inventory') {
            $mo = ([string]$r.Definition) -split ':',5
            Stop-If ($mo.Count -ne 5 -or $mo[0] -ne 'urn' -or $mo[1] -ne 'vmomi' -or $mo[4] -ne $Snapshot.UUID -or $mo[2] -ne $r.EntityType -or $r.EntityId -ne "$($mo[2])-$($mo[3])") 'CSV: invalid MoRef/Definition.'
            "inventory|$p|$g|$($mo[2].ToLowerInvariant())|$($mo[3].ToLowerInvariant())"
        } else { throw "CSV: invalid PermissionType: $($r.PermissionType)" }
        $assignment = "$(([string]$r.RoleName).ToLowerInvariant())|$(([string]$r.Propagate).ToLowerInvariant())"
        Stop-If ($r.IdentityKey -ne $expected -or $r.AssignmentKey -ne $assignment) "CSV: inconsistent keys for $($r.Principal)."
    }
}
function Save-LiveSnapshot([string]$Root, [ValidateSet('PRE','CURRENT','POST')][string]$Phase, [object]$Live) {
    $phasePath = if ($Phase -eq 'PRE') { Join-Path $Root 'PRE' } else {
        Join-Path $Root ("{0}-{1}" -f $Phase, (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    }
    Stop-If (Test-Path $phasePath) "$Phase already exists. Refusing to overwrite: $phasePath"
    New-Item -ItemType Directory -Path $phasePath -ErrorAction Stop | Out-Null
    try {
        $Live.Roles | Export-Csv (Join-Path $phasePath 'Roles.csv') -NoTypeInformation -Encoding utf8
        $Live.Permissions | Export-Csv (Join-Path $phasePath 'Permissions.csv') -NoTypeInformation -Encoding utf8
        [pscustomobject]@{
            Phase=$Phase; Server=$Server; EvidenceId=$EvidenceId; InstanceUuid=$Live.UUID
            CapturedUtc=[datetime]::UtcNow.ToString('o'); ToolVersion=$Script:BuildVersion
            Global=$Live.GlobalCount; Inventory=$Live.InventoryCount; Total=$Live.Permissions.Count
            RoleCount=$Live.Roles.Count
        } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $phasePath 'Manifest.json') -Encoding utf8
    } catch { throw "Unable to save evidence to ${phasePath}: $($_.Exception.Message)" }
    Say "$Phase evidence saved: $phasePath" 'Green'
    return $phasePath
}
function Get-PhasePath([string]$Root, [ValidateSet('PRE','CURRENT','POST')][string]$Phase) {
    if ($Phase -eq 'PRE') {
        $path = Join-Path $Root 'PRE'
        Stop-If (-not (Test-Path (Join-Path $path 'Manifest.json'))) 'No validated PRE baseline exists for this EvidenceId.'
        return $path
    }
    $latest = Get-ChildItem -Path $Root -Directory -Filter "$Phase-*" |
        Where-Object { Test-Path (Join-Path $_.FullName 'Manifest.json') } |
        Sort-Object Name -Descending | Select-Object -First 1
    Stop-If (-not $latest) "No $Phase snapshot exists for this EvidenceId."
    return $latest.FullName
}
function Load-Snapshot([string]$Path) {
    $meta = Get-Content (Join-Path $Path 'Manifest.json') -Raw | ConvertFrom-Json
    $snap = [pscustomobject]@{
        UUID=[string]$meta.InstanceUuid
        Roles=@(Import-Csv (Join-Path $Path 'Roles.csv'))
        Permissions=@(Import-Csv (Join-Path $Path 'Permissions.csv'))
        Path=$Path
        Meta=$meta
    }
    Assert-Integrity $snap
    return $snap
}
function Compare-Phase([object]$Pre, [object]$Actual, [string]$SaveTo) {
    Stop-If ($Pre.UUID -ne $Actual.UUID) "InstanceUuid CHANGED: PRE=$($Pre.UUID), CURRENT=$($Actual.UUID). STOP."
    $actualMap = @{}
    foreach ($r in $Actual.Permissions) { $actualMap[$r.IdentityKey] = $r }
    $permissionComparison = @(
        foreach ($saved in $Pre.Permissions) {
            $current = if ($actualMap.ContainsKey($saved.IdentityKey)) { $actualMap[$saved.IdentityKey] } else { $null }
            $status = if ($null -eq $current) { 'MISSING' } elseif ($saved.AssignmentKey -eq $current.AssignmentKey) { 'MATCH' } else { 'DRIFT' }
            [pscustomobject]@{
                Principal=$saved.Principal; IsGroup=$saved.IsGroup; RoleName=$saved.RoleName
                RoleId=$saved.RoleId; Propagate=$saved.Propagate; EntityId=$saved.EntityId
                EntityName=$saved.EntityName; EntityType=$saved.EntityType
                PermissionType=$saved.PermissionType; IdentityKey=$saved.IdentityKey
                Definition=$saved.Definition; Status=$status
            }
        }
    )
    $rolesNow = @{}
    foreach ($r in $Actual.Roles) { $rolesNow[$r.RoleName] = $r }
    $roleComparison = @(
        foreach ($r in $Pre.Roles) {
            $current = if ($rolesNow.ContainsKey($r.RoleName)) { $rolesNow[$r.RoleName] } else { $null }
            $status = if ($null -eq $current) {
                if ($r.IsSystem -eq 'True') { 'MISSING_SYSTEM' } else { 'MISSING' }
            } else {
                $p1 = @(([string]$r.Privileges -split ';') | Where-Object { $_ } | Sort-Object -Unique)
                $p2 = @(([string]$current.Privileges -split ';') | Where-Object { $_ } | Sort-Object -Unique)
                if (($p1 -join ';') -eq ($p2 -join ';')) { 'MATCH' } else { 'PRIVILEGE_DRIFT' }
            }
            [pscustomobject]@{ RoleName=$r.RoleName; IsSystem=$r.IsSystem; Privileges=$r.Privileges; Status=$status }
        }
    )
    $permissionComparison | Export-Csv (Join-Path $SaveTo 'PermissionComparison.csv') -NoTypeInformation -Encoding utf8
    $roleComparison | Export-Csv (Join-Path $SaveTo 'RoleComparison.csv') -NoTypeInformation -Encoding utf8
    Say 'PERMISSIONS comparison (PRE vs current snapshot):'
    $permissionComparison | Group-Object PermissionType,Status | Select-Object Count,Name | Format-Table -AutoSize | Out-Host
    Say 'ROLES comparison:'
    $roleComparison | Group-Object Status | Select-Object Count,Name | Format-Table -AutoSize | Out-Host
    Say "CSV reports: $SaveTo" 'Green'
    return [pscustomobject]@{ Permissions=$permissionComparison; Roles=$roleComparison; Actual=$Actual }
}
function New-ComparisonFromDisk([string]$Root, [ValidateSet('CURRENT','POST')][string]$Phase) {
    $pre = Load-Snapshot (Get-PhasePath $Root 'PRE')
    $actual = Load-Snapshot (Get-PhasePath $Root $Phase)
    $diff = Compare-Phase $pre $actual $actual.Path
    return [pscustomobject]@{ PRE=$pre; CURRENT=$actual; DIFF=$diff }
}
function Test-ProtectedPrincipal([string]$Principal) {
    # IMPORTANT: VSPHERE.LOCAL is an SSO domain, not a blanket service-account marker.
    # Custom local users and groups can be intentionally assigned permissions.
    # Explicit reserved identities are blocked, regardless of approval.
    $id = $Principal.Trim()
    $reserved = @(
        '(?i)^VSPHERE\.LOCAL\\Administrators$',
        '(?i)^VSPHERE\.LOCAL\\Administrator$',
        '(?i)^VSPHERE\.LOCAL\\vCLSAdmin$',
        '(?i)^VSPHERE\.LOCAL\\SystemConfiguration\.Administrators$',
        '(?i)(?:^|\\)vpxd-(?:extension|[A-Za-z0-9_-]+)$',
        '(?i)(?:^|\\)vsphere-webclient$',
        '(?i)(?:^|\\)vCLSAdmin$',
        '(?i)(?:^|\\)vapiEndpoint$'
    )
    foreach ($pattern in $reserved) {
        if ($id -match $pattern) { return $true }
    }
    return $false
}
function New-RestorePlan([object]$Diff, [string]$Destination) {
    $plan = @(
        foreach ($r in @($Diff.Roles | Where-Object Status -eq 'MISSING')) {
            [pscustomobject]@{
                Type='Role'; Principal=''; RoleName=$r.RoleName; EntityName=''; EntityId=''
                Propagate=''; Decision='ELIGIBLE'; Reason='Missing custom role'
            }
        }
        foreach ($r in @($Diff.Permissions | Where-Object Status -eq 'MISSING')) {
            $blocked = Test-ProtectedPrincipal ([string]$r.Principal)
            [pscustomobject]@{
                Type=$r.PermissionType; Principal=$r.Principal; RoleName=$r.RoleName
                EntityName=$r.EntityName; EntityId=$r.EntityId; Propagate=$r.Propagate
                Decision=$(if ($blocked) {'MANUAL_REVIEW'} else {'ELIGIBLE'})
                Reason=$(if ($blocked) {'Reserved/system principal'} else {'Missing baseline permission'})
            }
        }
    )
    # Plan files are written to the new timestamped CURRENT evidence folder only.
    $plan | Export-Csv -Path $Destination -NoTypeInformation -Encoding utf8 -ErrorAction Stop
    Say "RESTORE plan saved: $Destination" 'Green'
    $plan | Format-Table Type,Principal,RoleName,EntityName,Propagate,Decision -AutoSize | Out-Host
    return $plan
}
function Restore-Roles([object]$Comparison, [object]$Connection) {
    $missing = @($Comparison.DIFF.Roles | Where-Object Status -eq 'MISSING')
    $bad = @($Comparison.DIFF.Roles | Where-Object Status -in @('MISSING_SYSTEM','PRIVILEGE_DRIFT'))
    if ($bad.Count -gt 0) {
        $bad | Format-Table RoleName,Status -AutoSize | Out-Host
        throw 'Missing system roles or role drift detected. Resolve manually before proceeding.'
    }
    foreach ($row in $missing) {
        $saved = @($Comparison.PRE.Roles | Where-Object RoleName -eq $row.RoleName)
        Stop-If ($saved.Count -ne 1) "Ambiguous PRE role: $($row.RoleName)"
        $privs = @()
        foreach ($id in @(([string]$saved[0].Privileges -split ';') | Where-Object { $_ })) {
            $found = @(Get-VIPrivilege -Server $Connection.Server -Id $id -ErrorAction Stop)
            Stop-If ($found.Count -ne 1) "Privilege $id not found for $($row.RoleName)."
            $privs += $found[0]
        }
        Stop-If ($privs.Count -eq 0) 'Role has no privileges; manual review required.'
        $null = New-VIRole -Server $Connection.Server -Name $row.RoleName -Privilege $privs -ErrorAction Stop
        Say "Role creation requested: $($row.RoleName). Verify against a subsequent snapshot." 'Green'
    }
}
function Get-SSOAdminConnection([object]$Connection) {
    if ($Script:SsoAdminConnection) { return $Script:SsoAdminConnection }
    $mod = Get-Module -ListAvailable -Name VMware.vSphere.SsoAdmin |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $mod) {
        Say 'A local SSO identity could not be verified through Get-VIAccount.' 'Yellow'
        Say 'VMware.vSphere.SsoAdmin is a community/open-source module (not an officially supported PowerCLI module).' 'Yellow'
        Say 'This module is used ONLY for read-only local SSO identity verification.' 'Yellow'
        if (-not (Confirm-Exact 'Install VMware.vSphere.SsoAdmin v1.3.9 from PowerShell Gallery for local SSO identity verification?' 'INSTALL SSOADMIN')) {
            throw 'Local SSO identity verification unavailable. No changes applied. Install/review VMware.vSphere.SsoAdmin or use a separately validated manual workflow.'
        }
        Install-Module -Name VMware.vSphere.SsoAdmin -RequiredVersion '1.3.9' `
            -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
    }
    Import-Module VMware.vSphere.SsoAdmin -ErrorAction Stop
    foreach ($command in @('Connect-SsoAdminServer','Disconnect-SsoAdminServer','Get-SsoGroup','Get-SsoPersonUser')) {
        Stop-If (-not (Get-Command $command -ErrorAction SilentlyContinue)) "Missing SsoAdmin command: $command"
    }
    $params = @{ Server=$Connection.Server.Name; Credential=$Connection.MobCredential; ErrorAction='Stop' }
    if ($Script:SkipCertificateChecks) { $params.SkipCertificateCheck = $true }
    Say "Connecting to read-only SSO identity discovery on $($Connection.Server.Name)..." 'Cyan'
    $results = @(Connect-SsoAdminServer @params)
    Stop-If ($results.Count -ne 1) 'Expected exactly one SSO Admin connection. No changes applied.'
    $Script:SsoAdminConnection = $results[0]
    return $Script:SsoAdminConnection
}
function Resolve-LocalSsoViaAdmin([string]$PrincipalText, [string]$AccountName, [string]$Domain, [bool]$IsGroup, [object]$Connection) {
    $sso = Get-SSOAdminConnection $Connection
    if ($IsGroup) {
        $entries = @(Get-SsoGroup -Server $sso -Name $AccountName -Domain $Domain -ErrorAction Stop)
    } else {
        $entries = @(Get-SsoPersonUser -Server $sso -Name $AccountName -Domain $Domain -ErrorAction Stop)
    }
    $exact = @($entries | Where-Object {
        [string]$_.Name -ieq $AccountName -and [string]$_.Domain -ieq $Domain
    })
    Stop-If ($exact.Count -ne 1) "Local SSO principal '$PrincipalText' was not uniquely verified by SSO Admin API (exact=$($exact.Count)). No changes applied."
    Say "Verified LOCAL_SSO $($(if ($IsGroup) {'group'} else {'user'})) through SSO Admin: $PrincipalText" 'Green'
    # A verified SSO object is not a VIAccount. New-VIPermission will use the
    # documented explicit -GroupName/-UserName string parameter, not -Principal.
    return [pscustomobject]@{ VerifiedVia='SSO_ADMIN'; Principal=$PrincipalText; IsGroup=$IsGroup }
}
function Resolve-ELMRbacPrincipal([string]$PrincipalText, [bool]$IsGroup, [object]$Connection) {
    # Read-only identity preflight; no wildcard identity substitution.
    # Local SSO: Get-VIAccount followed by SSO Admin API if necessary.
    # AD/LDAP: restrict by directory domain using Get-VIAccount.
    # Federation: vCenter enumeration is not reliable; fail closed.
    Stop-If ([string]::IsNullOrWhiteSpace($PrincipalText)) 'Empty RBAC principal is not eligible for automatic recovery.'
    $text = $PrincipalText.Trim()
    $domain = ''
    $accountName = $text
    $source = 'UNQUALIFIED'
    $query = @{ Server=$Connection.Server; ErrorAction='Stop' }
    if ($IsGroup) { $query.Group = $true } else { $query.User = $true }
    if ($text -match '^(?<Domain>[^\\]+)\\(?<Name>.+)$') {
        $domain = $Matches.Domain
        $accountName = $Matches.Name
        if ($domain -ieq $LocalSsoDomain) {
            $source = 'LOCAL_SSO'; $query.Id = $accountName
        } else {
            $source = 'AD_DOMAIN'; $query.Domain = $domain; $query.Id = $accountName
        }
    } elseif ($text -match '^(?<Name>[^@]+)@(?<Domain>[^@]+)$') {
        $domain = $Matches.Domain
        $accountName = $Matches.Name
        if ($domain -ieq $LocalSsoDomain) {
            $source = 'LOCAL_SSO'; $query.Id = $accountName
        } else {
            $source = 'AD_UPN'; $query.Domain = $domain; $query.Id = $accountName
        }
    } else {
        # Do not guess the directory domain of unqualified accounts.
        $query.Id = $accountName
    }
    $found = @()
    $lookupError = ''
    $attemptCount = if ($source -in @('AD_DOMAIN','AD_UPN')) { 3 } else { 1 }
    for ($attempt = 1; $attempt -le $attemptCount; $attempt++) {
        try {
            $found = @(Get-VIAccount @query)
            if ($found.Count -gt 0) { break }
        } catch { $lookupError = $_.Exception.Message }
        if ($attempt -lt $attemptCount) {
            Say "AD account lookup attempt $attempt/$attemptCount failed for $text. Retrying." 'Yellow'
            Start-Sleep -Seconds 2
        }
    }
    # -Name and -Id are different Get-VIAccount parameter sets. Test separately.
    if ($found.Count -eq 0 -and $source -eq 'LOCAL_SSO') {
        foreach ($candidate in @($text,$accountName)) {
            try {
                $named = @(Get-VIAccount -Server $Connection.Server -Name $candidate `
                    -Group:$IsGroup -User:(!$IsGroup) -ErrorAction Stop)
                if ($named.Count -gt 0) { $found = $named; break }
            } catch { $lookupError = $_.Exception.Message }
        }
    }
    $matching = @(
        foreach ($item in $found) {
            $id = ([string]$item.Id).Trim()
            $name = ([string]$item.Name).Trim()
            $returnedDomain = ''
            if ($item.PSObject.Properties['Domain']) {
                $returnedDomain = ([string]$item.Domain).Trim()
            }
            $names = @($id, $name)
            if ($id -match '^[^\\]+\\(.+)$') { $names += $Matches[1] }
            if ($id -match '^([^@]+)@[^@]+$') { $names += $Matches[1] }
            if (@($names | Where-Object { $_ -ieq $accountName }).Count -eq 0) { continue }
            $qualifiedDomain = ''
            if ($id -match '^([^\\]+)\\.+$') { $qualifiedDomain = $Matches[1] }
            elseif ($id -match '^[^@]+@(.+)$') { $qualifiedDomain = $Matches[1] }
            if ($source -eq 'LOCAL_SSO') {
                # Require evidence that this account really belongs to LOCAL SSO.
                if ($returnedDomain -and $returnedDomain -ine $domain) { continue }
                if ($qualifiedDomain -and $qualifiedDomain -ine $domain) { continue }
                if (-not $returnedDomain -and -not $qualifiedDomain) { continue }
            } elseif ($source -in @('AD_DOMAIN','AD_UPN')) {
                if ($qualifiedDomain -and $qualifiedDomain -ine $domain -and $returnedDomain -ine $domain) { continue }
            } else {
                # Unqualified principals are never assigned to another identity on guesswork.
                if ($qualifiedDomain -or $returnedDomain) { continue }
            }
            $item
        }
    )
    if ($matching.Count -eq 1) {
        Say "Verified $source $($(if ($IsGroup) {'group'} else {'user'})) via Get-VIAccount: $text" 'Green'
        return $matching[0]
    }
    if ($source -eq 'LOCAL_SSO' -and $matching.Count -eq 0) {
        Say "Get-VIAccount could not uniquely verify local SSO '$text'; using SSO Admin identity discovery." 'Yellow'
        return (Resolve-LocalSsoViaAdmin -PrincipalText $text -AccountName $accountName `
            -Domain $domain -IsGroup $IsGroup -Connection $Connection)
    }
    if ($matching.Count -gt 1) {
        throw "Principal '$text' has multiple exact directory matches ($($matching.Count)). No changes applied."
    }
    throw "Unable to verify $source principal '$text' ($($(if ($IsGroup) {'group'} else {'user'}))). Do not substitute another identity. Get-VIAccount detail: $lookupError"
}
function Restore-Inventory([object]$Row, [object]$Connection) {
    $roles = @(Get-VIRole -Server $Connection.Server -Name $Row.RoleName -ErrorAction Stop)
    Stop-If ($roles.Count -ne 1) "Role missing or ambiguous: $($Row.RoleName)"
    $view = Get-View -Server $Connection.Server -Id $Row.EntityId -ErrorAction Stop
    Stop-If ([string]$view.Name -ne [string]$Row.EntityName) "Object $($Row.EntityId) has a different name. Blocked."
    $entity = Get-VIObjectByVIView -VIView $view -ErrorAction Stop
    $isGroup = [bool]::Parse([string]$Row.IsGroup)
    $principalAccount = Resolve-ELMRbacPrincipal -PrincipalText ([string]$Row.Principal) -IsGroup $isGroup -Connection $Connection
    $propagate = [bool]::Parse([string]$Row.Propagate)
    $params = @{ Server=$Connection.Server; Entity=$entity; Role=$roles[0]; Propagate=$propagate; ErrorAction='Stop' }
    if ($principalAccount.PSObject.Properties['VerifiedVia'] -and $principalAccount.VerifiedVia -eq 'SSO_ADMIN') {
        if ($isGroup) { $params.GroupName = [string]$Row.Principal }
        else { $params.UserName = [string]$Row.Principal }
    } else {
        $params.Principal = $principalAccount
    }
    $null = New-VIPermission @params
}
function Restore-Global([object]$Row, [object]$Connection) {
    $roles = @(Get-VIRole -Server $Connection.Server -Name $Row.RoleName -ErrorAction Stop)
    Stop-If ($roles.Count -ne 1) "Global role not found or ambiguous: $($Row.RoleName)"
    $isGroup = [bool]::Parse([string]$Row.IsGroup)
    # The MOB method accepts a text principal. Resolve it against the configured
    # identity source first so an orphan or different AD identity is never created.
    $null = Resolve-ELMRbacPrincipal -PrincipalText ([string]$Row.Principal) -IsGroup $isGroup -Connection $Connection
    $roleId = [string]$roles[0].ExtensionData.RoleId
    $principal = [System.Security.SecurityElement]::Escape([string]$Row.Principal)
    $group = $isGroup.ToString().ToLowerInvariant()
    $propagate = ([bool]::Parse([string]$Row.Propagate)).ToString().ToLowerInvariant()
    $xml = @"
<permissions>
  <principal><name>$principal</name><group>$group</group></principal>
  <roles>$roleId</roles>
  <propagate>$propagate</propagate>
  <version>-1</version>
</permissions>
"@
    $null = Invoke-ELMMob -HostName $Connection.Server.Name -Method 'AddGlobalAccessControlList' -Credential $Connection.MobCredential -Body @{permissions=$xml}
    Say 'MOB accepted HTTP request; only an independent POST snapshot can confirm the result.' 'Yellow'
}
function Run-Action([string]$Mode) {
    if ($Mode -eq 'Setup') { Install-Prerequisites; return }
    $root = Get-Context -Offline:($Mode -eq 'Compare')
    if ($Mode -eq 'Compare') {
        $p = (Read-Host 'Compare PRE against CURRENT or POST? [CURRENT]').ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($p)) { $p = 'CURRENT' }
        Stop-If ($p -notin @('CURRENT','POST')) 'Invalid selection: CURRENT or POST.'
        $null = New-ComparisonFromDisk $root $p
        return
    }
    $conn = Connect-ELM
    if ($Mode -in @('PRE','CURRENT','POST')) {
        if ($Mode -eq 'PRE' -and (Test-Path (Join-Path $root 'PRE'))) {
            throw 'PRE already exists. Do not recreate or overwrite the baseline; review evidence.'
        }
        if ($Mode -ne 'PRE') {
            $pre = Load-Snapshot (Get-PhasePath $root 'PRE')
            $vi = Get-View -Server $conn.Server -Id ServiceInstance -ErrorAction Stop
            Stop-If ([string]$vi.Content.About.InstanceUuid -ne $pre.UUID) 'UUID changed since PRE. Do not automate.'
        }
        $live = Get-LiveSnapshot $conn
        $path = Save-LiveSnapshot $root $Mode $live
        $disk = Load-Snapshot $path
        if ($Mode -eq 'PRE') {
            Say 'PRE VALIDATED. Copy this evidence folder to secure storage BEFORE the ELM split.' 'Green'
        } else {
            $pre = Load-Snapshot (Get-PhasePath $root 'PRE')
            $diff = Compare-Phase $pre $disk $path
            if (@($diff.Permissions | Where-Object Status -ne 'MATCH').Count -eq 0 -and
                @($diff.Roles | Where-Object Status -ne 'MATCH').Count -eq 0) {
                Say "${Mode}: all PRE roles and permissions are MATCH." 'Green'
            } else { Say "${Mode}: differences found. Review reports; do not mark complete." 'Yellow' }
        }
        return
    }
    if ($Mode -eq 'Restore') {
        Say 'RESTORE requires approved change authorization. Collecting a fresh CURRENT snapshot before any write.' 'Yellow'
        $pre = Load-Snapshot (Get-PhasePath $root 'PRE')
        $vi = Get-View -Server $conn.Server -Id ServiceInstance -ErrorAction Stop
        Stop-If ([string]$vi.Content.About.InstanceUuid -ne $pre.UUID) 'UUID changed since PRE. STOP.'
        $currentLive = Get-LiveSnapshot $conn
        $currentPath = Save-LiveSnapshot $root 'CURRENT' $currentLive
        $current = Load-Snapshot $currentPath
        $diff = Compare-Phase $pre $current $currentPath
        $bundle = [pscustomobject]@{ PRE=$pre; CURRENT=$current; DIFF=$diff }
        $changes = @($diff.Permissions | Where-Object Status -ne 'MATCH')
        $changes | Format-Table PermissionType,Principal,RoleName,EntityName,Status -AutoSize | Out-Host
        if (@($diff.Permissions | Where-Object Status -eq 'DRIFT').Count -gt 0) {
            throw 'Permission DRIFT detected. Automated restoration is blocked pending manual review.'
        }
        $invalidRoles = @($diff.Roles | Where-Object Status -in @('MISSING_SYSTEM','PRIVILEGE_DRIFT'))
        if ($invalidRoles.Count -gt 0) {
            $invalidRoles | Format-Table RoleName,Status -AutoSize | Out-Host
            throw 'Missing system roles or role privilege drift detected. No automated writes allowed.'
        }
        $planPath = Join-Path $currentPath 'RestorePlan.csv'
        $plan = @(New-RestorePlan -Diff $diff -Destination $planPath)
        $eligible = @($plan | Where-Object Decision -eq 'ELIGIBLE')
        $excluded = @($plan | Where-Object Decision -eq 'MANUAL_REVIEW')
        if ($excluded.Count -gt 0) {
            Say "WARNING: $($excluded.Count) reserved principal permissions will NOT be restored automatically." 'Yellow'
        }
        if ($eligible.Count -eq 0) {
            Say 'No eligible changes; no write operations performed.' 'Yellow'
            return
        }
        # Identity preflight is read-only and runs before the single batch approval.
        # A missing/unqueryable AD, LDAP or federated identity must block all writes.
        $identityRows = @($diff.Permissions | Where-Object {
            $_.Status -eq 'MISSING' -and -not (Test-ProtectedPrincipal ([string]$_.Principal))
        })
        if ($identityRows.Count -gt 0) {
            Say "IDENTITY PREFLIGHT: validating $($identityRows.Count) missing permission principal(s) before authorizing changes." 'Cyan'
            foreach ($r in $identityRows) {
                $isGroup = [bool]::Parse([string]$r.IsGroup)
                $null = Resolve-ELMRbacPrincipal -PrincipalText ([string]$r.Principal) -IsGroup $isGroup -Connection $conn
            }
            Say 'IDENTITY PREFLIGHT PASSED. No AD or local SSO identity ambiguities found.' 'Green'
        }
        Say "BATCH PLAN: $(@($eligible | Where-Object Type -eq 'Role').Count) roles; $(@($eligible | Where-Object Type -eq 'Global').Count) Global; $(@($eligible | Where-Object Type -eq 'Inventory').Count) Inventory permissions." 'Yellow'
        Say 'Review the CSV restore plan and confirm the planned changes are covered by an approved change request.' 'Yellow'
        if (-not (Confirm-Exact 'Apply ALL eligible items shown in RestorePlan.csv (one approval for the whole batch)?' 'APPLY ALL')) {
            Say 'Batch not authorized. No changes applied.' 'Yellow'
            return
        }
        # Roles are restored first. Every write is covered by the single reviewed batch plan.
        Restore-Roles $bundle $conn
        $afterRolesLive = Get-LiveSnapshot $conn
        $afterRolesPath = Save-LiveSnapshot $root 'CURRENT' $afterRolesLive
        $afterRoles = Load-Snapshot $afterRolesPath
        $diff2 = Compare-Phase $pre $afterRoles $afterRolesPath
        Stop-If (@($diff2.Roles | Where-Object Status -ne 'MATCH').Count -gt 0) 'Roles are not MATCH. Resolve before restoring permissions.'
        Stop-If (@($diff2.Permissions | Where-Object Status -eq 'DRIFT').Count -gt 0) 'Permission DRIFT detected. Do not modify permissions.'
        $initialMissingKeys = @($diff.Permissions | Where-Object Status -eq 'MISSING' | Select-Object -ExpandProperty IdentityKey | Sort-Object)
        $recheckedMissingKeys = @($diff2.Permissions | Where-Object Status -eq 'MISSING' | Select-Object -ExpandProperty IdentityKey | Sort-Object)
        Stop-If (($initialMissingKeys -join [char]10) -ne ($recheckedMissingKeys -join [char]10)) 'The missing permission list changed after restoring roles. New approval required.'
        $missing = @($diff2.Permissions | Where-Object Status -eq 'MISSING')
        $hadErrors = $false
        foreach ($r in $missing) {
            if (Test-ProtectedPrincipal ([string]$r.Principal)) {
                Say "SKIPPED (reserved principal): $($r.Principal). Requires manual review." 'Yellow'
                continue
            }
            try {
                Say "RESTORING $($r.PermissionType): $($r.Principal) => $($r.RoleName) on $($r.EntityName)" 'Cyan'
                if ($r.PermissionType -eq 'Inventory') { Restore-Inventory $r $conn }
                else { Restore-Global $r $conn }
                Say "Request submitted for $($r.Principal); awaiting independent POST verification." 'Green'
            } catch {
                $hadErrors = $true
                Say "ERROR restoring $($r.Principal): $($_.Exception.Message)" 'Red'
                break
            }
        }
        Say 'Collecting an independent POST snapshot for verification...'
        $postLive = Get-LiveSnapshot $conn
        $postPath = Save-LiveSnapshot $root 'POST' $postLive
        $post = Load-Snapshot $postPath
        $postDiff = Compare-Phase $pre $post $postPath
        if ($hadErrors -or @($postDiff.Permissions | Where-Object Status -ne 'MATCH').Count -gt 0 -or
            @($postDiff.Roles | Where-Object Status -ne 'MATCH').Count -gt 0) {
            throw 'POST INCOMPLETE: review CSV reports, address gaps, and document exceptions.'
        } else {
            Say 'PRE vs POST: all baseline roles and permissions are MATCH.' 'Green'
        }
        return
    }
    throw "Action not implemented: $Mode"
}
function Show-Menu {
    Write-Host ''
    Write-Host ('======== vCenter ELM - RBAC {0} ========' -f $Script:BuildVersion) -ForegroundColor Cyan
    Write-Host '1  Prepare PowerShell/VCF PowerCLI'
    Write-Host '2  PRE      - Backup before ELM split'
    Write-Host '3  CURRENT  - Snapshot and comparison after ELM split'
    Write-Host '4  COMPARE  - Compare saved CSV files (offline)'
    Write-Host '5  RESTORE  - Reviewed recovery plan; one batch approval'
    Write-Host '6  POST     - Final independent verification'
    Write-Host '0  Exit'
    Write-Host '======================================================' -ForegroundColor Cyan
}
try {
    if ($Action -eq 'Menu') {
        Show-Menu
        $choice = Read-Host 'Option'
        $Action = switch ($choice) {
            '1' { 'Setup' }; '2' { 'PRE' }; '3' { 'CURRENT' }; '4' { 'Compare' }
            '5' { 'Restore' }; '6' { 'POST' }; '0' { return }
            default { throw "Invalid option: $choice" }
        }
    }
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    $logFolder = Join-Path $WorkDir 'Logs'
    New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
    $logFile = Join-Path $logFolder ("ELM-{0}-{1}.log" -f $Action,(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    Start-Transcript -Path $logFile -ErrorAction Stop | Out-Null
    $Script:TranscriptStarted = $true
    Say "Action: $Action; build $Script:BuildVersion"
    Run-Action $Action
    Say "Completed. Log: $logFile" 'Green'
} catch {
    Say "STOPPED: $($_.Exception.Message)" 'Red'
    Say 'Do not treat this backup/change as successful. Review log and data before retrying.' 'Yellow'
    exit 1
} finally {
    if ($Script:SsoAdminConnection) {
        try { Disconnect-SsoAdminServer -Server $Script:SsoAdminConnection -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
    if ($Script:VIConnection) {
        try { Disconnect-VIServer -Server $Script:VIConnection -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
    Disable-SessionCertificateBypass
    if ($Script:TranscriptStarted) {
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
}
