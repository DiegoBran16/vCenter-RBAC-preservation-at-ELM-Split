# vCenter Server 8 — ELM Split RBAC Preservation and Recovery
## Operational Runbook | Operator Edition

**Tool:** `scripts/vCenter-ELM-RBAC-v0.1.0.ps1` (copy to the workstation working directory before execution)  
**Release:** v0.1.0 — Initial Public Pre-release  
**Runbook edition:** Operator Edition  
**Scope:** vCenter Server 8.x; backup, comparison, conditional restoration, and validation of roles, Global Permissions, and Inventory Permissions  
**Validation status:** PRE, CURRENT, custom-role restoration, local SSO Global/Inventory permission restoration, and independent POST comparison succeeded in a controlled vCenter 8 lab. **Restoration of 1 Global Permission and 1 Inventory Permission assigned to OpenLDAP users was also validated in the lab, matching the local SSO test scope.** Microsoft Active Directory, other LDAP configurations, LDAP/AD groups, federated identities, and the full ELM split operation have not been validated by these tests. **Microsoft AD via an integrated LDAP/LDAPS identity source is expected to work, but remains untested.**

> **Boundary:** This tool does **not** split Enhanced Linked Mode. Execute the ELM split using a separately approved procedure. The RBAC tool complements, but does not replace, coordinated vCenter backups, snapshots, recovery plans, and change approvals.

### Execution record

| Field | Enter at execution time |
|---|---|
| Change / ticket | |
| Operator | |
| Change date and time | |
| vCenter FQDN | |
| Evidence ID (keep unchanged across phases) | |
| Secure location of PRE backup | |

## 1. Prerequisites

Before beginning:

- Have access to a Windows workstation with **PowerShell 7.4 or later** and connectivity to the target vCenter on HTTPS.
- Have authorized vCenter administration and MOB credentials. They are requested interactively and should not be saved in scripts.
- Confirm the target vCenter is version 8.x; confirm vCenter, SSO, and identity-source health.
- Obtain the approved change request, ELM-split procedure, coordinated vCenter protection/backup plan, and recovery method.
- Obtain **`scripts/vCenter-ELM-RBAC-v0.1.0.ps1`** from the approved repository release, verify its source, and copy it into your local working directory **without renaming it**. Inspect the script before use.
- Use the **same** vCenter FQDN and Evidence ID in PRE, CURRENT, RESTORE, COMPARE, and POST.
- Use a trusted vCenter TLS certificate for production. Any bypass is intended only for a controlled lab and requires explicit acknowledgment.

**Identity sources:** Local SSO and directory-backed users/groups must remain resolvable through their existing vCenter identity sources after the split. The tool does **not** migrate identity sources or create directory accounts. **Lab-validated:** restoration of **1 Global Permission and 1 Inventory Permission** using local SSO principals, and an equivalent test of **1 Global Permission and 1 Inventory Permission** assigned to **OpenLDAP user accounts**. **Expected but not yet lab-validated:** Microsoft AD accounts connected through a vCenter LDAP/LDAPS identity source are likely to work using the same directory-backed resolution and recovery mechanisms that succeeded with OpenLDAP user accounts; this is an engineering expectation, **not** an AD test result. Microsoft AD users and groups, LDAP/AD group-permission restoration, and other LDAP configurations still require separate end-to-end tests. External federated IdPs are not supported for automatic identity discovery/recovery.

## 2. One-time workstation setup

Open Windows PowerShell and install PowerShell 7 if necessary:

```powershell
winget install --id Microsoft.PowerShell
```

Open **PowerShell 7** (`pwsh`), then verify:

```powershell
$PSVersionTable.PSVersion
```

Choose a writable working directory and place the script there:

```powershell
New-Item -ItemType Directory -Path 'C:\ELM-Break' -Force
Set-Location 'C:\ELM-Break'
```

After validating the file's provenance and content, remove the downloaded-file block if Windows applied one:

```powershell
Unblock-File .\vCenter-ELM-RBAC-v0.1.0.ps1
```

Optional syntax validation (does not execute the script):

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path '.\vCenter-ELM-RBAC-v0.1.0.ps1').Path,
    [ref]$tokens,
    [ref]$errors
) | Out-Null
$errors | Format-List Message,Extent
```

No errors should be displayed. Start the tool and select **1 — Prepare PowerShell/VCF PowerCLI**:

```powershell
.\vCenter-ELM-RBAC-v0.1.0.ps1
```

If `VCF.PowerCLI` is missing, Setup requests explicit permission to install the pinned module version **9.1.1.25718932** from PowerShell Gallery. Verify the publisher/source before approving the installation. A community SSO Admin module may be offered later **only when necessary** to verify local SSO principals during RESTORE; its installation is not required for PRE/CURRENT.

**Setup acceptance:** PowerShell and PowerCLI versions are shown, the working directory is prepared, and `SETUP COMPLETED` appears. Run Setup only as needed, not before every phase.

## 3. Execution overview

| Menu | Phase | When to use | vCenter configuration changed? |
|---|---|---|---|
| **1** | Setup | One-time module preparation | No (workstation only) |
| **2** | PRE | **Before** the ELM split | No |
| **3** | CURRENT | After the split, before recovery | No |
| **4** | COMPARE | Offline comparison of saved evidence | No |
| **5** | RESTORE | After reviewing missing items and obtaining approval | **Yes** |
| **6** | POST | Final independent verification | No |

Launch the menu with:

```powershell
Set-Location 'C:\ELM-Break'
.\vCenter-ELM-RBAC-v0.1.0.ps1
```

When prompted, provide the **vCenter FQDN**, an **Evidence ID** (for example, `vc01`), and credentials. Preserve the same Evidence ID in every phase. If you launch the tool in a different directory, outputs still default to the folder containing the script unless `-WorkDir` is explicitly supplied.

### Phase A — PRE (menu option 2)

1. Run **PRE** against the original vCenter **before** the ELM split.
2. Confirm roles, Global Permissions, and Inventory Permissions are collected.
3. Require the final `4/4 VALIDATED` quality check and `PRE VALIDATED` message.
4. Confirm `Roles.csv`, `Permissions.csv`, and `Manifest.json` were created in `<workdir>\<EvidenceId>\PRE`.
5. **Copy the entire PRE evidence folder to secure external storage** and protect it from modification.

**STOP if:** any permission is unresolved, the parser fails, validation does not pass, or PRE is missing/incomplete. Never overwrite a completed PRE baseline to hide an error.

### Phase B — Perform the approved ELM split

Carry out the **separate** change runbook and required backups/snapshots. Before continuing, validate vCenter services, inventory access, SSO health, and the needed local and directory identity sources. Do not begin automatic recovery if identities cannot be resolved.

### Phase C — CURRENT (menu option 3)

1. Run **CURRENT** using the same vCenter FQDN and Evidence ID.
2. The tool captures a new state, checks the vCenter instance UUID against PRE, and creates `RoleComparison.csv` and `PermissionComparison.csv`.
3. Review the comparison summary and all non-`MATCH` rows. Confirm that any changes are expected and documented.

| Comparison result | Required action |
|---|---|
| `MATCH` | No action |
| `MISSING` | Review for authorized conditional restoration |
| `DRIFT` / `PRIVILEGE_DRIFT` | **Stop**; manual investigation |
| `MISSING_SYSTEM` | **Stop**; escalate |

**Do not** assume that an item marked `MISSING` should always be restored. Confirm its owner, identity source, and approved intended assignment first.

### Phase D — RESTORE (menu option 5, only if needed)

1. Confirm the change request explicitly authorizes RBAC restoration.
2. Select **RESTORE** with the same target/evidence ID. The tool captures a **fresh CURRENT** before writes.
3. Review missing entries and the generated `RestorePlan.csv`, including `ELIGIBLE` and `MANUAL_REVIEW` decisions.
4. Complete the **identity preflight**. The tool verifies each missing user's/group's exact identity against its configured source (for example, local SSO or an integrated LDAP directory) before requesting the batch approval. If it cannot verify an identity, **stop** and resolve the source or use an approved manual process. Never substitute a different user/group with a similar name.
5. After reviewing the entire plan, authorize the batch with the exact required confirmations: `REVIEW`, then **`APPLY ALL`**. Do not approve unless every `ELIGIBLE` item is covered by the change request.
6. The tool recreates missing custom roles first, captures a new state, then restores eligible missing Global and Inventory Permissions. Protected system/service principals are excluded.
7. An independent POST snapshot and comparison run automatically after the restore attempts.

**Important:** A batch may partially succeed. If the script stops or POST is incomplete, review the live state and logs before any rerun. Never retry writes blindly or treat an HTTP 200 response as proof of a restored permission.

### Phase E — POST (menu option 6)

Run **POST** independently after recovery or, if no recovery was needed, after completing CURRENT review. Require **all PRE baseline roles and permissions to be `MATCH`**. Resolve and document every remaining non-match before change closure.

Example successful completion message:

```text
4/4 VALIDATED: Global=<count> Inventory=<count> Total=<count>
PRE vs POST: all baseline roles and permissions are MATCH.
```

Counts vary by vCenter; the acceptance condition is **full reconciliation with the PRE baseline**, not a predetermined number of entries.

## 4. Evidence location and handoff

By default, reports are saved beside the script:

```text
C:\ELM-Break\
  vCenter-ELM-RBAC-v0.1.0.ps1
  Logs\
    ELM-<action>-<timestamp>.log
  <EvidenceId>\
    PRE\
      Roles.csv
      Permissions.csv
      Manifest.json
    CURRENT-<timestamp>\
      Roles.csv
      Permissions.csv
      Manifest.json
      RoleComparison.csv
      PermissionComparison.csv
      RestorePlan.csv      (when RESTORE prepares a plan)
    POST-<timestamp>\
      Roles.csv
      Permissions.csv
      Manifest.json
      RoleComparison.csv
      PermissionComparison.csv
```

PRE is not silently overwritten; CURRENT and POST have unique timestamped folders. Retain the protected PRE, latest relevant CURRENT, RESTORE plan, POST and logs with the change ticket. Treat files as sensitive: they contain identity and infrastructure information.

## 5. Common stop conditions and operator response

| Symptom | Operator response |
|---|---|
| Invalid vCenter certificate | Correct the certificate/CA trust. A temporary `IGNORE` exception is for verified **lab** use only. |
| MOB parsing or permission metadata failure | **Stop**; do not use an incomplete PRE/CURRENT. Preserve the log and escalate for parser/API review. |
| UUID differs from PRE | **Stop**; verify target vCenter identity and whether the appliance was replaced/redeployed. |
| SSO/AD/LDAP identity not found or ambiguous | **Stop**; validate the original identity source and exact user/group; never substitute a similarly named account. |
| External federated IdP principal cannot be resolved | Do not use automated restoration; follow an independently reviewed manual procedure. |
| Protected system/service principal missing | Leave in `MANUAL_REVIEW` and escalate. |
| `DRIFT`, `PRIVILEGE_DRIFT` or missing system roles | **Stop**; do not automatically overwrite. |
| Partial RESTORE / POST not fully `MATCH` | Retain evidence; investigate actual vCenter state before trying again. |

## 6. Completion checklist

- [ ] PRE validated and copied to protected storage **before** the change.
- [ ] Approved ELM split completed and vCenter/SSO/identity services validated.
- [ ] CURRENT and comparison reports captured and reviewed.
- [ ] Any RESTORE was authorized against a reviewed `RestorePlan.csv`.
- [ ] POST independently collected and all PRE roles/permissions `MATCH`.
- [ ] Evidence, logs, exceptions, and approvals attached to the change record.

## 7. Notes on validation scope

Release **v0.1.0 (pre-release)** was validated in a controlled **vCenter Server 8** lab through deliberate deletion and recovery of **two custom roles**, **one local SSO Global Permission**, and **one local SSO Inventory Permission**. An independent POST comparison returned **50 roles**, **27 Global Permissions**, and **6 Inventory Permissions** as `MATCH` in that test. These counts are environment-specific.

A separate **OpenLDAP user-account** lab test followed the same permission-recovery scope as the local SSO test: **1 deliberately removed Global Permission and 1 deliberately removed Inventory Permission**, both successfully restored through the configured vCenter identity source. This validates the tested user-principal workflow for **both permission types**, but does **not** validate LDAP groups, every LDAP implementation, or every identity-source configuration. The 50/27/6 reconciliation totals above belong to the local SSO scenario and must not be assumed to represent the independent OpenLDAP test.

**Microsoft AD compatibility note:** Because the tool supports directory-backed identity lookup and successfully restored OpenLDAP user permissions, it is **reasonable to expect** restoration to work with Microsoft AD users/groups when AD is configured as a vCenter integrated LDAP/LDAPS identity source, provided each identity can be resolved unambiguously. **This remains an untested scenario and is not a guarantee of compatibility.** Verify domain aliases, individual users, groups, and Global/Inventory Permissions in a non-production AD-connected vCenter before production use. This expectation does not extend to federated IdPs such as ADFS or Entra ID.

**Not yet established by these tests:** an end-to-end production ELM split, recovery with Microsoft Active Directory principals, LDAP/AD group permissions, other LDAP directory configurations, external federated IdP recovery, and all possible vCenter 8 MOB variants. Validate these cases separately before relying on them in a production change.

---

**Release history:** [CHANGELOG.md](../CHANGELOG.md)  
**Reference:** [Broadcom VCF PowerCLI installation guide](https://developer.broadcom.com/powercli/installation-guide) · [PowerCLI `Get-VIAccount`](https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/get-viaccount) · [PowerCLI `New-VIPermission`](https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/new-vipermission)
