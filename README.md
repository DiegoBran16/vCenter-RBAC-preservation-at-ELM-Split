# vCenter RBAC Preservarion at ELM Split

PowerShell toolkit for **backing up, comparing, and conditionally restoring vCenter Server roles, Global Permissions, and Inventory Permissions** before and after a VMware vCenter Enhanced Linked Mode (ELM) split.

> **Scope:** This tool **does not perform the ELM split**. It preserves RBAC evidence and helps recover approved missing assignments around a separately planned ELM split. **v0.1.0 is an initial public pre-release**, validated in a controlled vCenter Server 8 lab—not a production-certified recovery procedure.

## Features

- Capture a **PRE** baseline of roles, role privileges, Global Permissions, and Inventory Permissions.
- Collect a fresh **CURRENT** snapshot and compare it to the saved baseline.
- Run **COMPARE** offline against previously captured evidence.
- Review a `RestorePlan.csv` and conditionally **RESTORE** missing custom roles and eligible permissions with explicit `REVIEW` / `APPLY ALL` authorization.
- Validate results using an independent **POST** snapshot and PRE-to-POST reconciliation.
- Export CSV evidence, manifests, and execution logs for change documentation.
- Stop on unresolved principals, mismatched vCenter UUIDs, detected privilege drift, and protected system/service-account scenarios rather than silently changing them.

## Lab validation status

| Scenario | Status |
| --- | --- |
| PRE, CURRENT, COMPARE, RESTORE, and POST workflows | Lab validated on vCenter Server 8 |
| Custom role recovery | Lab validated (2 roles restored) |
| Local SSO permissions | Lab validated: 1 Global Permission assigned to a group + 1 Inventory Permission assigned to a user |
| OpenLDAP group — Global Permission | **Lab validated** (1 permission restored) |
| OpenLDAP user — cluster Inventory Permission | **Lab validated** (1 permission restored) |
| Microsoft Active Directory via an integrated LDAP/LDAPS identity source | **Expected to work, not yet tested** |
| Microsoft AD user/group-permission recovery | Not yet tested with Microsoft AD |
| Federated external IdPs | Automated identity recovery not established; manual review required |
| Full ELM split and production deployment | Outside this tool's validation scope |

In the local SSO lab scenario, the deliberately removed Global Permission belonged to a local SSO group and the Inventory Permission belonged to a local SSO user. Independent POST verification returned **50/50 roles**, **27/27 Global Permissions**, and **6/6 Inventory Permissions** as `MATCH`. These counts reflect that specific lab, not required values for other environments.

**Microsoft AD note:** The successful OpenLDAP group and user permission-recovery tests and the tool's directory-backed identity-resolution approach provide a reasonable technical basis to expect Microsoft AD principals to work when AD is configured as an integrated vCenter LDAP/LDAPS identity source. **This has not been tested end-to-end with Microsoft AD, and compatibility is not guaranteed.** Validate users, groups, domain aliases, and both permission types in a non-production AD-connected vCenter first.

## Requirements

- Windows workstation with **PowerShell 7.4+** (recommended by the Operator Runbook).
- Network access to the target **vCenter Server 8.x** and permissions to read RBAC configuration; approved administrative permissions are required for recovery.
- **VCF.PowerCLI** (the tool's Setup option can install its pinned version after prompting).
- Approved change request, vCenter protection/backup strategy, and a separate ELM split procedure.
- Working identity sources (local SSO and/or integrated directories) so principals can be resolved after the split.
- A trusted vCenter TLS certificate for production. The temporary certificate exception is intended for controlled labs only.

The community `VMware.vSphere.SsoAdmin` module may be requested for local SSO identity verification when PowerCLI cannot resolve a principal. Its installation requires explicit approval.

## Quick start

From the repository root, copy the release script **outside the Git repository** so generated evidence and logs are not accidentally committed:

```powershell
New-Item -ItemType Directory -Path 'C:\ELM-Break' -Force | Out-Null
Copy-Item '.\scripts\vCenter-ELM-RBAC-v0.1.0.ps1' 'C:\ELM-Break\'
Set-Location 'C:\ELM-Break'

# Review and trust the downloaded script before unblocking it.
Unblock-File '.\vCenter-ELM-RBAC-v0.1.0.ps1'
.\vCenter-ELM-RBAC-v0.1.0.ps1
```

Use the menu to run these phases:

| Option | Action | Purpose |
| --- | --- | --- |
| 1 | **Setup** | Prepare PowerShell / VCF PowerCLI |
| 2 | **PRE** | Capture and safeguard the baseline **before** splitting ELM |
| 3 | **CURRENT** | Capture and compare state **after** the split |
| 4 | **COMPARE** | Recompare existing saved evidence offline |
| 5 | **RESTORE** | Review and approve recovery of eligible missing items |
| 6 | **POST** | Verify that the PRE baseline is fully reconciled |

**Important:** Use the **same vCenter FQDN and Evidence ID** across all phases. Protect the full PRE evidence directory in separate secure storage before the change. Only RESTORE is intended to write RBAC configuration to vCenter.

For command-line usage, prerequisites, interpretation of comparison statuses, and stop/recovery conditions, see the **[Operator Runbook](docs/Operator-Runbook.md)**.

## Safety and known limitations

- **No automatic ELM split:** follow an approved, separate procedure, including coordinated vCenter backups and recovery planning.
- **No automatic drift overwrite:** `DRIFT`, `PRIVILEGE_DRIFT`, missing system roles, and unresolved or protected principals require investigation.
- **Verify identities before restoration:** the script does not create directory users/groups or migrate identity sources; do not substitute a similarly named principal.
- **Review every planned change:** RESTORE requires explicit batch authorization and may partially succeed. A successful HTTP request alone is **not** proof of recovery; use POST evidence.
- **Protect evidence:** CSVs and logs may contain identities and infrastructure metadata. Keep them out of source control and attach them only to authorized change records.
- **Test before production:** results from the documented lab cases should not be generalized to all identity providers, vCenter configurations, or production ELM splits.

## Repository contents

```text
vCenter-RBAC-preservation-at-ELM-Split/
├── README.md
├── CHANGELOG.md
├── docs/
│   └── Operator-Runbook.md
└── scripts/
    └── vCenter-ELM-RBAC-v0.1.0.ps1
```

## Development acknowledgment

This tool was developed with AI assistance for PowerShell scripting, troubleshooting, code refinement, and documentation. Technical requirements, implementation decisions, and functional testing were directed and validated by the project author.

The tool was iteratively tested in a controlled vCenter Server 8 laboratory, including RBAC backup, comparison, and recovery of custom roles, local SSO permissions, and OpenLDAP permissions (a group-assigned Global Permission and a user-assigned cluster Inventory Permission). AI assistance does not replace independent code review, change control, or validation in the intended environment.

**Documentation:** [Operator Runbook](docs/Operator-Runbook.md) · [Changelog](CHANGELOG.md)

**Release:** `v0.1.0` — Initial Public Pre-release

This is an independent community toolkit. Review its code and validate it in a non-production environment before operational use.
