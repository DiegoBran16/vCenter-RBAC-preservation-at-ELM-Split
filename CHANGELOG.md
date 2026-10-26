# Changelog

All notable **public release** changes to vCenter ELM RBAC Recovery will be documented in this file.

The project provides a PowerShell toolkit for preserving, comparing, and conditionally restoring vCenter Server roles, Global Permissions, and Inventory Permissions during Enhanced Linked Mode (ELM) split activities. **It does not perform the ELM split.**

## [0.1.0] - 2026-10-26

**Initial public pre-release.** This is the first version published in this repository. Earlier development and lab iterations were internal and are intentionally not listed as public releases.

### Added

- Versioned executable **`scripts/vCenter-ELM-RBAC-v0.1.0.ps1`** with interactive **SETUP, PRE, CURRENT, COMPARE, RESTORE, and POST** actions.
- One-time PowerShell/VCF PowerCLI setup, with prerequisite and command checks.
- Backups of vCenter roles and privileges, Global Permissions, and Inventory Permissions.
- MOB and vSphere API collection with cross-validation, metadata checks, and stop-on-error controls.
- Timestamped evidence folders, CSV exports, manifests, comparisons, and execution logs.
- Conditional restoration of missing custom roles and eligible permissions through a reviewed restore plan and a single explicit **`APPLY ALL`** authorization.
- Identity preflight for local SSO and supported integrated AD/LDAP identity sources; ambiguous or unresolved principals are not automatically restored.
- Session-only handling of untrusted certificates after explicit operator acknowledgement for controlled lab scenarios.
-  An [Operator Runbook](docs/Operator-Runbook.md).

### Lab validation

- **Local SSO scenario:** tested in a controlled **vCenter Server 8** lab with deliberately removed custom roles and local SSO permissions. Successfully restored **2 custom roles**, **1 Global Permission assigned to a local SSO group**, and **1 Inventory Permission assigned to a local SSO user**.
- **Local SSO independent POST:** reconciled the baseline with **50/50 roles**, **27/27 Global Permissions**, and **6/6 Inventory Permissions** reported as `MATCH`. These counts are specific to that lab, not expected values for other vCenters.
- **OpenLDAP scenario:** separately tested principals provided by an OpenLDAP vCenter identity source. Deliberately removed and successfully restored **1 Global Permission assigned to an OpenLDAP group** and **1 Inventory Permission assigned to an OpenLDAP user on a cluster**—the same number and permission types as in the local SSO scenario. This validates the tested OpenLDAP **group (Global)** and **user (Inventory)** recovery paths; it does **not** establish that every combination of account type, permission scope, LDAP directory, or identity-source configuration will work.

### Known limitations and validation boundaries

- **Microsoft Active Directory** and LDAP implementations other than the tested OpenLDAP configuration have **not** been independently validated end-to-end in this release. **Microsoft AD configured as an integrated LDAP/LDAPS identity source is expected to be compatible** with the existing identity-resolution and restoration workflow, based on successful OpenLDAP **group and user** recovery and the tool's use of PowerCLI directory-account lookup. This is a **technical expectation, not a verified compatibility claim**; AD users and groups must be tested separately before production use. Only the tested OpenLDAP group/Global and user/cluster-Inventory combinations are established by the lab evidence.
- External **federated IdP** identities may not be resolvable by the tool; automated restoration must stop when identity verification is unavailable.
- A complete real-world ELM split and production deployment have not been validated with this release.
- Changes reported as `DRIFT` or system/service-account anomalies require manual investigation; the tool must not silently overwrite them.
- This utility does not replace vCenter file-based backups, coordinated snapshots, an approved ELM split runbook, or change-control procedures.

---

For operating instructions, see [docs/Operator-Runbook.md](docs/Operator-Runbook.md).
