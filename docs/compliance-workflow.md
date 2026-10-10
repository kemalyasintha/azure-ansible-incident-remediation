# Compliance workflow demonstration

This extension demonstrates evidence collection, access review and remediation tracking using synthetic data and local files. It needs Python 3.10 or later, no third-party packages and no Azure subscription. It does not implement NERC CIP compliance or certify a system.

## Run the scenario

From the repository root:

```bash
python scripts/compliance_workflow.py run --input examples/compliance/scenario.json --output artifacts/compliance-demo --as-of 2026-10-10
python scripts/compliance_workflow.py verify --output artifacts/compliance-demo --as-of 2026-10-10
python -m unittest discover -s tests -v
```

These single-line commands also work in PowerShell. On Windows, use `py` instead of `python` if that is your installed launcher. Use a fresh output directory for every run; existing evidence is never overwritten.

The date pins the policy evaluation for a reproducible scenario. Omitting it on `run` uses today's local date. The fixture intentionally includes an open patch finding and a temporary exception. A later evaluation can fail:

```bash
python scripts/compliance_workflow.py verify --output artifacts/compliance-demo --as-of 2026-11-01
```

Expected: exit code 1 with an overdue unresolved finding and an expired exception. A failed policy gate still retains evidence for follow-up. `verify` without a date uses the original manifest evaluation date, not today's date.

## What actually happens

1. Validate the input before making local changes. Require a recorded approval from a separate reviewer, approval before execution, a rollback procedure and a linked incident.
2. Create a local configuration containing the deliberately wrong upstream port. Restore the declared port and verify the resulting file. This does not run Nginx, prove HTTP availability or contact Application Gateway.
3. Review two synthetic grants with recorded manager decisions and business justification. Retain the support user's grant and remove the former contractor's grant from the output grant inventory. This does not revoke access in Entra ID or Azure.
4. Export a patch and vulnerability register containing a closed drift finding, an open illustrative patch finding and an approved temporary exception. No scanner is run; these are supplied findings, not real CVEs.
5. Generate linked change and incident records, a review report, revocation records and an event log. Generate a SHA-256 manifest over the evidence files.
6. Validate evidence presence, hashes, change and incident linkage, approval sequencing and recovery status. Report overdue open findings and expired exceptions with a failing exit code.

## Evidence files

| File | Review purpose |
| --- | --- |
| `change.json` | Reason, risk, requester, approver, scenario timestamps, rollback and local recovery result |
| `incident.json` | Root cause, impact, mitigation, preventive action, owner and associated change |
| `config-before.txt`, `config-after.txt` | Concrete local configuration before and after repair |
| `access-review.csv` | Users, roles, manager decisions and business justification |
| `revocations.csv`, `access-after.json` | Approved removals and remaining local access grants |
| `vulnerability-register.csv` | Findings, severity, owner, due date, remediation, verification and exceptions |
| `events.jsonl` | Local configuration repair and synthetic access removal events |
| `summary.md` | Completed checks, tracked findings and outstanding policy issues |
| `manifest.json` | Evidence inventory, hashes, identifiers, actual generation time and evaluation date |

Input approval identities and scenario times are synthetic assertions. The script checks their consistency; it does not authenticate approvers. The manifest detects accidental changes when the manifest is trusted. It is not a digital signature, immutable audit log or proof against an attacker who can rewrite the bundle and manifest.

## Review and change procedure

For a real environment, use an authenticated change-management system and an independently approved change before invoking the existing Ansible playbooks. The local example is not authorization to run them against a live environment.

1. Record the affected asset, change reason, incident reference, risk and intended result.
2. Retain a reviewed known-good configuration, document rollback triggers and identify the person responsible for recovery.
3. Obtain the appropriate approval and confirm the change window.
4. Capture the initial configuration or certificate state without secrets.
5. Execute the approved remediation. Keep credentials and private keys out of evidence and console output.
6. Verify health and the served certificate for live changes. Attach actual outputs and timestamps; local file comparison is insufficient for live recovery.
7. Record the outcome, remaining findings, assigned owners and due dates. Link verification evidence before closing an incident.

The local rollback demonstration consists of restoring `config-before.txt`; that recreates the original faulty scenario. A live rollback must restore a separately reviewed known-good configuration, not blindly reintroduce the broken one. Test the live rollback procedure before relying on it.

## Access review procedure

Prepare an inventory with user, role, manager and justification. Obtain a recorded retain or revoke decision from the manager. Apply revocations to the correct system, independently verify removal and retain evidence. Escalate missing decisions rather than treating silence as approval. The script applies these decisions only to a synthetic inventory.

## UAT acceptance cases

| Case | Expected result | Automated coverage |
| --- | --- | --- |
| Approved local drift repair and valid manager decisions | Restored config, one retained grant and one removal record | `test_repair_and_revoke_are_verified` |
| Missing, self or late change approval | Reject before producing a bundle | Approval tests |
| Wrong manager, missing justification or duplicate grant | Reject input | Access-review tests |
| Closed finding without verification | Reject input | Closed-finding test |
| Overdue unresolved finding or exception expiring today | Preserve bundle and fail the gate | Finding and exception tests |
| Modified or deleted evidence file | Fail verification | Tamper and deletion tests |
| Missing manifest entry or unsafe path | Fail verification | Manifest and path tests |
| Reuse an evidence directory | Reject to preserve original evidence | Overwrite test |

CI runs these tests, generates the demonstration and uploads its evidence as an artifact. CI validation does not enforce production deployment approvals or branch protection.

## Resume wording after successful execution

- Built a Python compliance demonstration for synthetic access reviews, approved local configuration remediation and patch/vulnerability tracking.
- Generated linked incident and change records, access revocation evidence and SHA-256 evidence manifests, with checks for missing or modified evidence, overdue findings and expired exceptions.
- Added automated acceptance tests and GitHub Actions evidence generation for the demonstration.

Keep this work in the project section. Do not describe it as professional audit experience, live directory access administration, automated vulnerability scanning or NERC CIP implementation.
