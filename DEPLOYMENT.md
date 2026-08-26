# CIPP Intune deployment and support runbook

This runbook is the operational entry point for deploying the templates in this
repository. It is written for Shoothill technicians who understand Microsoft
Intune but may not have followed the design conversations that produced the
baseline.

Importing a template only saves policy content in CIPP. It does **not** create a
live Intune policy or assign anything. A CIPP Standards run creates or updates
the live policy and applies the configured assignment.

## Safety rules

- Use a static pilot group before any production group.
- Keep configuration and compliance in separate CIPP Standards templates.
- Keep the Standards schedule disabled during the pilot and use **Run Now** only
  after reviewing the saved template and assignment.
- Enable configuration first. Deploy compliance only after configuration is
  successful on real hardware.
- Review Conditional Access before compliance. A compliant-device requirement
  can turn a policy problem into a user lockout.
- Never target All users or All devices during the pilot.
- Never put Wi-Fi keys, Apple token files, certificates, private keys, Temporary
  Access Passes, enrollment tokens or customer secrets in this repository.
- Do not force-push or replace a same-named live policy whose purpose and
  assignments have not been established.

## 1. Validate the source

From the repository root:

```bash
python3 validate.py --refresh
pwsh ./Import-CippIntuneTemplates.ps1
git status --short
```

The validator must finish with `All policies valid.` and report 20 manifest
entries with no orphans. The PowerShell command is a dry run; it shows what CIPP
would receive without creating templates. Investigate every validation or Graph
error rather than retrying with speculative payload changes.

## 2. Add or refresh the CIPP community repository

1. Open **CIPP > Tools > Community Repositories**.
2. Add or refresh the approved repository containing this project.
3. Open the Intune policy catalog and select **Browse Catalog**.
4. Import only the required files for the platform and wave listed in
   [POLICY-GUIDE.md](POLICY-GUIDE.md).
5. A catalog entry is normally shown by filename, such as
   `33-ios-supervised-device-restrictions`. After import, CIPP shows the saved
   template by its display name, such as
   `Baseline - iOS/iPadOS (Supervised) - Device Restrictions`.

Do not import the same item again from Template Library after importing it from
Browse Catalog. These are two views of the same saved CIPP template, not two
required deployment stages. If a template has changed upstream, re-import it
once from Browse Catalog and confirm there is exactly one saved copy.

The command-line alternative is:

```powershell
# Dry run
./Import-CippIntuneTemplates.ps1

# Create missing saved templates
./Import-CippIntuneTemplates.ps1 -Execute

# Import selected files only
./Import-CippIntuneTemplates.ps1 -Execute -Only @(
  '33-ios-supervised-device-restrictions.json',
  '34-ios-managed-software-updates.json'
)
```

The bulk importer intentionally refuses ambiguous duplicates. Use
`-ExistingAction Skip` only to resume a reviewed partial import.

## 3. Set tenant prerequisites and variables

Create the tenant-scoped CIPP variables before adding a dependent template to a
Standard. Values must come from the customer's supported estate and live Intune
objects; do not guess them.

| Platform | Required variables |
|---|---|
| Android | `androidminimumosversion`, `androidminimumsecuritypatchlevel`, `androidcompliancenotificationtemplateid`, `androidfrprecoveryaccount`, `androidwallpaperurl`, `androidedgeappid` |
| iOS/iPadOS | `iosminimumosversion`, `ioscompliancenotificationtemplateid` |

Windows and macOS version floors are tenant decisions described in the policy
guide. Android also requires Managed Google Play, Microsoft Launcher and Edge as
app prerequisites. Apple requires healthy APNs, Automated Device Enrollment and
Apps and Books connections before a real ADE enrollment can succeed.

Use the read-only bootstrap plan before applying tenant-specific mobile objects:

```powershell
./automation/Invoke-AndroidFullyManagedTenant.ps1 -ConfigPath /secure/path/android.json
./automation/Invoke-IosCorporateTenant.ps1 -ConfigPath /secure/path/ios.json
```

Keep populated tenant configuration files outside this repository. See
[automation/README.md](automation/README.md) for the supported `-Apply` workflow.

## 4. Create CIPP Standards templates

Create one manual Standard for configuration and a separate one for compliance.
A separate configuration Standard per platform makes the assignment and rollback
boundary easy to understand.

For each configuration policy:

1. Open **CIPP > Standards & Drift > Add Standards Template**.
2. Give it a clear tenant and platform name, for example
   `Customer - iOS Pilot - Configuration`.
3. Select only the intended tenant.
4. Enable **Do not run on schedule**.
5. Select **Add Standard to Template** and add **Intune Template**.
6. Expand the Intune Template card. Use its refresh button if the saved-template
   list is stale.
7. Choose the saved template by display name. Do not search for the policy name
   in the Add Standard catalog; the catalog item is named **Intune Template**.
8. Select **Report** and **Remediate**.
9. Set Assignment to **Custom Group** and select the static pilot group.
10. Enable **Verify assignments**.
11. Add another Intune Template card for each policy in the same configuration
    wave, then save.

Create the compliance Standard in the same way, but include only the platform's
compliance policy. Leave it manual and do not run it yet.

Recommended mobile split:

| Standard | Saved templates |
|---|---|
| Android Configuration | Device Restrictions; Launcher and Branding; Microsoft Edge |
| Android Compliance | Android Enterprise Fully Managed Compliance only |
| iOS Configuration | Supervised Device Restrictions; Managed Software Updates |
| iOS Compliance | iOS/iPadOS Compliance only |

For Windows, keep wave 1 observation/telemetry separate from wave 2 hardening,
wave 3 compliance and wave 4 ASR enforcement. For macOS, deploy FileVault and
Gatekeeper/firewall before compliance.

## 5. Pre-run review

Before clicking **Run Now**, capture the change reference and verify:

- the correct customer tenant is the only tenant selected;
- the correct saved template is shown and is the latest imported copy;
- the assignment is exactly the pilot group, with no exclusion or broad target;
- **Verify assignments** is enabled;
- **Do not run on schedule** remains enabled;
- required tenant variables resolve to real values;
- no same-named live policy has an unexplained purpose or assignment;
- compliance and compliant-device Conditional Access are still outside the
  configuration wave;
- a rollback/export of the affected current configuration exists where needed.

For iOS, run the deep audit at every gate:

```powershell
./automation/Test-IosCorporateTenant.ps1 -ConfigPath /secure/path/ios.json
```

## 6. Run and verify configuration

1. Click **Run Now** on the configuration Standard only.
2. Wait for the CIPP job to complete and review its report/remediation result.
3. In Intune, confirm the exact live policy type, values and assignment. A green
   creation response alone is not proof that the intended settings applied.
4. Sync a real pilot device and wait for its policy status.
5. Test the platform-specific items in [POLICY-GUIDE.md](POLICY-GUIDE.md).
6. Record policy IDs, device ID/serial, result, conflicts, exceptions and test
   evidence in the customer's change or rollout record.

Do not proceed when a setting reports conflict, error or not applicable without
understanding why. Verify security-critical outcomes directly: recovery-key
escrow, actual OS version, firewall state, managed app identity, supervision and
enrollment method.

## 7. Introduce compliance

Only run the compliance Standard after the pilot device is configured, updated,
checking in and usable.

1. Confirm the minimum OS/build and notification-template variables.
2. Review the noncompliance actions and grace period.
3. Review Conditional Access, emergency access and enrollment exclusions.
4. Click **Run Now** on the compliance Standard.
5. Confirm it is assigned only to the pilot group.
6. Observe the complete grace period and confirm Intune and Entra agree on device
   compliance before testing access controls.
7. Introduce any compliant-device Conditional Access policy in report-only first.

## 8. Expand and enable drift control

Expand one controlled group at a time. Record approval, affected devices and a
backout window. Enable a CIPP schedule only after the manual pilot and production
wave have shown that automatic remediation is safe.

When a community template changes:

1. review the repository diff and validate it;
2. refresh the community catalog;
3. re-import the changed saved template once;
4. read back the saved template and check for duplicates;
5. review the existing Standard and assignment;
6. run manually against the pilot;
7. verify the live payload and device behavior;
8. then allow the normal schedule to resume.

Community sync updates CIPP's catalog/saved content. It does not, by itself,
remediate the tenant. The Standards run owns the live policy lifecycle.

## 9. Rollback

CIPP Standards are desired-state enforcement, not transactional deployments.
Disabling a schedule does not undo settings already applied.

If a policy causes an incident:

1. disable its Standards schedule and prevent another run;
2. remove the affected group assignment or exclude the impacted pilot only after
   identifying the exact live policy;
3. restore the recorded prior value or deploy a reviewed replacement policy;
4. sync and verify the affected device/workload;
5. document the exception, owner and review date;
6. correct the central template only if the change applies to every tenant using
   it.

Special cases:

- Never deploy ASR audit and ASR enforced together; unassign audit when moving to
  enforcement.
- Confirm BitLocker/FileVault keys are retrievable before changing encryption
  assignments.
- A device losing compliance can be blocked by Conditional Access even after a
  configuration policy is removed; check both control planes.
- Do not release an Apple device from ABM as a troubleshooting shortcut.

## 10. Support evidence

For every rollout, retain:

- customer, tenant ID, change reference and approving technician;
- repository commit and saved CIPP template ID;
- Standard name/ID, schedule state and exact assignment group;
- live Intune policy ID and concrete Graph type;
- pilot device serial/ID, check-in, result and actual tested state;
- accepted exceptions, owner and review date;
- rollback/export location;
- Apple/Google token renewal ownership where applicable.

Customer-specific identifiers and secrets belong in the approved customer system,
not in this reusable repository.
