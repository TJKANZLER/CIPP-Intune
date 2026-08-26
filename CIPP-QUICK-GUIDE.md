# Simple CIPP Intune guide

This is the day-to-day guide for deploying and maintaining the Intune policies
in this repository through CIPP. It assumes you can sign in to CIPP and have
permission to manage Standards and Intune templates.

Use [DEPLOYMENT.md](DEPLOYMENT.md) only when you need the deeper technical,
rollback or automation detail.

## The four things to understand

```text
Browse Catalog -> Saved Intune Template -> CIPP Standard -> Live Intune Policy
```

1. **Browse Catalog** shows policies available from this repository.
2. **Saved Intune Template** is the copy imported into CIPP.
3. **CIPP Standard** selects the saved template, customer and assignment group.
4. **Live Intune Policy** is created or updated when the Standard runs.

Importing from Browse Catalog does not deploy anything. Running the Standard is
the step that changes the customer's Intune tenant.

## Rules to follow every time

- Start with one small pilot group.
- Never use All users or All devices for a first run.
- Keep **Do not run on schedule** enabled during the pilot.
- Deploy configuration before compliance.
- Do not run the compliance Standard until a real pilot device is working.
- Enable **Verify assignments** so CIPP checks the intended group.
- Check Conditional Access before deploying compliance.
- Never place passwords, Wi-Fi keys, Apple tokens or enrollment tokens in CIPP
  notes or this repository.

## Import or update a policy

1. Open **CIPP > Tools > Community Repositories**.
2. Open the `CIPP-Intune` repository.
3. Select **Browse Catalog**.
4. Find the required policy by filename, for example:
   `33-ios-supervised-device-restrictions`.
5. Select **Import**.
6. Confirm it now shows as imported.

That is all the importing required. Do not import it a second time from Template
Library.

When an existing policy is updated in the repository, repeat these steps once.
This refreshes CIPP's saved copy. It does not update the live customer policy
until its Standard is run.

## Create a configuration Standard

1. Open **CIPP > Standards & Drift**.
2. Select **Add Standards Template**.
3. Name it clearly, for example:
   `Customer - iOS Pilot - Configuration`.
4. Select only the intended customer tenant.
5. Enable **Do not run on schedule**.
6. Select **Add Standard to Template**.
7. Search for and add **Intune Template**.
8. Expand the new Intune Template card.
9. Use the refresh button beside **Select Intune Template** if the list is empty
   or out of date.
10. Select the saved policy by its full display name.
11. Select **Report** and **Remediate**.
12. Set Assignment to **Custom Group**.
13. Select the customer's pilot group.
14. Enable **Verify assignments**.
15. Add another Intune Template card for each policy in the same configuration
    group.
16. Save the Standard.

Do not look for the individual baseline in the **Add Standard** search window.
The item in that window is called **Intune Template**; the baseline is selected
inside the card.

## Create a compliance Standard

Repeat the configuration steps, but:

- name it `Customer - Platform Pilot - Compliance`;
- add only that platform's compliance policy;
- keep **Do not run on schedule** enabled;
- save it without selecting **Run Now**.

Compliance is deliberately separate so it cannot mark an unconfigured device as
noncompliant or combine unexpectedly with Conditional Access.

## What to put in each Standard

### Windows

| Standard | Policies | What they do |
|---|---|---|
| Windows Wave 1 | Defender Antivirus; Firewall; ASR Audit | Turns on core protection and records risky application behaviour without ASR blocking. |
| Windows Wave 2 | BitLocker; Windows Hello; Security Hardening; Credential Guard; LAPS | Encrypts devices, protects sign-in and credentials, hardens Windows and manages the local admin password. |
| Windows Compliance | Windows Compliance | Checks whether Defender, firewall, TPM, encryption and boot security are healthy. |
| Windows ASR Enforcement | ASR Enforced | Blocks or warns on the risky behaviours previously observed by ASR Audit. |

Run ASR Audit for at least two weeks. Remove its assignment before assigning ASR
Enforced because the two policies control the same settings.

### Android Enterprise fully managed

| Standard | Policies | What they do |
|---|---|---|
| Android Configuration | Device Restrictions; Launcher and Branding; Microsoft Edge | Locks down the corporate phone, applies the managed home screen/wallpaper and configures the managed Edge browser. |
| Android Compliance | Android Fully Managed Compliance | Checks PIN, encryption, device integrity, operating-system version and security patch. |

Before configuration, Microsoft Launcher and Edge must be approved in Managed
Google Play and assigned as Required. This bundle is for corporate-owned,
single-user fully managed devices, not personal phones or shared kiosks.

### iPhone and iPad

| Standard | Policies | What they do |
|---|---|---|
| iOS Configuration | Supervised Device Restrictions; Managed Software Updates | Blocks personal Apple/iCloud use and risky data transfer while keeping approved business features; forces supported Apple updates after seven days. |
| iOS Compliance | iOS/iPadOS Compliance | Checks the six-digit passcode, jailbreak state and customer's minimum iOS version. |

Apple APNs, Automated Device Enrollment and Apps and Books must be working before
enrolling a real device. The pilot group contains corporate device objects, not
users. Do not run compliance until the supervised pilot device is enrolled,
updated and working.

### macOS

| Standard | Policies | What they do |
|---|---|---|
| macOS Configuration | FileVault; Gatekeeper and Firewall | Encrypts the Mac, stores its recovery key in Intune, enables the firewall and restricts untrusted applications. |
| macOS Compliance | macOS Compliance | Checks FileVault, firewall, System Integrity Protection, Gatekeeper and supported macOS version. |

Confirm the FileVault recovery key is visible in Intune before expanding beyond
the pilot.

## What every individual policy does

| File | Plain-English purpose |
|---|---|
| `01-compliance-windows.json` | Checks Windows security and encryption health. |
| `02-compliance-android-fully-managed.json` | Checks Android PIN, encryption, device integrity and supported versions. |
| `03-compliance-ios.json` | Checks iOS passcode, jailbreak state and minimum version. |
| `04-compliance-macos.json` | Checks Mac encryption, firewall, SIP, Gatekeeper and minimum version. |
| `10-win-sc-defender-antivirus.json` | Configures Microsoft Defender Antivirus. |
| `11-win-sc-asr-rules-audit.json` | Records ASR events without blocking them. |
| `12-win-sc-asr-rules-enforced.json` | Enforces the reviewed ASR rules. |
| `13-win-sc-firewall.json` | Enables and configures all Windows Firewall profiles. |
| `14-win-sc-bitlocker.json` | Encrypts the Windows drive and stores its recovery key in Entra. |
| `15-win-sc-windows-hello.json` | Configures Windows Hello PIN and biometrics. |
| `16-win-sc-security-hardening.json` | Applies the wider Windows operating-system security baseline. |
| `17-win-sc-credential-guard.json` | Protects credentials using VBS, Credential Guard and HVCI. |
| `18-win-sc-laps.json` | Creates and rotates managed local administrator passwords. |
| `20-macos-sc-filevault.json` | Enables FileVault and recovery-key storage. |
| `21-macos-sc-gatekeeper-firewall.json` | Enables Mac firewall, Gatekeeper and XProtect reporting. |
| `30-android-device-restrictions.json` | Blocks unsafe Android device features and requires the corporate PIN. |
| `31-android-launcher-branding.json` | Applies Microsoft Launcher layout and corporate wallpaper. |
| `32-android-edge-browser.json` | Configures the managed Android Edge browser. |
| `33-ios-supervised-device-restrictions.json` | Applies corporate supervised-device restrictions to iPhone/iPad. |
| `34-ios-managed-software-updates.json` | Enforces the latest supported Apple update after seven days. |

## Run the configuration pilot

Before running, open the Standard and check:

- the correct customer is selected;
- **Do not run on schedule** is enabled;
- every template is the intended configuration policy;
- Assignment is the pilot group only;
- **Verify assignments** is enabled;
- the compliance policy is not included.

Then:

1. Select **Run Now**.
2. Wait for the CIPP task to finish.
3. Review the Report and Remediate results.
4. Open the customer's Intune tenant and confirm the live policies target only
   the pilot group.
5. Sync the pilot device.
6. Wait for each configuration policy to report success.
7. Test encryption/recovery, sign-in, applications, networking, updates and the
   customer's normal work on the actual device.
8. Record the result and any accepted exceptions in the change ticket.

Do not treat a successful CIPP job as proof that the device works. The real pilot
device must be tested.

## Run compliance later

After configuration is healthy:

1. Confirm the customer's supported minimum OS/build is correct.
2. Confirm compliance notifications and grace period are correct.
3. Check whether Conditional Access requires a compliant device.
4. Confirm emergency-access accounts and enrollment are not accidentally blocked.
5. Open the separate compliance Standard.
6. Confirm the pilot group is the only assignment.
7. Select **Run Now**.
8. Sync the pilot and confirm it becomes compliant in both Intune and Entra.
9. Observe the full grace period before introducing access enforcement.

Any compliant-device Conditional Access policy should begin in report-only.

## Expand to production

1. Obtain approval from the pilot results.
2. Add one controlled production group or wave at a time.
3. Run the Standard manually.
4. Check device results and support impact.
5. Repeat until the approved estate is covered.
6. Enable the CIPP schedule only after repeated manual runs are safe.

The schedule lets CIPP detect and remediate later drift. Community Repository
refresh alone does not update live tenant policies.

## If something goes wrong

1. Disable the Standard's schedule.
2. Do not run it again.
3. Identify the exact policy and affected pilot group in Intune.
4. Remove or correct only that assignment/policy using the approved change plan.
5. Sync and retest the pilot.
6. Record the cause, rollback and any customer exception.

Important checks:

- BitLocker/FileVault: confirm the recovery key is retrievable.
- ASR: confirm Audit and Enforced are not both assigned.
- Compliance: check Conditional Access as well as Intune.
- iOS: do not remove a device from Apple Business Manager to fix enrollment.
- Empty template picker: use the refresh button inside the Intune Template card.
- Policy missing from Add Standard: add **Intune Template** first, then select the
  policy inside it.
- Updated catalog but old live policy: re-import once, verify the saved copy, then
  run the existing pilot Standard manually.

When unsure, stop before **Run Now** and ask another technician to review the
tenant, template, group and expected user impact.
