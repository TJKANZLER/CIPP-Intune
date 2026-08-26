# CIPP Intune policy guide

This guide explains what each reusable policy does, where it belongs in the
rollout, its likely user impact and the evidence required before expanding beyond
a pilot. The JSON files remain the technical source of truth; this document is
the technician-readable operational summary.

For the exact deployment procedure, see [DEPLOYMENT.md](DEPLOYMENT.md). Rollout
wave numbers match [manifest.cipp](manifest.cipp).

## Windows

| File | Wave | What it does | Pilot evidence and cautions |
|---|---:|---|---|
| `10-win-sc-defender-antivirus.json` | 1 | Enables Defender real-time and behaviour monitoring, cloud protection, PUA and network protection, scheduled scanning and defined remediation actions. | Confirm Defender is the intended active antivirus, signatures update and line-of-business software is not falsely detected. |
| `13-win-sc-firewall.json` | 1 | Enables Domain, Private and Public firewalls, blocks unsolicited inbound traffic, enables stealth mode and logs dropped packets. | Test remote support, discovery, printing and server applications. Add narrow rules rather than disabling a profile. |
| `11-win-sc-asr-rules-audit.json` | 1 | Places all 18 Attack Surface Reduction rules in audit mode to collect evidence without blocking. | Run for at least two weeks and review Defender reports. This is the day-one ASR policy. |
| `14-win-sc-bitlocker.json` | 2 | Silently encrypts the operating-system drive with XTS-AES 256 and requires Entra recovery-key backup before encryption starts. | Prove the key is retrievable in Entra before expansion. Check silent-encryption prerequisites and recovery roles. |
| `15-win-sc-windows-hello.json` | 2 | Enables Windows Hello for Business with TPM-backed PIN and biometric options. | Test provisioning, PIN reset, shared-device suitability and existing authentication workflows. |
| `16-win-sc-security-hardening.json` | 2 | Applies 96 OS controls covering legacy protocols/ciphers, LSA protection, PowerShell logging and other security baselines. | Test legacy NAS, scanners and applications. Minimum SMB dialect 3.0 and provisioning-package restrictions are known compatibility risks. |
| `17-win-sc-credential-guard.json` | 2 | Enables VBS, Credential Guard, HVCI and LSA protection using remotely reversible values without UEFI lock. | Use VBS-capable hardware and test old kernel drivers, VPN, security and printing software. |
| `18-win-sc-laps.json` | 2 | Stores Windows LAPS passwords in Entra, rotates every seven days, uses 21-character passwords and resets/logs off after password use. | Confirm the managed local administrator exists, password escrow works and only approved support roles can retrieve it. |
| `01-compliance-windows.json` | 3 | Evaluates Defender, antivirus/antispyware, firewall, TPM, BitLocker, Secure Boot and code integrity. Hardware-dependent VBS/HVCI/DMA gates remain off by default. | Deploy after configuration is healthy. Set supported build ranges and review Conditional Access before assignment. |
| `12-win-sc-asr-rules-enforced.json` | 4 | Enforces the reviewed ASR posture: 13 rules block, three warn and two remain audit. | Unassign the audit policy first. Apply exclusions learned during the two-week audit and retain rollback evidence. |

## Android Enterprise fully managed

These policies are for corporate-owned, single-user fully managed devices. They
are not a BYOD/MAM baseline and are not suitable for shared/dedicated kiosk devices
without redesign.

| File | Wave | What it does | Pilot evidence and cautions |
|---|---:|---|---|
| `30-android-device-restrictions.json` | 2 | Requires a six-digit complex PIN; blocks sideloading, developer options, USB transfer, external media, personal Google accounts and screenshots; enables Play Protect and automatic application/system updates. | Test required peripherals, camera/scan workflows, mobile-data use, recovery and factory-reset protection. Supply the controlled FRP account variable. |
| `31-android-launcher-branding.json` | 2 | Makes Microsoft Launcher the managed single-user home experience, sets and locks tenant wallpaper, removes the personalised feed and controls dock/search placement. | Require Microsoft Launcher first. Confirm the wallpaper URL is reachable and test the chosen phone/tablet orientation. Use Managed Home Screen for kiosk devices instead. |
| `IntuneTemplate/32-android-edge-browser.json` | 2 | Applies managed Edge settings: focused locked new-tab layout, reduced first-run/personalisation, HTTPS, SmartScreen/PUA protection and authenticated password autofill; requests Edge as default. | Require the correct Managed Google Play Edge object and set `androidedgeappid`. Android may still need one user confirmation for the default browser. Test business sites and autofill. |
| `02-compliance-android-fully-managed.json` | 3 | Checks complex PIN, encryption, hardware-backed device integrity, Intune app integrity, minimum OS and security-patch floors. Pending OEM/carrier updates do not immediately fail compliance. | Set all tenant variables and notification template. Confirm actual supported OEM patch behavior before enabling access enforcement. |

## iOS/iPadOS corporate supervised

These policies assume corporate ownership, Apple Business Manager Automated
Device Enrollment, supervision, user affinity and Setup Assistant with modern
authentication. Personal Apple devices remain a separate BYOD/MAM service.

| File | Wave | What it does | Pilot evidence and cautions |
|---|---:|---|---|
| `33-ios-supervised-device-restrictions.json` | 2 | Enforces a six-digit passcode and managed-data boundary. Blocks personal Apple Accounts/iCloud, user Activation Lock, AirDrop, normal computer and Apple Watch pairing, USB Files, user App Store installation, unmanaged VPN, gaming, renaming and wallpaper changes. It allows screenshots, camera, Messages, FaceTime, Bluetooth, other Wi-Fi, Personal Hotspot, roaming, local erase, Apple media services and removal of optional apps. | Confirm supervision and pilot-only assignment. Test Outlook contact export, managed/unmanaged data flow, recovery-mode restore, app delivery, communication, tethering and support workflows on real hardware. |
| `34-ios-managed-software-updates.json` | 2 | Uses Apple Declarative Device Management to install the latest version supported by the device after seven days, at 03:00 local time. | Requires iOS/iPadOS 17+. Verify the device's actual OS version; a successful policy status does not prove installation. Test every supported model. |
| `03-compliance-ios.json` | 3 | Checks six-digit passcode, jailbreak status and tenant-defined minimum OS. It uses tenant-defined user notification and a seven-day block schedule. | Set `iosminimumosversion` and the notification-template ID. Deploy only after the configuration pilot and Apple application compatibility are healthy. |

Apple prerequisites outside these templates include APNs, ADE, Apps and Books,
Company Portal device licensing, app acquisition, enrollment-profile assignment,
Wi-Fi and any private wallpaper payload. The bootstrap and audit cover these
tenant-specific objects without storing their secrets here.

## macOS

| File | Wave | What it does | Pilot evidence and cautions |
|---|---:|---|---|
| `20-macos-sc-filevault.json` | 2 | Enables FileVault and escrows the personal recovery key to Intune. | Prove the key is visible and retrievable before broad assignment. Test existing encrypted devices and institutional recovery procedures. |
| `21-macos-sc-gatekeeper-firewall.json` | 2 | Enables the application firewall, Gatekeeper/System Policy Control and XProtect sample submission. | Test signed line-of-business applications, inbound services, remote support and approved security tooling. |
| `04-compliance-macos.json` | 3 | Evaluates FileVault, firewall, System Integrity Protection, Gatekeeper and the tenant's supported macOS floor. | Configure and verify FileVault/Gatekeeper first, then set a supported version and review Conditional Access. |

## What the policies do not provide

The repository is a security baseline, not a complete tenant build. It does not
by itself provide:

- policy assignment or production group design;
- Windows update rings or feature-update deployment;
- Defender for Endpoint onboarding/tamper protection;
- Apple or Managed Google Play token setup and application acquisition;
- Autopilot, ADE, Android enrollment token or zero-touch ownership workflows;
- customer Wi-Fi secrets or app inventories;
- macOS update and Defender PPPC/system-extension prerequisites;
- App Protection/MAM for personally owned devices;
- compliant-device Conditional Access.

Those items belong in the tenant bootstrap and customer rollout record. Never
infer their presence merely because these templates imported successfully.

## Normal user-impact expectations

| Change | Expected impact |
|---|---|
| Encryption | BitLocker/FileVault may require restart, power and escrow prerequisites; recovery-key failure is a stop condition. |
| Passcodes and Windows Hello | Users may be prompted to create or strengthen a PIN/passcode and reauthenticate. |
| Firewall and OS hardening | Legacy discovery, SMB, scanners, drivers and line-of-business applications may fail until reviewed exceptions exist. |
| Android restrictions | Screenshots, personal accounts, sideloading, USB data and developer functions are unavailable. |
| iOS restrictions | Personal Apple/iCloud services, AirDrop, ordinary computer pairing, App Store installation and device personalisation are unavailable; approved managed apps still deploy. |
| Compliance | A device can become noncompliant before access is blocked; Conditional Access determines the final user-access effect. |
| Managed updates | Supported Apple devices are forced to the latest supported release after the configured deadline. |
| ASR enforcement | Office/script/executable behaviors can be blocked; audit evidence and exclusions are required first. |

## Verification standard

A policy is not proven merely because JSON validates, CIPP imports it or Graph
returns success. Before production expansion, verify all four layers:

1. repository source and current validation;
2. unique saved CIPP template and resolved tenant variables;
3. exact live policy type, payload and pilot-only assignment;
4. actual pilot-device behavior and business workflow.

Record failures as one of: policy defect, unsupported setting/device, assignment
error, prerequisite missing, accepted exception or tenant-specific conflict. Do
not hide an unexplained result by widening the assignment or disabling a broader
security control.
