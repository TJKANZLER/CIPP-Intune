# CIPP Intune Security Baseline — Generic Template Set

Generic, security-focused Intune policy set for import into CIPP as reusable **Intune Templates**. This is the base — clone it into a client-specific version (Lloyds first) once reviewed.

20 policies across Windows, Android Enterprise, iOS/iPadOS and macOS. Every policy is validated before it ships (`python3 validate.py`) and can be bulk-imported in one command.

---

## Quick start

```bash
python3 validate.py --refresh                # validate all 18 against current Graph/CIPP data
pwsh ./Import-CippIntuneTemplates.ps1        # dry run — shows what would be created
pwsh ./Import-CippIntuneTemplates.ps1 -Execute   # actually create the templates in CIPP
```

The import script reuses the CIPP app registration already set up for the CIPP MCP bridge (`~/.local/share/cipp-mcp/config.json`). It creates templates only — **nothing is assigned to any device**. Assignment stays a deliberate separate step; see [Rollout order](#rollout-order).

---

## What's included

### Compliance policies — hand-authored against the Graph beta schema

| File | Platform | Notes |
|---|---|---|
| `01-compliance-windows.json` | Windows 10/11 | Defender + firewall + TPM + BitLocker/Secure Boot attestation |
| `02-compliance-android-fully-managed.json` | Android Enterprise COBO (single-user fully managed) | Hardware-backed device integrity, encryption, Intune app integrity; pending updates do not directly fail compliance |
| `03-compliance-ios.json` | iOS/iPadOS | Passcode, jailbreak detection |
| `04-compliance-macos.json` | macOS | FileVault, firewall, SIP, Gatekeeper |

### Windows Settings Catalog — derived from OpenIntuneBaseline

| File | Covers | Settings |
|---|---|---|
| `10-win-sc-defender-antivirus.json` | Defender AV: real-time/behaviour monitoring, cloud protection, PUA, network protection, scan schedule, remediation actions | 31 |
| `11-win-sc-asr-rules-audit.json` | All 18 ASR rules in **audit** mode | 20 |
| `12-win-sc-asr-rules-enforced.json` | ASR rules **enforcing** (13 block / 3 warn / 2 audit) | 20 |
| `13-win-sc-firewall.json` | Firewall on all 3 profiles, inbound blocked, stealth mode, dropped-packet logging | 31 |
| `14-win-sc-bitlocker.json` | Silent OS-disk encryption, recovery key to Entra ID | 25 |
| `15-win-sc-windows-hello.json` | Windows Hello for Business PIN/biometrics, TPM required | 7 |
| `16-win-sc-security-hardening.json` | Legacy protocol/cipher restrictions, LSA protection, PowerShell logging | 96 |
| `17-win-sc-credential-guard.json` | Credential Guard, HVCI, VBS | 8 |
| `18-win-sc-laps.json` | Windows LAPS: Entra escrow, seven-day rotation, post-use reset/logoff | 6 |

### macOS Settings Catalog — derived from OpenIntuneBaseline

| File | Covers | Settings |
|---|---|---|
| `20-macos-sc-filevault.json` | FileVault with recovery key escrow to Intune | 8 |
| `21-macos-sc-gatekeeper-firewall.json` | Application firewall + Gatekeeper / System Policy Control + XProtect sample submission | 8 |

### Android Enterprise fully managed bundle — hand-authored

| File | Covers |
|---|---|
| `30-android-device-restrictions.json` | Blocks sideloading, developer options, USB file transfer, external media, personal Google accounts and screen capture; disables the kiosk-only network escape hatch; enables automatic app/system updates; enforces Play Protect and lockout-to-wipe |
| `31-android-launcher-branding.json` | Makes Microsoft Launcher the managed home experience for single-user fully managed devices; applies and locks a tenant-specific wallpaper; disables the personalised feed and locks dock/search placement |
| `IntuneTemplate/32-android-edge-browser.json` | Requests Edge as the default browser; locks a focused new-tab page; removes first-run, Copilot, My Apps and personalisation prompts; enables HTTPS, SmartScreen/PUA protection and authenticated password autofill |

The Android bundle consists of `30` (security and device behaviour), `31` (single-user launcher and branding), `32` (managed Edge browser), and `02` (compliance, assigned only after configuration is healthy). Keeping them separate means browser and branding choices can change without reopening the security policy, while compliance remains gated behind the pilot. App installation and policy assignment remain separate actions.

Before deploying the Android bundle, define the required tenant-scoped CIPP variables: `androidminimumosversion`, `androidminimumsecuritypatchlevel`, `androidcompliancenotificationtemplateid`, `androidfrprecoveryaccount`, `androidwallpaperurl` and `androidedgeappid`. This keeps the full deployed policies under CIPP Standards control without putting customer values in GitHub or relying on a post-deployment overlay. The notification variable must identify an existing Intune compliance notification template, and the FRP variable must be a tested corporate Google account.

Before deploying `31`, add Microsoft Launcher through Managed Google Play and assign it as **Required** to the same pilot group. Set `androidwallpaperurl` to a direct, publicly reachable HTTPS image URL. CIPP replaces `%androidwallpaperurl%` at deployment, so the template remains portable and the Lloyds URL does not need to be hard-coded in GitHub. Use at least 1080×1920 for phones or 1920×1080 for landscape tablets. Shared/dedicated kiosk devices must use Managed Home Screen instead of this Launcher policy.

Before deploying `32`, approve and sync Microsoft Edge from Managed Google Play and assign it as **Required** to the same pilot group. Create a tenant-scoped CIPP custom variable named `androidedgeappid` containing that tenant's Intune mobile-app object ID for Microsoft Edge. The stable package ID is included in the policy, while the variable supplies the tenant-specific association required by Graph. Android may still show a one-time browser chooser; select **Edge → Always**. The baseline deliberately keeps Edge password storage enabled because no separate managed password manager is assumed, and requires device PIN/biometric authentication before autofill.

`32` is stored as a CIPP-native `IntuneTemplate` repository entity rather than a raw Graph object. This is deliberate: CIPP supports `AppConfiguration` deployment, but its generic community-repository type inference otherwise classifies an `androidManagedStoreAppConfiguration` as a classic Device policy. The native wrapper preserves the correct type during GitHub catalog import; the bulk-import script unwraps it and sends the identical Graph payload. Intune requires the Android Enterprise `payloadJson` value to contain Base64-encoded managed-configuration JSON; sending the readable JSON directly produces an unhelpful HTTP 500 from the AppLifecycle service. `validate.py` decodes and checks both layers and all embedded Edge settings.

### iOS/iPadOS corporate supervised bundle — hand-authored

| File | Covers |
|---|---|
| `33-ios-supervised-device-restrictions.json` | Microsoft Level 1/2-aligned passcode, managed-data, certificate/profile, USB Files, backup and lock-screen protections for corporate-owned supervised iPhone and iPad devices |
| `34-ios-managed-software-updates.json` | Apple Declarative Device Management enforcement of the latest supported update after seven days, at 03:00 local device time |
| `03-compliance-ios.json` | Six-digit passcode and jailbreak compliance plus tenant-defined minimum OS and notification template |

Define `iosminimumosversion` and `ioscompliancenotificationtemplateid` as tenant-scoped CIPP variables before deploying iOS compliance. Keep `33` and `34` in an `iOS Corporate - Configuration` package and `03` alone in `iOS Corporate - Compliance`. Assign the configuration package to a static pilot first; assign compliance only after the pilot device reports configuration success and has updated.

The corporate core blocks user account and device-name changes, user-controlled Activation Lock, personal iCloud backup, document, application, Keychain, Photos and Private Relay services, AirDrop, user App Store installations, USB Files access, computer and Apple Watch pairing, unmanaged VPN creation, gaming services and wallpaper changes. It forces automatic date and time. Approved Apps and Books applications still deploy through Intune with device licensing. Required app assignments are nonremovable while Available apps remain removable. AirDrop is also treated as an unmanaged destination as defence in depth. It deliberately leaves Messages, FaceTime, Siri while unlocked, keyboard assistance, biometrics, Handoff, secure AirPrint, Apple media services, eSIM/cellular-plan controls, Bluetooth, the camera, screenshots, Personal Hotspot, mobile data and voice roaming, local Erase All Content and Settings, and joining non-managed Wi-Fi networks available. Recovery-mode erase/restore remains the technician recovery path when normal host pairing is unavailable.

Company Portal and all other iOS apps must come from Apple Business Manager Apps and Books with device licensing. For ADE with Setup Assistant modern authentication, select **Install Company Portal with VPP** in the enrollment profile; do not ask users to install Company Portal manually from the public App Store. Apple tokens, app licences, ADE profiles, Wi-Fi secrets and wallpaper image payloads are tenant-specific and are not stored in this repository. The iOS bootstrap can upload a private local wallpaper into an exact-type Device features profile, while validating its format and size and never logging the encoded image.

---

## Rollout order

`manifest.cipp` assigns every policy a wave. Its non-JSON extension deliberately prevents CIPP's Community Repository catalog from treating the rollout manifest as an Intune policy. Configuration must remediate devices before compliance evaluates them. Never assume compliance is report-only: if an existing Conditional Access policy requires a compliant device, a noncompliant result can block access.

**Wave 1 — establish controls and telemetry.** Defender AV, Windows Firewall and **ASR in audit mode**. Start with a representative pilot, check conflicts, then expand.

**Wave 2 — remediate with a pilot group first.** BitLocker, Windows Hello, OS hardening, Credential Guard, Windows LAPS, macOS FileVault/Gatekeeper, Android restrictions, Android Launcher branding, the Edge mobile baseline, supervised iOS restrictions and Apple DDM updates. Each can visibly change behavior or depends on hardware:
- **BitLocker** — confirm the recovery key actually lands in Entra ID on a pilot device. A device that encrypts without a retrievable key is a support incident waiting to happen.
- **Credential Guard / HVCI** — needs VBS-capable hardware and can break old kernel-mode drivers. The baseline uses the remotely reversible **without UEFI lock** values.
- **Windows LAPS** — confirm a local administrator account exists, passwords escrow to Entra ID, and recovery roles are least-privileged.
- **OS hardening** (96 settings) — explicitly test legacy NAS/scanners because the minimum SMB dialect is 3.0. It also blocks adding/removing provisioning packages after policy applies.
- **Android restrictions** — several are user-visible; check them against how the handhelds are actually used.
- **Android Launcher and branding** — single-user fully managed devices only. Assign Microsoft Launcher as Required and define the tenant's `androidwallpaperurl` CIPP variable before deploying the policy.
- **Android Microsoft Edge** — approve and require Edge first, then define `androidedgeappid`. The default-browser policy registers Edge where Android permits it; some devices still require one user confirmation. Test business sites and password autofill on the pilot.
- **iOS/iPadOS supervised restrictions** — use ADE and supervision. Test Outlook contact export, managed/unmanaged data flow, USB Files access, AirDrop, screenshots, personal Apple Account and recovery workflows before changing the documented core decisions.
- **Apple managed updates** — the DDM policy requires iOS/iPadOS 17 or later and enforces the latest device-supported version after seven days. Verify the actual OS version and update reporting on each supported model.

**Wave 3 — compliance after remediation is healthy.** Set supported OS/build and patch floors, verify configuration success, create notification templates, and review Conditional Access. Compliance uses a seven-day migration grace. Shorten it only after the estate is stable.

**Wave 4 — ASR enforcement.** Run the audit policy for **at least two weeks**, review Defender reports, add exclusions, then switch to `12-win-sc-asr-rules-enforced.json`. **Unassign audit when assigning enforced** because both set the same CSPs.

---

## Gaps to close before deploying to a real tenant

These controls need tenant and fleet data before wave 3:

- **Supported OS/build floors** — Windows, iOS and macOS inactive version fields are omitted rather than sent as empty strings. For Android, define `androidminimumosversion` and `androidminimumsecuritypatchlevel` per tenant before deployment. For Windows, prefer `validOperatingSystemBuildRanges`. Do not set a maximum version unless there is a deliberate compatibility hold.
- **Android minimum security patch level** — set `androidminimumsecuritypatchlevel` from the supported device/OEM estate. `requireNoPendingSystemUpdates` is deliberately `false`; treating every pending update as immediate noncompliance is too fragile for a generic baseline.
- **`deviceThreatProtectionEnabled`** — `false` everywhere. Only enable per platform once a Mobile Threat Defense connector (Defender for Endpoint) is actually wired up. Enabled without a connector, devices report no signal and fail compliance for the wrong reason.
- **Windows VBS/HVCI/DMA compliance checks** — `memoryIntegrityEnabled`, `virtualizationBasedSecurityEnabled`, `kernelDmaProtectionEnabled` and `firmwareProtectionEnabled` are all `false`. They're hardware-dependent. Turn them on only after `17-win-sc-credential-guard.json` is proven on the actual hardware, or you will fail every older machine in the fleet.
- **`gracePeriodHours: 168`** on every compliance block action gives a seven-day migration window. Shorten only after configuration health and user communications are proven.
- **Android password posture** — a six-digit `numericComplex` PIN is required in both the restrictions and compliance policies. Move to `alphanumeric` only if Lloyds explicitly accepts the usability and support cost.
- **Android recovery/data posture** — the kiosk-only network escape hatch is disabled for this single-user fully managed scope. App updates use any network and may consume cellular data; use `wiFiOnly` if cellular cost outweighs delayed app patching.
- **Android compliance notification template** — create the tenant's message template first and put its GUID in `androidcompliancenotificationtemplateid`. Referencing a GUID that does not exist in that tenant will fail deployment. The other platform policies still ship with block-only actions and can receive tenant-specific notification actions later.
- **iOS/iPadOS OS floor and notification** — define `iosminimumosversion` from the supported Apple model inventory and `ioscompliancenotificationtemplateid` from an existing Intune notification template. Never guess a floor before the supported hardware and current OS versions are known.

Still intentionally **out of scope**: Windows Update rings/feature-update policy, Defender for Endpoint onboarding and tamper protection, macOS update/Defender PPPC prerequisites, Apple enrollment restrictions and token creation, Apps and Books acquisition/assignment, Managed Google Play app creation/assignment, tenant-specific kiosk app allowlists, and App Protection/MAM for BYOD. Treat these as tenant bootstrap responsibilities rather than assuming this set is a complete Intune architecture.

---

## Design decisions worth knowing

**Settings Catalog, not the legacy templates.** An earlier draft of this baseline used the classic `windows10EndpointProtectionConfiguration` and `windowsIdentityProtectionConfiguration` profile types. Those were dropped, for two reasons: Microsoft has deprecated the legacy Endpoint Protection templates (the macOS one can no longer create new policies at all, and Administrative Templates were deprecated in the December 2024 release), and more immediately, a legacy Endpoint Protection profile and a Settings Catalog firewall/BitLocker policy set the *same* CSPs — running both produces a policy conflict rather than defence in depth.

**Beta schema, deliberately.** CIPP reads and writes Intune through the Graph **beta** endpoint (`New-CIPPIntuneTemplate.ps1` hardcodes `graph.microsoft.com/beta`). The beta compliance schema exposes roughly a dozen security controls the v1.0 schema doesn't — `defenderEnabled`, `rtpEnabled`, `activeFirewallRequired`, `antivirusRequired`, `antiSpywareRequired`, `signatureOutOfDate`, `tpmRequired`, plus the VBS/HVCI/DMA attestation checks. Targeting v1.0 would have silently cost about half the available Windows compliance coverage.

**Derived, reviewed and pinned.** The Settings Catalog policies come from [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline). `build.py` pins an exact reviewed upstream commit, strips tenant state, applies the documented local safety overrides, and replaces outputs atomically only if every source builds. Updating upstream is a deliberate SHA change followed by a reviewed diff and `validate.py --refresh`.

**Validation covers values, not just JSON shape.** `validate.py` refreshes cached Microsoft/CIPP data every 24 hours, checks hand-authored names and enums, validates the compliance action structure and embedded Edge managed configuration, verifies every Settings Catalog definition and selected choice against CIPP's current catalog, rejects deprecated settings and unexpected cross-policy overlap, and checks generated files for tenant scaffolding. A successful CIPP template import still only proves storage; deployment to a test tenant is the final Graph acceptance test.

---

## Tooling

| File | Purpose |
|---|---|
| `validate.py` | Validate Graph properties, compliance actions, current CIPP setting IDs/options, deprecations, overlap and tenant scaffolding. Use `--refresh` before release/import. |
| `build.py` | Rebuild atomically from the pinned OpenIntuneBaseline revision and reapply local safety overrides. `--plain` drops endpoint-security template linkage. |
| `Import-CippIntuneTemplates.ps1` | Bulk-import to CIPP. Dry run by default; duplicate-safe `-Execute`; `-ExistingAction Skip` resumes a partial run; `-Prefix` and `-Only` scope imports. |
| `manifest.cipp` | Maps each file to its CIPP template type and rollout wave; excluded from CIPP's JSON policy catalog. |
| `automation/Invoke-AndroidFullyManagedTenant.ps1` | Idempotent plan/apply bootstrap for tenant-specific Android groups, enrollment targeting, compliance floors, FRP, WPA/WPA2 Personal Wi-Fi and Managed Google Play assignments. Never stores the PSK. |
| `automation/android-fully-managed.example.config` | Redacted, JSON-formatted tenant configuration example for the Android bootstrap. The non-`.json` extension prevents CIPP from offering it as an Intune policy. Copy it outside the public repository before customising it. |
| `automation/Invoke-IosCorporateTenant.ps1` | Read-only-by-default Apple prerequisite, group, ADE-profile, policy, WPA2 Personal Wi-Fi and Apps and Books assignment bootstrap. Refuses apply when APNs/ADE/Apps and Books prerequisites are absent. |
| `automation/ios-corporate.example.config` | Redacted, JSON-formatted tenant configuration example for the iOS bootstrap. The non-`.json` extension prevents CIPP from offering it as an Intune policy. Never add Apple token files, certificate material or Wi-Fi keys. |
| `automation/Test-IosCorporateTenant.ps1` | Deep read-only audit of APNs/ADE/Apps and Books dates, exact live types and settings, assignments, app identities, enrollment restrictions, Conditional Access and pilot-device health. |

For repeat deployments, add the three Android configuration templates to a CIPP
package and deploy that package from a **CIPP Standards template** with assignment
verification enabled. Keep Android compliance in a separate package so it can be
introduced only after configuration is healthy. CIPP's community library refreshes
same-named templates from GitHub, while the Standards run compares and remediates
the live tenant policies. See [automation/README.md](automation/README.md) for the
exact split between CIPP-owned policy lifecycle and tenant bootstrap automation.

**If an endpoint-security policy is rejected on deploy:** first capture and review the Graph error. As a fallback, `python3 build.py --plain` detaches endpoint-security template linkage and changes delivery to MDM-only Settings Catalog. The CSP values remain the same, but Microsoft Defender security-management targeting no longer applies. Revalidate and retry only the failed file.

---

## Making the Lloyds version

1. Import the base set and confirm it deploys cleanly to a test tenant.
2. Fill in the gaps above from Lloyds' actual fleet data — pull current OS builds, Android device password policy, and Defender for Endpoint licensing from the Miradore inventory before cutover.
3. Re-import under client naming:
   ```bash
   pwsh ./Import-CippIntuneTemplates.ps1 -Execute -Prefix 'Lloyds - '
   ```
4. Assign to Lloyds' device groups following the wave order above.

---

## Sources

- [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline) — source for the Settings Catalog policies
- [CyberDrain CIS Templates](https://github.com/CyberDrain/CyberDrain-CIS-Templates) — CIS-aligned CIPP template pack, addable via CIPP → Endpoint Management → Templates → Community Repositories, if you want deeper CIS coverage on top of this baseline
- [CIPP Policy Templates documentation](https://docs.cipp.app/user-documentation/endpoint/mem/list-templates)
- Microsoft Graph beta schemas: [windows10CompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windows10compliancepolicy?view=graph-rest-beta) · [androidDeviceOwnerCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androiddeviceownercompliancepolicy?view=graph-rest-beta) · [iosCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-ioscompliancepolicy?view=graph-rest-beta) · [macOSCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-macoscompliancepolicy?view=graph-rest-beta) · [androidDeviceOwnerGeneralDeviceConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androiddeviceownergeneraldeviceconfiguration?view=graph-rest-beta) · [androidManagedStoreAppConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-androidmanagedstoreappconfiguration?view=graph-rest-beta)
- [Microsoft Edge mobile policy reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-mobile-policies)
