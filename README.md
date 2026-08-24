# CIPP Intune Security Baseline — Generic Template Set

Generic, security-focused Intune policy set for import into CIPP as reusable **Intune Templates**. This is the base — clone it into a client-specific version (Lloyds first) once reviewed.

16 policies across Windows, Android Enterprise, iOS/iPadOS and macOS. Every policy is validated before it ships (`python3 validate.py`) and can be bulk-imported in one command.

---

## Quick start

```bash
python3 validate.py --refresh                # validate all 16 against current Graph/CIPP data
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
| `02-compliance-android-fully-managed.json` | Android Enterprise COBO/COSU | Play Integrity (hardware-backed), encryption, no pending updates |
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

### Android Enterprise device restrictions — hand-authored

| File | Covers |
|---|---|
| `30-android-device-restrictions.json` | Blocks sideloading, developer options, USB file transfer, external media and screen capture; enables network recovery and automatic app updates on any network; enforces Play Protect and lockout-to-wipe |

---

## Rollout order

`manifest.cipp` assigns every policy a wave. Its non-JSON extension deliberately prevents CIPP's Community Repository catalog from treating the rollout manifest as an Intune policy. Configuration must remediate devices before compliance evaluates them. Never assume compliance is report-only: if an existing Conditional Access policy requires a compliant device, a noncompliant result can block access.

**Wave 1 — establish controls and telemetry.** Defender AV, Windows Firewall and **ASR in audit mode**. Start with a representative pilot, check conflicts, then expand.

**Wave 2 — remediate with a pilot group first.** BitLocker, Windows Hello, OS hardening, Credential Guard, Windows LAPS, macOS FileVault/Gatekeeper and Android restrictions. Each can visibly change behavior or depends on hardware:
- **BitLocker** — confirm the recovery key actually lands in Entra ID on a pilot device. A device that encrypts without a retrievable key is a support incident waiting to happen.
- **Credential Guard / HVCI** — needs VBS-capable hardware and can break old kernel-mode drivers. The baseline uses the remotely reversible **without UEFI lock** values.
- **Windows LAPS** — confirm a local administrator account exists, passwords escrow to Entra ID, and recovery roles are least-privileged.
- **OS hardening** (96 settings) — explicitly test legacy NAS/scanners because the minimum SMB dialect is 3.0. It also blocks adding/removing provisioning packages after policy applies.
- **Android restrictions** — several are user-visible; check them against how the handhelds are actually used.

**Wave 3 — compliance after remediation is healthy.** Set supported OS/build and patch floors, verify configuration success, create notification templates, and review Conditional Access. Compliance uses a seven-day migration grace. Shorten it only after the estate is stable.

**Wave 4 — ASR enforcement.** Run the audit policy for **at least two weeks**, review Defender reports, add exclusions, then switch to `12-win-sc-asr-rules-enforced.json`. **Unassign audit when assigning enforced** because both set the same CSPs.

---

## Gaps to close before deploying to a real tenant

These controls need tenant and fleet data before wave 3:

- **Supported OS/build floors** — inactive version fields are omitted rather than sent as empty strings. Add a minimum supported version per platform; for Windows, prefer `validOperatingSystemBuildRanges`. Do not set a maximum version unless there is a deliberate compatibility hold.
- **Android minimum security patch level** — set this from the supported device/OEM estate. `requireNoPendingSystemUpdates` is deliberately `false`; treating every pending update as immediate noncompliance is too fragile for a generic baseline.
- **`deviceThreatProtectionEnabled`** — `false` everywhere. Only enable per platform once a Mobile Threat Defense connector (Defender for Endpoint) is actually wired up. Enabled without a connector, devices report no signal and fail compliance for the wrong reason.
- **Windows VBS/HVCI/DMA compliance checks** — `memoryIntegrityEnabled`, `virtualizationBasedSecurityEnabled`, `kernelDmaProtectionEnabled` and `firmwareProtectionEnabled` are all `false`. They're hardware-dependent. Turn them on only after `17-win-sc-credential-guard.json` is proven on the actual hardware, or you will fail every older machine in the fleet.
- **`gracePeriodHours: 168`** on every compliance block action gives a seven-day migration window. Shorten only after configuration health and user communications are proven.
- **Android `passwordRequiredType`** is `numericComplex`, which suits shared/handheld devices. Switch to `alphanumeric` for personal-style corporate phones.
- **Android recovery/data posture** — the network escape hatch is enabled so a kiosk can recover if its managed network changes, and app updates use any network. For higher-security devices that leave site, disable the escape hatch only if resilient managed connectivity exists; use `wiFiOnly` if cellular cost outweighs delayed app patching.
- **Compliance notification templates** — the block actions use an empty `notificationTemplateId` (no email). Add a notification action once a message template exists in the target tenant; referencing a template GUID that doesn't exist there will fail the deploy.

Still intentionally **out of scope**: Windows Update rings/feature-update policy, Defender for Endpoint onboarding and tamper protection, macOS update/Defender PPPC prerequisites, iOS restrictions, enrollment restrictions, and App Protection/MAM for BYOD. Treat these as the next layer rather than assuming this set is a complete Intune architecture.

---

## Design decisions worth knowing

**Settings Catalog, not the legacy templates.** An earlier draft of this baseline used the classic `windows10EndpointProtectionConfiguration` and `windowsIdentityProtectionConfiguration` profile types. Those were dropped, for two reasons: Microsoft has deprecated the legacy Endpoint Protection templates (the macOS one can no longer create new policies at all, and Administrative Templates were deprecated in the December 2024 release), and more immediately, a legacy Endpoint Protection profile and a Settings Catalog firewall/BitLocker policy set the *same* CSPs — running both produces a policy conflict rather than defence in depth.

**Beta schema, deliberately.** CIPP reads and writes Intune through the Graph **beta** endpoint (`New-CIPPIntuneTemplate.ps1` hardcodes `graph.microsoft.com/beta`). The beta compliance schema exposes roughly a dozen security controls the v1.0 schema doesn't — `defenderEnabled`, `rtpEnabled`, `activeFirewallRequired`, `antivirusRequired`, `antiSpywareRequired`, `signatureOutOfDate`, `tpmRequired`, plus the VBS/HVCI/DMA attestation checks. Targeting v1.0 would have silently cost about half the available Windows compliance coverage.

**Derived, reviewed and pinned.** The Settings Catalog policies come from [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline). `build.py` pins an exact reviewed upstream commit, strips tenant state, applies the documented local safety overrides, and replaces outputs atomically only if every source builds. Updating upstream is a deliberate SHA change followed by a reviewed diff and `validate.py --refresh`.

**Validation covers values, not just JSON shape.** `validate.py` refreshes cached Microsoft/CIPP data every 24 hours, checks hand-authored names and enums, validates the compliance action structure, verifies every Settings Catalog definition and selected choice against CIPP's current catalog, rejects deprecated settings and unexpected cross-policy overlap, and checks generated files for tenant scaffolding. A successful CIPP template import still only proves storage; deployment to a test tenant is the final Graph acceptance test.

---

## Tooling

| File | Purpose |
|---|---|
| `validate.py` | Validate Graph properties, compliance actions, current CIPP setting IDs/options, deprecations, overlap and tenant scaffolding. Use `--refresh` before release/import. |
| `build.py` | Rebuild atomically from the pinned OpenIntuneBaseline revision and reapply local safety overrides. `--plain` drops endpoint-security template linkage. |
| `Import-CippIntuneTemplates.ps1` | Bulk-import to CIPP. Dry run by default; duplicate-safe `-Execute`; `-ExistingAction Skip` resumes a partial run; `-Prefix` and `-Only` scope imports. |
| `manifest.cipp` | Maps each file to its CIPP template type and rollout wave; excluded from CIPP's JSON policy catalog. |

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
- Microsoft Graph beta schemas: [windows10CompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windows10compliancepolicy?view=graph-rest-beta) · [androidDeviceOwnerCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androiddeviceownercompliancepolicy?view=graph-rest-beta) · [iosCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-ioscompliancepolicy?view=graph-rest-beta) · [macOSCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-macoscompliancepolicy?view=graph-rest-beta) · [androidDeviceOwnerGeneralDeviceConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androiddeviceownergeneraldeviceconfiguration?view=graph-rest-beta)
