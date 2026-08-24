#!/usr/bin/env python3
"""
Rebuild the Settings Catalog policies in this baseline from OpenIntuneBaseline (OIB).

OIB publishes raw Microsoft Graph exports taken from live tenants. Those exports carry
tenant-specific identifiers (policy GUIDs embedded in @odata.id paths, createdDateTime,
settingCount, Graph action stubs) that make them fail on import into another tenant --
this is the "don't import NativeImport templates" warning in the CIPP docs.

This script strips the export down to exactly the six fields CIPP itself keeps when it
captures a Settings Catalog policy from a tenant, per New-CIPPIntuneTemplate.ps1:

    name, description, settings, platforms, technologies, templateReference

Run:  python3 build.py            # refresh all Settings Catalog policies
      python3 build.py --plain    # also strip endpoint-security template linkage
                                  # (fallback if a policy is rejected on deploy)

Requires network access to raw.githubusercontent.com. The generated .json files are
committed, so this only needs re-running to pick up upstream OIB changes.
"""

import argparse
import json
import os
import pathlib
import sys
import tempfile
import urllib.parse
import urllib.request

# Pin the exact reviewed upstream revision. Updating the baseline is therefore a deliberate
# change: update this SHA, rebuild, review the diff, then run validate.py --refresh.
OIB_COMMIT = "4844247055305c9eb8dfe4b12c895ec8422dee67"
OIB_RAW = f"https://raw.githubusercontent.com/SkipToTheEndpoint/OpenIntuneBaseline/{OIB_COMMIT}"

# (output filename, OIB source path, override display name, override description)
# Descriptions are rewritten: OIB's own text carries "OIBID:" tracking markers and
# version strings that would be misleading once the policy is cloned per-client.
POLICIES = [
    (
        "10-win-sc-defender-antivirus.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Defender Antivirus - D - AV Configuration - v3.3.json",
        "Baseline - Windows - Defender Antivirus",
        "Microsoft Defender Antivirus configuration: real-time and behaviour monitoring, "
        "cloud-delivered protection, PUA blocking, network protection, scan schedule and "
        "threat remediation actions. Derived from OpenIntuneBaseline.",
    ),
    (
        "11-win-sc-asr-rules-audit.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Attack Surface Reduction - D - ASR Rules (Audit Mode) - v3.1.json",
        "Baseline - Windows - ASR Rules (AUDIT - deploy first)",
        "Attack Surface Reduction rules in AUDIT mode. Deploy this FIRST and leave it for "
        "at least two weeks. ASR rules block legitimate line-of-business software far more "
        "often than people expect; audit mode reports what would have been blocked without "
        "breaking anything. Review Defender reports, add exclusions, then switch to the "
        "enforced policy. Derived from OpenIntuneBaseline.",
    ),
    (
        "12-win-sc-asr-rules-enforced.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Attack Surface Reduction - D - ASR Rules (L2) - v3.7.json",
        "Baseline - Windows - ASR Rules (ENFORCED - after audit)",
        "Attack Surface Reduction rules in enforcing mode. DO NOT DEPLOY until the audit-mode "
        "policy has run for at least two weeks and its findings have been reviewed. Unassign "
        "the audit policy when you assign this one -- running both sets the same CSPs and "
        "will conflict. Derived from OpenIntuneBaseline.",
    ),
    (
        "13-win-sc-firewall.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Windows Firewall - D - Firewall Configuration - v3.1.json",
        "Baseline - Windows - Windows Firewall",
        "Windows Firewall enabled on all three profiles (domain, private, public) with inbound "
        "blocked by default, outbound allowed, stealth mode on, local policy merge disabled on "
        "the public profile, and dropped-packet logging enabled. Derived from OpenIntuneBaseline.",
    ),
    (
        "14-win-sc-bitlocker.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Encryption - D - BitLocker (OS Disk) - v3.7.json",
        "Baseline - Windows - BitLocker (OS Disk)",
        "Silent BitLocker encryption of the OS disk with the recovery key escrowed to Entra ID. "
        "Verify Entra key escrow is working on a pilot device before broad assignment -- a "
        "device that encrypts without a retrievable key is a support incident waiting to happen. "
        "Derived from OpenIntuneBaseline.",
    ),
    (
        "15-win-sc-windows-hello.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Windows Hello for Business - D - WHfB Configuration - v3.2.json",
        "Baseline - Windows - Windows Hello for Business",
        "Windows Hello for Business PIN and biometric configuration, TPM required. Replaces the "
        "deprecated windowsIdentityProtectionConfiguration template. Derived from OpenIntuneBaseline.",
    ),
    (
        "16-win-sc-security-hardening.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - SC - Device Security - D - Security Hardening - v3.7.json",
        "Baseline - Windows - OS Security Hardening",
        "General OS hardening: legacy protocol and cipher restrictions, LSA protection, "
        "PowerShell logging and related CIS-aligned settings. Review against line-of-business "
        "apps before enforcing -- this is the policy most likely to surface a legacy-app "
        "dependency. Derived from OpenIntuneBaseline.",
    ),
    (
        "17-win-sc-credential-guard.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - SC - Device Security - U - Device Guard, Credential Guard and HVCI - v3.7.json",
        "Baseline - Windows - Device Guard / Credential Guard / HVCI",
        "Virtualisation-based security: Credential Guard, HVCI (memory integrity) and Secure "
        "Boot enforcement, enabled without UEFI lock so it remains remotely reversible. "
        "Requires compatible hardware and can break old kernel-mode drivers, "
        "so pilot before broad rollout. Pairs with the virtualizationBasedSecurityEnabled and "
        "memoryIntegrityEnabled checks in the Windows compliance policy. "
        "Derived from OpenIntuneBaseline.",
    ),
    (
        "18-win-sc-laps.json",
        "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Windows LAPS - D - LAPS Configuration - v3.1.json",
        "Baseline - Windows - Local Administrator Password Solution",
        "Windows LAPS with recovery to Microsoft Entra ID, a 21-character password, seven-day "
        "rotation, and password reset plus account logoff after administrative use. Confirm the "
        "tenant has a managed local administrator account and authorized recovery roles before "
        "assignment. Derived from OpenIntuneBaseline.",
    ),
    (
        "20-macos-sc-filevault.json",
        "MACOS/IntuneManagement/SettingsCatalog/MacOS - OIB - Disk Encryption - D - FileVault - v1.0.json",
        "Baseline - macOS - FileVault Disk Encryption",
        "FileVault full-disk encryption with the recovery key escrowed to Intune. The legacy "
        "macOS endpoint protection template is deprecated -- Settings Catalog is the only "
        "supported path for new FileVault policies. Derived from OpenIntuneBaseline.",
    ),
    (
        "21-macos-sc-gatekeeper-firewall.json",
        "MACOS/IntuneManagement/SettingsCatalog/MacOS - OIB - Firewall - D - Gatekeeper - v1.0.json",
        "Baseline - macOS - Gatekeeper and Firewall",
        "macOS application firewall plus Gatekeeper / System Policy Control, restricting app "
        "execution to identified developers and allowing XProtect malware sample submission. "
        "Derived from OpenIntuneBaseline.",
    ),
]

# Intentional safety and portability changes applied after cleaning the upstream exports.
# Keeping them here ensures a rebuild cannot silently reintroduce the reviewed-out values.
CHOICE_OVERRIDES = {
    "device_vendor_msft_policy_config_deviceguard_lsacfgflags":
        "device_vendor_msft_policy_config_deviceguard_lsacfgflags_2",
    "device_vendor_msft_policy_config_localsecurityauthority_configurelsaprotectedprocess":
        "device_vendor_msft_policy_config_localsecurityauthority_configurelsaprotectedprocess_2",
    "device_vendor_msft_policy_config_virtualizationbasedtechnology_hypervisorenforcedcodeintegrity":
        "device_vendor_msft_policy_config_virtualizationbasedtechnology_hypervisorenforcedcodeintegrity_2",
    "com.apple.systempolicy.control_enablexprotectmalwareupload":
        "com.apple.systempolicy.control_enablexprotectmalwareupload_true",
}
SIMPLE_OVERRIDES = {
    "com.apple.security.fderecoverykeyescrow_location":
        "Your FileVault recovery key is escrowed to Microsoft Intune. If recovery is required, "
        "contact your IT support team and provide the device serial number.",
}
DROP_SETTING_IDS = {
    "com.apple.security.firewall_enablelogging",  # Apple marks this payload key deprecated.
}
DROP = object()

# Graph response scaffolding and tenant-specific state. None of it belongs in a
# portable template; several fields actively break cross-tenant import.
STRIP_KEYS = {
    "@odata.context", "@odata.id", "@odata.editLink", "@odata.count",
    "id", "createdDateTime", "lastModifiedDateTime", "creationSource",
    "settingCount", "priorityMetaData", "supportsScopeTags",
    "assignments", "isAssigned", "version",
}


def clean(node):
    """Recursively drop Graph scaffolding, tenant state, and @odata.* annotation keys.

    Annotation keys are the `<field>@odata.type` / `@odata.associationLink` style
    siblings Graph emits alongside real fields. The genuine discriminator
    `@odata.type` is kept -- Graph rejects settings payloads without it.
    """
    if isinstance(node, list):
        return [clean(v) for v in node]
    if not isinstance(node, dict):
        return node

    out = {}
    for key, value in node.items():
        if key in STRIP_KEYS:
            continue
        # Graph action stubs: "#microsoft.graph.assign", "#microsoft.graph.createCopy", ...
        if key.startswith("#microsoft.graph."):
            continue
        # Annotation siblings, but never the real "@odata.type" discriminator.
        if "@odata." in key and key != "@odata.type":
            continue
        out[key] = clean(value)
    return out


def apply_local_overrides(node):
    """Apply reviewed local changes without losing upstream reproducibility."""
    if isinstance(node, list):
        values = (apply_local_overrides(v) for v in node)
        return [v for v in values if v is not DROP]
    if not isinstance(node, dict):
        return node

    setting_id = node.get("settingDefinitionId")
    if setting_id in DROP_SETTING_IDS:
        return DROP

    out = {key: apply_local_overrides(value) for key, value in node.items()}
    if setting_id in CHOICE_OVERRIDES and isinstance(out.get("choiceSettingValue"), dict):
        out["choiceSettingValue"]["value"] = CHOICE_OVERRIDES[setting_id]
    if setting_id in SIMPLE_OVERRIDES and isinstance(out.get("simpleSettingValue"), dict):
        out["simpleSettingValue"]["value"] = SIMPLE_OVERRIDES[setting_id]
    return out


def fetch(path):
    url = f"{OIB_RAW}/{urllib.parse.quote(path)}"
    with urllib.request.urlopen(url, timeout=60) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} for {url}")
        return json.loads(response.read().decode("utf-8"))


def build(outfile, source_path, display_name, description, plain):
    raw = fetch(source_path)

    settings = apply_local_overrides(clean(raw.get("settings", [])))
    if not settings:
        raise RuntimeError(f"{source_path}: no settings survived cleaning")

    policy = {
        "name": display_name,
        "description": description,
        "platforms": raw["platforms"],
        "technologies": raw["technologies"],
        "roleScopeTagIds": ["0"],
        "templateReference": clean(raw.get("templateReference")) or None,
        "settings": settings,
    }

    if plain:
        # Detach from the endpoint-security template. Some CIPP/Graph combinations
        # reject a templateId that the target tenant cannot resolve; a plain Settings
        # Catalog policy keeps the same CSP values without that dependency, but changes
        # delivery to MDM-only (Microsoft Defender security-management targeting is removed).
        policy["templateReference"] = None
        policy["technologies"] = "mdm"
        policy["settings"] = strip_template_refs(policy["settings"])

    return policy, count_settings(settings)


def write_atomic(path, policy):
    """Replace a generated policy only after every upstream policy built successfully."""
    destination = pathlib.Path(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(policy, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def strip_template_refs(node):
    """Null out settingInstanceTemplateReference / settingValueTemplateReference.

    These bind a setting to a specific endpoint-security template version and are
    meaningless -- and potentially rejected -- once templateReference is removed.
    """
    if isinstance(node, list):
        return [strip_template_refs(v) for v in node]
    if not isinstance(node, dict):
        return node
    out = {}
    for key, value in node.items():
        if key in ("settingInstanceTemplateReference", "settingValueTemplateReference"):
            out[key] = None
        else:
            out[key] = strip_template_refs(value)
    return out


def count_settings(node, total=0):
    """Count settingDefinitionId occurrences, including nested children."""
    if isinstance(node, list):
        return sum(count_settings(v) for v in node)
    if isinstance(node, dict):
        total = 1 if "settingDefinitionId" in node else 0
        return total + sum(count_settings(v) for v in node.values())
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plain",
        action="store_true",
        help="strip endpoint-security template linkage (deploy-failure fallback)",
    )
    args = parser.parse_args()

    failures = []
    generated = []
    for outfile, source_path, name, description in POLICIES:
        try:
            policy, n = build(outfile, source_path, name, description, args.plain)
            generated.append((outfile, policy))
            print(f"  ok  {outfile}  ({n} settings)")
        except Exception as exc:  # noqa: BLE001 - report and continue over the whole set
            failures.append((outfile, exc))
            print(f"FAIL  {outfile}: {exc}", file=sys.stderr)

    if failures:
        print(f"\n{len(failures)} of {len(POLICIES)} failed.", file=sys.stderr)
        return 1

    for outfile, policy in generated:
        write_atomic(outfile, policy)
    print(f"\n{len(POLICIES)} policies written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
