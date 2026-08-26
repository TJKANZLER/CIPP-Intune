#!/usr/bin/env python3
"""
Validate the hand-authored policies in this baseline against the Microsoft Graph beta
schemas they target.

A wrong property name or a wrong enum string does not fail loudly. Graph usually accepts
the payload and silently ignores what it does not recognise, so the policy deploys, reports
success, and simply never applies the control you thought you configured. This script
catches that class of error before it reaches a tenant. It found a fabricated
`safeBootBlocked` property on first run.

Checks performed:
  1. every JSON file parses
  2. every property name exists in the target resource's documented property table
  3. every string value assigned to a documented enum property is a documented value
  4. compliance policies contain exactly one valid block action
  5. every Settings Catalog definition and choice exists in CIPP's current catalog
  6. generated Settings Catalog files carry no tenant-specific Graph scaffolding
  7. no unexpected setting overlap exists between separate policies
  8. the rollout manifest covers every policy exactly once and contains no orphan entries
  9. CIPP replacement tokens are explicitly allowlisted
 10. separate hand-authored policies for the same Graph resource do not configure the same setting
 11. the embedded Microsoft Edge managed-app payload has the expected package, keys and value types
 12. the supervised iOS restrictions and declarative update policy preserve their safety-critical posture

Run:  python3 validate.py
      python3 validate.py --refresh   # force fresh Microsoft/CIPP schema data

Schemas are fetched from the public microsoft-graph-docs-contrib repo and cached in
.schema-cache/. Delete that directory to force a refresh.
"""

import argparse
import base64
import json
import pathlib
import re
import sys
import time
import urllib.request

HERE = pathlib.Path(__file__).parent
CACHE = HERE / ".schema-cache"
DOCS_RAW = (
    "https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib"
    "/main/api-reference/beta/resources"
)
CIPP_CATALOG_URL = (
    "https://raw.githubusercontent.com/KelvinTegelaar/CIPP-API/"
    "master/Config/intuneCollection.json"
)

# Hand-authored file -> the Graph resource it must conform to.
HAND_AUTHORED = {
    "01-compliance-windows.json": "intune-deviceconfig-windows10compliancepolicy",
    "02-compliance-android-fully-managed.json": "intune-deviceconfig-androiddeviceownercompliancepolicy",
    "03-compliance-ios.json": "intune-deviceconfig-ioscompliancepolicy",
    "04-compliance-macos.json": "intune-deviceconfig-macoscompliancepolicy",
    "30-android-device-restrictions.json": "intune-deviceconfig-androiddeviceownergeneraldeviceconfiguration",
    "31-android-launcher-branding.json": "intune-deviceconfig-androiddeviceownergeneraldeviceconfiguration",
    "IntuneTemplate/32-android-edge-browser.json": "intune-apps-androidmanagedstoreappconfiguration",
    "33-ios-supervised-device-restrictions.json": "intune-deviceconfig-iosgeneraldeviceconfiguration",
}

ALLOWED_CIPP_TOKENS = {
    "androidcompliancenotificationtemplateid",
    "androidedgeappid",
    "androidfrprecoveryaccount",
    "androidminimumosversion",
    "androidminimumsecuritypatchlevel",
    "androidwallpaperurl",
    "ioscompliancenotificationtemplateid",
    "iosminimumosversion",
}
PASSTHROUGH_PERCENT_VARS = {"systemroot"}
POLICY_IDENTITY_FIELDS = {"@odata.type", "displayName", "description", "roleScopeTagIds"}

# Present on the payload but not in the resource's own property table: the type
# discriminator, inherited naming fields, and the scheduledActionsForRule relationship
# (required by Graph when creating any compliance policy).
NOT_IN_PROPERTY_TABLE = {
    "@odata.type",
    "displayName",
    "description",
    "roleScopeTagIds",
    "scheduledActionsForRule",
}

# Scaffolding that must not survive into a generated Settings Catalog template.
FORBIDDEN_IN_GENERATED = [
    ("@odata.id", "tenant-specific policy path"),
    ("@odata.context", "Graph response metadata"),
    ("@odata.editLink", "tenant-specific edit path"),
    ("createdDateTime", "source-tenant timestamp"),
    ("lastModifiedDateTime", "source-tenant timestamp"),
    ("settingCount", "derived field Graph rejects on write"),
    ("creationSource", "source-tenant provenance"),
    ("#microsoft.graph.assign", "Graph action stub"),
]

EDGE_BOOLEAN_SETTINGS = {
    "DefaultBrowserSettingEnabled",
    "EdgeNewTabPageLayoutUserSelectable",
    "EdgeCopilotEnabled",
    "EdgeDisableShareUsageData",
    "EdgeMyApps",
    "HideFirstRunExperience",
    "EdgeDefaultHTTPS",
    "SmartScreenEnabled",
    "SmartScreenPuaEnabled",
    "PreventSmartScreenPromptOverride",
    "PasswordManagerEnabled",
    "BiometricAuthenticationBeforeFilling",
}
EDGE_STRING_SETTINGS = {
    "EdgeNewTabPageLayout": {"focused"},
}
EDGE_CIPP_TEMPLATE_GUID = "1512f9e1-09af-5411-b1c5-febc1d8af922"


def cached_download(url, cached, refresh=False, max_age_hours=24):
    CACHE.mkdir(exist_ok=True)
    stale = not cached.exists() or time.time() - cached.stat().st_mtime > max_age_hours * 3600
    if refresh or stale:
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                cached.write_bytes(r.read())
        except Exception:
            if not cached.exists():
                raise
            print(f"  warning: refresh failed for {url}; using cached copy", file=sys.stderr)
    return cached.read_text(encoding="utf-8")


def schema(resource, refresh=False, max_age_hours=24):
    cached = CACHE / f"{resource}.md"
    return cached_download(
        f"{DOCS_RAW}/{resource}.md", cached, refresh, max_age_hours
    )


def cipp_catalog(refresh=False, max_age_hours=24):
    cached = CACHE / "cipp-intuneCollection.json"
    return json.loads(cached_download(
        CIPP_CATALOG_URL, cached, refresh, max_age_hours
    ))


def parse_schema(text):
    """Return (valid property names, {property: allowed enum values}).

    Property tables are pipe-delimited markdown: |name|type|description|. Enum values
    appear backticked inside the description ("Possible values are: `a`, `b`.").
    """
    names, enums = set(), {}
    for match in re.finditer(r"^\|\s*([a-zA-Z][a-zA-Z0-9]*)\s*\|(.*)$", text, re.M):
        prop, rest = match.group(1), match.group(2)
        names.add(prop)
        values = re.findall(r"`([a-zA-Z][a-zA-Z0-9]*)`", rest)
        if values:
            enums[prop] = set(values)
    return names, enums


def check_compliance_actions(filename, data):
    problems = []
    if not data.get("@odata.type", "").endswith("CompliancePolicy"):
        return problems
    rules = data.get("scheduledActionsForRule")
    if not isinstance(rules, list) or len(rules) != 1:
        return [f"{filename}: scheduledActionsForRule must contain exactly one rule"]
    if rules[0].get("ruleName") != "PasswordRequired":
        problems.append(f"{filename}: compliance ruleName must be 'PasswordRequired'")
    actions = rules[0].get("scheduledActionConfigurations")
    if not isinstance(actions, list):
        return problems + [f"{filename}: scheduledActionConfigurations must be an array"]
    blocks = [a for a in actions if a.get("actionType") == "block"]
    if len(blocks) != 1:
        problems.append(f"{filename}: compliance policy must contain exactly one block action")
    for action in actions:
        grace = action.get("gracePeriodHours")
        if not isinstance(grace, int) or not 0 <= grace <= 8760:
            problems.append(f"{filename}: invalid gracePeriodHours {grace!r}")
        if not isinstance(action.get("notificationMessageCCList", []), list):
            problems.append(f"{filename}: notificationMessageCCList must be an array")
    return problems


def check_edge_managed_configuration(filename, data):
    """Validate the JSON-inside-JSON payload used by Android managed app configuration."""
    if filename != "IntuneTemplate/32-android-edge-browser.json":
        return []

    problems = []
    if data.get("packageId") != "com.microsoft.emmx":
        problems.append(f"{filename}: packageId must be com.microsoft.emmx")
    if data.get("targetedMobileApps") != ["%androidedgeappid%"]:
        problems.append(f"{filename}: targetedMobileApps must contain only %androidedgeappid%")
    if data.get("profileApplicability") != "androidDeviceOwner":
        problems.append(f"{filename}: profileApplicability must be androidDeviceOwner")

    try:
        encoded_payload = data.get("payloadJson", "")
        payload = json.loads(base64.b64decode(encoded_payload, validate=True).decode("utf-8"))
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return problems + [f"{filename}: payloadJson is not valid Base64-encoded JSON - {exc}"]

    if payload.get("kind") != "androidenterprise#managedConfiguration":
        problems.append(f"{filename}: payloadJson has an invalid kind")
    if payload.get("productId") != "app:com.microsoft.emmx":
        problems.append(f"{filename}: payloadJson productId must be app:com.microsoft.emmx")

    settings = payload.get("managedProperty")
    if not isinstance(settings, list):
        return problems + [f"{filename}: payloadJson managedProperty must be an array"]
    keys = [item.get("key") for item in settings if isinstance(item, dict)]
    duplicates = sorted({key for key in keys if key and keys.count(key) > 1})
    if duplicates:
        problems.append(f"{filename}: duplicate Edge managed configuration keys: {duplicates}")

    expected = EDGE_BOOLEAN_SETTINGS | set(EDGE_STRING_SETTINGS)
    missing = sorted(expected - set(keys))
    unknown = sorted(set(keys) - expected)
    if missing:
        problems.append(f"{filename}: missing Edge managed configuration keys: {missing}")
    if unknown:
        problems.append(f"{filename}: unapproved Edge managed configuration keys: {unknown}")

    for item in settings:
        if not isinstance(item, dict):
            problems.append(f"{filename}: each managedProperty entry must be an object")
            continue
        key = item.get("key")
        value_fields = set(item) - {"key"}
        if key in EDGE_BOOLEAN_SETTINGS:
            if value_fields != {"valueBool"} or not isinstance(item.get("valueBool"), bool):
                problems.append(f"{filename}: {key} must contain one Boolean valueBool")
        elif key in EDGE_STRING_SETTINGS:
            if value_fields != {"valueString"} or item.get("valueString") not in EDGE_STRING_SETTINGS[key]:
                problems.append(f"{filename}: {key} has an invalid valueString")
    if not problems:
        print(f"  ok  {filename} embedded Edge payload  ({len(settings)} managed settings)")
    return problems


def check_android_tenant_tokens(filename, data):
    """Keep tenant overlays inside CIPP's policy lifecycle, not post-deploy scripts."""
    problems = []
    if filename == "02-compliance-android-fully-managed.json":
        expected = {
            "osMinimumVersion": "%androidminimumosversion%",
            "minAndroidSecurityPatchLevel": "%androidminimumsecuritypatchlevel%",
        }
        for key, value in expected.items():
            if data.get(key) != value:
                problems.append(f"{filename}: {key} must be the CIPP token {value}")
        actions = data.get("scheduledActionsForRule", [{}])[0].get(
            "scheduledActionConfigurations", []
        )
        notifications = [a for a in actions if a.get("actionType") == "notification"]
        if len(notifications) != 1:
            problems.append(f"{filename}: must contain exactly one notification action")
        elif (
            notifications[0].get("gracePeriodHours") != 24
            or notifications[0].get("notificationTemplateId")
            != "%androidcompliancenotificationtemplateid%"
        ):
            problems.append(
                f"{filename}: notification must run at 24 hours and use "
                "%androidcompliancenotificationtemplateid%"
            )
    elif filename == "30-android-device-restrictions.json":
        if data.get("factoryResetDeviceAdministratorEmails") != [
            "%androidfrprecoveryaccount%"
        ]:
            problems.append(
                f"{filename}: factoryResetDeviceAdministratorEmails must contain only "
                "%androidfrprecoveryaccount%"
            )
    return problems


def check_ios_policy_safety(filename, data):
    """Validate tenant tokens and support-sensitive Apple defaults."""
    problems = []
    if filename == "03-compliance-ios.json":
        if data.get("osMinimumVersion") != "%iosminimumosversion%":
            problems.append(
                f"{filename}: osMinimumVersion must be %iosminimumosversion%"
            )
        actions = data.get("scheduledActionsForRule", [{}])[0].get(
            "scheduledActionConfigurations", []
        )
        notifications = [a for a in actions if a.get("actionType") == "notification"]
        if len(notifications) != 1:
            problems.append(f"{filename}: must contain exactly one notification action")
        elif (
            notifications[0].get("gracePeriodHours") != 24
            or notifications[0].get("notificationTemplateId")
            != "%ioscompliancenotificationtemplateid%"
        ):
            problems.append(
                f"{filename}: notification must run at 24 hours and use "
                "%ioscompliancenotificationtemplateid%"
            )
    elif filename == "33-ios-supervised-device-restrictions.json":
        expected = {
            "accountBlockModification": True,
            "activationLockAllowWhenSupervised": False,
            "iCloudBlockBackup": True,
            "iCloudBlockManagedAppsSync": True,
            "iCloudBlockDocumentSync": True,
            "iCloudBlockPhotoLibrary": True,
            "iCloudBlockPhotoStreamSync": True,
            "iCloudBlockSharedPhotoStream": True,
            "iCloudPrivateRelayBlocked": True,
            "keychainBlockCloudSync": True,
            "airDropBlocked": True,
            "airDropForceUnmanagedDropTarget": True,
            "screenCaptureBlocked": False,
            "documentsBlockManagedDocumentsInUnmanagedApps": True,
            "documentsBlockUnmanagedDocumentsInManagedApps": False,
            "filesUsbDriveAccessBlocked": True,
            "hostPairingBlocked": True,
            "wiFiConnectOnlyToConfiguredNetworks": False,
            "wiFiConnectToAllowedNetworksOnlyForced": False,
        }
        for key, value in expected.items():
            if data.get(key) is not value:
                problems.append(f"{filename}: {key} must be {value}")
    return problems


def unwrap_cipp_native_template(filename, stored):
    """Return (Graph policy, problems) from a CIPP-native IntuneTemplate repo entity."""
    if not isinstance(stored, dict) or stored.get("PartitionKey") != "IntuneTemplate":
        return stored, []

    problems = []
    row_key = stored.get("RowKey")
    if row_key != EDGE_CIPP_TEMPLATE_GUID:
        problems.append(f"{filename}: native wrapper has an unexpected or missing RowKey")
    if stored.get("GUID") != row_key:
        problems.append(f"{filename}: native wrapper GUID and RowKey must match")
    try:
        record = stored.get("JSON")
        if isinstance(record, str):
            record = json.loads(record)
        if not isinstance(record, dict):
            raise TypeError("JSON must contain an object or encoded object")
        policy = record.get("RAWJson")
        if isinstance(policy, str):
            policy = json.loads(policy)
        if not isinstance(policy, dict):
            raise TypeError("RAWJson must contain an object or encoded object")
    except (TypeError, json.JSONDecodeError) as exc:
        return {}, problems + [f"{filename}: invalid native CIPP wrapper - {exc}"]

    if record.get("Type") != "AppConfiguration":
        problems.append(f"{filename}: native wrapper Type must be AppConfiguration")
    if record.get("GUID") != row_key:
        problems.append(f"{filename}: embedded template GUID must match RowKey")
    if record.get("Displayname") != policy.get("displayName"):
        problems.append(f"{filename}: wrapper and policy display names differ")
    if record.get("Description") != policy.get("description"):
        problems.append(f"{filename}: wrapper and policy descriptions differ")
    return policy, problems


def check_hand_authored(refresh=False, max_age_hours=24):
    problems = []
    property_owners = {}
    for filename, resource in sorted(HAND_AUTHORED.items()):
        path = HERE / filename
        if not path.exists():
            problems.append(f"{filename}: missing")
            continue
        stored = json.loads(path.read_text(encoding="utf-8"))
        data, wrapper_problems = unwrap_cipp_native_template(filename, stored)
        problems += wrapper_problems
        names, enums = parse_schema(schema(resource, refresh, max_age_hours))

        bad_names = [k for k in data if k not in names and k not in NOT_IN_PROPERTY_TABLE]
        bad_enums = [
            f"{k} = {v!r} (allowed: {', '.join(sorted(enums[k]))})"
            for k, v in data.items()
            if isinstance(v, str) and v and k in enums and v not in enums[k]
        ]

        checked = sum(1 for k, v in data.items() if isinstance(v, str) and k in enums)
        if bad_names or bad_enums:
            for b in bad_names:
                problems.append(f"{filename}: property '{b}' is not in the {resource} schema")
            for b in bad_enums:
                problems.append(f"{filename}: {b}")
        else:
            print(f"  ok  {filename}  ({len(data)} properties, {checked} enums verified)")
        problems += check_compliance_actions(filename, data)
        problems += check_edge_managed_configuration(filename, data)
        problems += check_android_tenant_tokens(filename, data)
        problems += check_ios_policy_safety(filename, data)

        for prop in set(data) - POLICY_IDENTITY_FIELDS:
            property_owners.setdefault((resource, prop), set()).add(filename)

    for (resource, prop), files in sorted(property_owners.items()):
        if len(files) > 1:
            problems.append(
                f"unexpected cross-policy property overlap for {resource}.{prop}: "
                f"{', '.join(sorted(files))}"
            )
    return problems


def iter_setting_instances(node):
    if isinstance(node, list):
        for value in node:
            yield from iter_setting_instances(value)
    elif isinstance(node, dict):
        if "settingDefinitionId" in node:
            yield node
        for value in node.values():
            yield from iter_setting_instances(value)


def check_generated(catalog):
    problems = []
    definitions = {item.get("id"): item for item in catalog}
    used_by = {}
    generated = set(
        p for p in HERE.glob("[12]*.json") if p.name not in HAND_AUTHORED
    )
    generated.add(HERE / "34-ios-managed-software-updates.json")
    generated = sorted(generated)
    for path in generated:
        raw = path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            problems.append(f"{path.name}: invalid JSON - {exc}")
            continue

        for needle, why in FORBIDDEN_IN_GENERATED:
            if needle in raw:
                problems.append(f"{path.name}: contains '{needle}' ({why}) - re-run build.py")

        missing = [k for k in ("name", "platforms", "technologies", "settings") if k not in data]
        if missing:
            problems.append(f"{path.name}: missing required field(s) {missing}")
        elif not data["settings"]:
            problems.append(f"{path.name}: settings array is empty")
        else:
            instances = list(iter_setting_instances(data["settings"]))
            ids = [item["settingDefinitionId"] for item in instances]
            duplicates = sorted({setting_id for setting_id in ids if ids.count(setting_id) > 1})
            if duplicates:
                problems.append(f"{path.name}: duplicate settingDefinitionId values: {duplicates}")

            for instance in instances:
                setting_id = instance["settingDefinitionId"]
                used_by.setdefault(setting_id, set()).add(path.name)
                definition = definitions.get(setting_id)
                if not definition:
                    problems.append(f"{path.name}: unknown current CIPP settingDefinitionId '{setting_id}'")
                    continue
                if "deprecated" in (definition.get("displayName") or "").lower():
                    problems.append(f"{path.name}: uses deprecated setting '{definition['displayName']}' ({setting_id})")

                choice = instance.get("choiceSettingValue")
                if isinstance(choice, dict) and isinstance(choice.get("value"), str):
                    options = definition.get("options") or []
                    if isinstance(options, dict):
                        options = [options]
                    allowed = {
                        option.get("id") for option in options if isinstance(option, dict)
                    }
                    if choice["value"] not in allowed:
                        problems.append(
                            f"{path.name}: invalid choice {choice['value']!r} for {setting_id}"
                        )

                simple = instance.get("simpleSettingValue")
                if isinstance(simple, dict):
                    value_type = simple.get("@odata.type", "")
                    value = simple.get("value")
                    if "IntegerSettingValue" in value_type and not isinstance(value, int):
                        problems.append(f"{path.name}: {setting_id} must have an integer value")
                    if "StringSettingValue" in value_type and not isinstance(value, str):
                        problems.append(f"{path.name}: {setting_id} must have a string value")

            if data.get("templateReference", {}).get("templateId"):
                missing_refs = [
                    setting["settingInstance"].get("settingDefinitionId")
                    for setting in data["settings"]
                    if not setting["settingInstance"].get("settingInstanceTemplateReference", {}).get(
                        "settingInstanceTemplateId"
                    )
                ]
                if missing_refs:
                    problems.append(
                        f"{path.name}: endpoint-security settings missing template references: {missing_refs}"
                    )

            print(f"  ok  {path.name}  ({len(instances)} settings, {data['platforms']})")

            if path.name == "34-ios-managed-software-updates.json":
                if data.get("technologies") != "mdm,appleRemoteManagement":
                    problems.append(
                        f"{path.name}: technologies must be mdm,appleRemoteManagement"
                    )
                by_id = {item["settingDefinitionId"]: item for item in instances}
                required = {
                    "ddm-latestsoftwareupdate_ddm-latestsoftwareupdate",
                    "ddm-latestsoftwareupdate_enforcelatestsoftwareupdateversion",
                    "ddm-latestsoftwareupdate_delayindays",
                    "ddm-latestsoftwareupdate_installtime",
                }
                missing = sorted(required - set(by_id))
                if missing:
                    problems.append(f"{path.name}: missing DDM update settings: {missing}")
                else:
                    enforce = by_id[
                        "ddm-latestsoftwareupdate_enforcelatestsoftwareupdateversion"
                    ].get("choiceSettingValue", {}).get("value")
                    delay = by_id["ddm-latestsoftwareupdate_delayindays"].get(
                        "simpleSettingValue", {}
                    ).get("value")
                    install_time = by_id["ddm-latestsoftwareupdate_installtime"].get(
                        "simpleSettingValue", {}
                    ).get("value")
                    if enforce != "ddm-latestsoftwareupdate_enforcelatestsoftwareupdateversion_0":
                        problems.append(f"{path.name}: latest-version enforcement is not enabled")
                    if delay != 7:
                        problems.append(f"{path.name}: enforcement delay must be seven days")
                    if install_time != "03:00":
                        problems.append(f"{path.name}: install time must be 03:00")

    allowed_overlap = {
        "11-win-sc-asr-rules-audit.json",
        "12-win-sc-asr-rules-enforced.json",
    }
    for setting_id, files in used_by.items():
        if len(files) > 1 and files != allowed_overlap:
            problems.append(
                f"unexpected cross-policy overlap for {setting_id}: {', '.join(sorted(files))}"
            )
    return problems


def check_manifest_and_tokens():
    problems = []
    manifest_path = HERE / "manifest.cipp"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"manifest.cipp: cannot read valid JSON - {exc}"]

    entries = manifest.get("policies")
    if not isinstance(entries, list):
        return ["manifest.cipp: policies must be an array"]

    listed = [entry.get("file") for entry in entries if isinstance(entry, dict)]
    duplicates = sorted({name for name in listed if name and listed.count(name) > 1})
    if duplicates:
        problems.append(f"manifest.cipp: duplicate policy entries: {duplicates}")

    actual = {
        path.relative_to(HERE).as_posix()
        for path in HERE.rglob("[0-9][0-9]-*.json")
        if not any(part.startswith(".") for part in path.relative_to(HERE).parts)
    }
    listed_set = {name for name in listed if isinstance(name, str)}
    missing = sorted(actual - listed_set)
    orphaned = sorted(listed_set - actual)
    if missing:
        problems.append(f"manifest.cipp: policy files not listed: {missing}")
    if orphaned:
        problems.append(f"manifest.cipp: entries without policy files: {orphaned}")

    allowed_types = {"AppConfiguration", "Catalog", "Device", "deviceCompliancePolicies"}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(f"manifest.cipp: entry {index} is not an object")
            continue
        if entry.get("templateType") not in allowed_types:
            problems.append(
                f"manifest.cipp: {entry.get('file')}: unsupported templateType {entry.get('templateType')!r}"
            )
        if entry.get("assignOrder") not in {1, 2, 3, 4}:
            problems.append(
                f"manifest.cipp: {entry.get('file')}: assignOrder must be 1, 2, 3, or 4"
            )

    token_pattern = re.compile(r"%([a-zA-Z][a-zA-Z0-9_-]*)%")
    for path in sorted(
        path for path in HERE.rglob("[0-9][0-9]-*.json")
        if not any(part.startswith(".") for part in path.relative_to(HERE).parts)
    ):
        tokens = {match.lower() for match in token_pattern.findall(path.read_text(encoding="utf-8"))}
        unknown = sorted(tokens - ALLOWED_CIPP_TOKENS - PASSTHROUGH_PERCENT_VARS)
        if unknown:
            problems.append(
                f"{path.relative_to(HERE).as_posix()}: unapproved CIPP replacement token(s): {unknown}"
            )

    if not problems:
        print(f"  ok  manifest.cipp  ({len(actual)} policies, no orphans or duplicate entries)")
        print(f"  ok  CIPP replacement tokens  ({', '.join(sorted(ALLOWED_CIPP_TOKENS))})")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="force fresh Microsoft and CIPP schema data")
    parser.add_argument(
        "--max-cache-age-hours", type=float, default=24,
        help="refresh cached schema data older than this many hours (default: 24)",
    )
    args = parser.parse_args()

    print("Hand-authored policies (validated against Graph beta schemas):")
    problems = check_hand_authored(args.refresh, args.max_cache_age_hours)
    print("\nGenerated Settings Catalog policies:")
    catalog = cipp_catalog(args.refresh, args.max_cache_age_hours)
    print(f"  current CIPP catalog: {len(catalog)} definitions")
    problems += check_generated(catalog)

    print("\nBundle integrity:")
    problems += check_manifest_and_tokens()

    if problems:
        print(f"\n{len(problems)} problem(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("\nAll policies valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
