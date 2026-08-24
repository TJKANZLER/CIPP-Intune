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

Run:  python3 validate.py
      python3 validate.py --refresh   # force fresh Microsoft/CIPP schema data

Schemas are fetched from the public microsoft-graph-docs-contrib repo and cached in
.schema-cache/. Delete that directory to force a refresh.
"""

import argparse
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
}

ALLOWED_CIPP_TOKENS = {"androidwallpaperurl"}
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


def check_hand_authored(refresh=False, max_age_hours=24):
    problems = []
    property_owners = {}
    for filename, resource in sorted(HAND_AUTHORED.items()):
        path = HERE / filename
        if not path.exists():
            problems.append(f"{filename}: missing")
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
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
    generated = sorted(
        p for p in HERE.glob("[12]*.json") if p.name not in HAND_AUTHORED
    )
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
                    allowed = {option.get("id") for option in definition.get("options") or []}
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

    actual = {path.name for path in HERE.glob("[0-9][0-9]-*.json")}
    listed_set = {name for name in listed if isinstance(name, str)}
    missing = sorted(actual - listed_set)
    orphaned = sorted(listed_set - actual)
    if missing:
        problems.append(f"manifest.cipp: policy files not listed: {missing}")
    if orphaned:
        problems.append(f"manifest.cipp: entries without policy files: {orphaned}")

    allowed_types = {"Catalog", "Device", "deviceCompliancePolicies"}
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
    for path in sorted(HERE.glob("[0-9][0-9]-*.json")):
        tokens = {match.lower() for match in token_pattern.findall(path.read_text(encoding="utf-8"))}
        unknown = sorted(tokens - ALLOWED_CIPP_TOKENS - PASSTHROUGH_PERCENT_VARS)
        if unknown:
            problems.append(f"{path.name}: unapproved CIPP replacement token(s): {unknown}")

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
