# Repeatable Android fully managed deployment

Use CIPP for reusable policy content and scheduled drift remediation. Use the
bootstrap script for tenant-specific objects that CIPP templates cannot safely
carry, especially groups, app object IDs, enrollment targeting and Wi-Fi secrets.

## CIPP-owned configuration

Import these four templates from the community repository:

1. `Baseline - Android Enterprise (Fully Managed) - Device Restrictions`
2. `Baseline - Android Enterprise (Fully Managed) - Launcher and Branding`
3. `Baseline - Android Enterprise - Microsoft Edge`
4. `Baseline - Android Enterprise (Fully Managed) - Compliance`

Create these tenant-scoped CIPP variables before deployment:

- `androidwallpaperurl` — direct public HTTPS wallpaper URL
- `androidedgeappid` — tenant Intune mobile-app object ID for Edge
- `androidminimumosversion` — supported Android floor, for example `14`
- `androidminimumsecuritypatchlevel` — patch floor in `YYYY-MM-DD` format
- `androidfrprecoveryaccount` — tested corporate Google recovery account
- `androidcompliancenotificationtemplateid` — tenant Intune compliance notification template GUID

Add the
first three templates to a CIPP package named `Android Fully Managed -
Configuration`. Put compliance in a separate package named `Android Fully Managed
- Compliance` so it cannot be enabled before configuration is healthy.

Create a CIPP Standards template for the configuration package:

- Standard: **Intune Template**
- Package: `Android Fully Managed - Configuration`
- Action: **Remediate**
- Assignment: **Custom group**
- Group: the tenant's Android pilot group
- Verify assignments: **On**
- Run manually during the pilot. Enable the schedule after validation.

Create the compliance Standards entry separately and run it only after a pilot
device is configured, updated and healthy. CIPP Standards compare the deployed
policy to the saved template and can update drift on later runs; a one-off Deploy
Policy action does not provide that lifecycle.

## Tenant bootstrap

Copy `android-fully-managed.example.json` outside the public repository and fill
in the tenant names, compliance floors, FRP recovery account, Wi-Fi name and app
matrix. Never add a Wi-Fi PSK to the JSON.

```powershell
# Read-only plan
./automation/Invoke-AndroidFullyManagedTenant.ps1 -ConfigPath /path/to/tenant.json

# Apply the reviewed plan. The Wi-Fi PSK is requested securely if needed.
./automation/Invoke-AndroidFullyManagedTenant.ps1 -ConfigPath /path/to/tenant.json -Apply

# Explicit key rotation; ordinary reruns leave the existing key untouched.
./automation/Invoke-AndroidFullyManagedTenant.ps1 -ConfigPath /path/to/tenant.json -Apply -RotateWifiKey
```

The script is safe to rerun. It discovers objects by exact display name, refuses
duplicates and verifies newly created assignments. Managed Google Play apps and a
default corporate-owned fully managed enrollment profile remain manual
prerequisites because their approval/token flows require an administrator.

## Per-tenant manual decisions

- Approve the required applications in Managed Google Play, then sync Intune.
- Create/export the fully managed enrollment QR or configure Zero-touch/Knox.
- Decide who belongs in the Drivers and Office groups.
- Pilot Conditional Access in report-only before requiring compliant devices.
- Keep the Wi-Fi PSK in the password manager, not CIPP variables or Git.
- Confirm the FRP recovery Google account is controlled and tested.

---

# Repeatable iOS/iPadOS corporate supervised deployment

Use Apple Business Manager Automated Device Enrollment (ADE), supervision, user
affinity and Setup Assistant with modern authentication. Apple setup is not an
Android token-equivalent workflow: APNs, ADE and Apps and Books are separate Apple
prerequisites with separate annual renewals.

## CIPP-owned iOS configuration

Import these templates from the community repository:

1. `Baseline - iOS/iPadOS (Supervised) - Device Restrictions`
2. `Baseline - iOS/iPadOS (Supervised) - Managed Software Updates`
3. `Baseline - iOS/iPadOS - Compliance`

Define these tenant-scoped CIPP variables before deploying compliance:

- `iosminimumosversion` — the floor supported by the customer-approved hardware
- `ioscompliancenotificationtemplateid` — an existing Intune compliance notification GUID

Put the first two templates in `iOS Corporate - Configuration`. Put compliance in
`iOS Corporate - Compliance`. Use CIPP Standards with **Remediate**, the static iOS
pilot group, and **Verify assignments**. Keep the Standards schedule disabled; run
configuration manually, validate a real ADE-enrolled device, and only then run the
compliance package manually.

## Apple and tenant bootstrap

Copy `ios-corporate.example.json` outside the public repository. Fill in names only;
never put APNs certificate material, ADE `.p7m` files, Apps and Books token files,
Wi-Fi keys or enrollment payloads in JSON or Git.

```powershell
# Read-only plan
./automation/Invoke-IosCorporateTenant.ps1 -ConfigPath /path/to/tenant.json

# Apply only after APNs, ADE and Apps and Books report healthy
./automation/Invoke-IosCorporateTenant.ps1 -ConfigPath /path/to/tenant.json -Apply

# Deliberate Wi-Fi key rotation
./automation/Invoke-IosCorporateTenant.ps1 -ConfigPath /path/to/tenant.json -Apply -RotateWifiKey
```

The script creates only missing static groups, a correctly typed iOS Basic WPA2
Personal Wi-Fi profile and reviewed app assignments. It refuses duplicate display
names, verifies every write, never changes CIPP-owned policy content, and stops
before writing when an Apple prerequisite is absent. ADE token upload, Apple device
assignment, Apps and Books token upload/app acquisition, Company Portal selection
in the enrollment profile, and optional wallpaper image upload remain manual Apple
or Intune portal steps.

Run the deep audit at every gate:

```powershell
./automation/Test-IosCorporateTenant.ps1 -ConfigPath /path/to/tenant.json
```

Set the tenant JSON `RolloutWave` to `Prerequisites`, `Configuration`, then
`Compliance` as each gate is approved. The audit changes its assignment and device
expectations accordingly and exits non-zero for failures or unresolved decisions.
