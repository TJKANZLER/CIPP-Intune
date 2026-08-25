<#
.SYNOPSIS
    Completes the tenant-specific parts of the CIPP Android fully managed bundle.

.DESCRIPTION
    CIPP remains the source of truth for the four reusable policy definitions and,
    preferably, their assignments through a CIPP Standards template. This script
    handles the objects that are tenant-specific or contain secrets: security
    groups, enrollment-time grouping, compliance floors, FRP recovery, a WPA/WPA2
    Personal Wi-Fi profile, and Managed Google Play app assignments.

    The script is read-only unless -Apply is supplied. It is idempotent: existing
    groups, assignments and profiles are reused, and duplicate display names stop
    the run rather than being guessed at. The Wi-Fi PSK is prompted as a secure
    string only when a profile must be created or -RotateWifiKey is used; it is
    never read from or written to the JSON configuration.

    Managed Google Play applications and the default fully managed enrollment
    profile must already exist. App approval is intentionally not automated because
    it requires the Managed Google Play approval flow. CIPP policy assignment is
    intentionally not duplicated here; use a CIPP Standards template/package.

.EXAMPLE
    ./automation/Invoke-AndroidFullyManagedTenant.ps1 -ConfigPath ./tenant.json
    Produces a plan and changes nothing.

.EXAMPLE
    ./automation/Invoke-AndroidFullyManagedTenant.ps1 -ConfigPath ./tenant.json -Apply
    Applies missing tenant-specific configuration and verifies each write.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [switch]$Apply,
    [switch]$RotateWifiKey
)

$ErrorActionPreference = 'Stop'
$graphRoot = 'https://graph.microsoft.com/beta'
$requiredScopes = @(
    'Group.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All',
    'DeviceManagementApps.ReadWrite.All'
)

function Invoke-GraphJson {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body
    )
    if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 30 -Compress
        return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $json -ContentType 'application/json'
    }
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    do {
        $page = Invoke-GraphJson -Method GET -Uri $Uri
        foreach ($item in @($page.value)) { $items.Add($item) }
        $Uri = $page.'@odata.nextLink'
    } while ($Uri)
    return @($items)
}

function Escape-ODataString {
    param([Parameter(Mandatory)][string]$Value)
    return $Value.Replace("'", "''")
}

function Add-Outcome {
    param([string]$Area, [string]$Item, [string]$State, [string]$Detail)
    $script:outcomes.Add([pscustomobject]@{ Area = $Area; Item = $Item; State = $State; Detail = $Detail })
}

function Get-OneByDisplayName {
    param([Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][string]$Kind)
    $matches = @($Items | Where-Object displayName -eq $DisplayName)
    if ($matches.Count -gt 1) { throw "$Kind '$DisplayName' has $($matches.Count) matches. Resolve duplicates before rerunning." }
    return $matches | Select-Object -First 1
}

function Get-OrCreateSecurityGroup {
    param([Parameter(Mandatory)][string]$DisplayName)
    $escaped = Escape-ODataString $DisplayName
    $matches = @(Get-GraphCollection "$graphRoot/groups?`$filter=displayName eq '$escaped'&`$select=id,displayName,securityEnabled,mailEnabled,groupTypes")
    if ($matches.Count -gt 1) { throw "Security group '$DisplayName' has $($matches.Count) matches." }
    if ($matches.Count -eq 1) {
        $group = $matches[0]
        if (-not $group.securityEnabled -or $group.mailEnabled -or $group.groupTypes -contains 'DynamicMembership') {
            throw "'$DisplayName' exists but is not a static, non-mail-enabled security group."
        }
        Add-Outcome 'Groups' $DisplayName 'Present' $group.id
        return $group
    }
    if (-not $Apply) {
        Add-Outcome 'Groups' $DisplayName 'Would create' 'Static security group'
        return $null
    }
    $mailNickname = (($DisplayName -replace '[^A-Za-z0-9]', '') + ([guid]::NewGuid().ToString('N').Substring(0, 6))).ToLowerInvariant()
    $group = Invoke-GraphJson -Method POST -Uri "$graphRoot/groups" -Body @{
        displayName     = $DisplayName
        description     = 'Intune Android Enterprise assignment group managed by the Android fully managed bootstrap.'
        mailEnabled     = $false
        mailNickname    = $mailNickname
        securityEnabled = $true
        groupTypes      = @()
    }
    Add-Outcome 'Groups' $DisplayName 'Created' $group.id
    return $group
}

function Ensure-GroupAssignment {
    param(
        [Parameter(Mandatory)][string]$AssignmentsUri,
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][ValidateSet('Policy', 'App')][string]$Kind,
        [ValidateSet('available', 'required')][string]$Intent,
        [Parameter(Mandatory)][string]$Label
    )
    $assignments = @(Get-GraphCollection $AssignmentsUri)
    $existing = @($assignments | Where-Object {
        $_.target.groupId -eq $GroupId -and ($Kind -eq 'Policy' -or $_.intent -eq $Intent)
    })
    if ($existing.Count -gt 0) {
        Add-Outcome 'Assignments' $Label 'Present' $(if ($Intent) { $Intent } else { 'assigned' })
        return
    }
    if (-not $Apply) {
        Add-Outcome 'Assignments' $Label 'Would add' $(if ($Intent) { $Intent } else { 'assigned' })
        return
    }
    if ($Kind -eq 'App') {
        $body = @{
            '@odata.type' = '#microsoft.graph.mobileAppAssignment'
            intent = $Intent
            target = @{
                '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                groupId = $GroupId
            }
        }
    } else {
        $body = @{
            '@odata.type' = '#microsoft.graph.deviceConfigurationAssignment'
            target = @{
                '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                groupId = $GroupId
            }
        }
    }
    Invoke-GraphJson -Method POST -Uri $AssignmentsUri -Body $body | Out-Null
    $verified = @(Get-GraphCollection $AssignmentsUri | Where-Object {
        $_.target.groupId -eq $GroupId -and ($Kind -eq 'Policy' -or $_.intent -eq $Intent)
    })
    if ($verified.Count -eq 0) { throw "Assignment verification failed for '$Label'." }
    Add-Outcome 'Assignments' $Label 'Added' $(if ($Intent) { $Intent } else { 'assigned' })
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration not found: $ConfigPath" }
$config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
foreach ($required in @('TenantId', 'PilotGroupName', 'DriversGroupName', 'OfficeGroupName', 'EnrollmentProfileName', 'DeviceNameTemplate')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.$required)) { throw "Configuration is missing '$required'." }
}
foreach ($requiredPolicy in @('Compliance', 'Restrictions', 'Launcher', 'Edge')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.Policies.$requiredPolicy)) { throw "Configuration is missing 'Policies.$requiredPolicy'." }
}
foreach ($requiredCompliance in @('MinimumAndroidVersion', 'MinimumSecurityPatchLevel')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.Compliance.$requiredCompliance)) { throw "Configuration is missing 'Compliance.$requiredCompliance'." }
}
foreach ($requiredWifi in @('DisplayName', 'Ssid')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.Wifi.$requiredWifi)) { throw "Configuration is missing 'Wifi.$requiredWifi'." }
}
if ($RotateWifiKey -and -not $Apply) { throw '-RotateWifiKey requires -Apply.' }

$context = Get-MgContext
$mustConnect = -not $context -or @($requiredScopes | Where-Object { $_ -notin $context.Scopes }).Count -gt 0
if (-not $mustConnect) {
    try { Invoke-MgGraphRequest -Method GET -Uri "$graphRoot/deviceManagement/deviceConfigurations?`$top=1" | Out-Null } catch { $mustConnect = $true }
}
if ($mustConnect) {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -TenantId $config.TenantId -Scopes $requiredScopes -ContextScope Process -NoWelcome
}

$outcomes = [System.Collections.Generic.List[object]]::new()
Write-Host "Mode: $(if ($Apply) { 'APPLY' } else { 'PLAN (no changes)' })" -ForegroundColor Cyan

$pilot = Get-OrCreateSecurityGroup $config.PilotGroupName
$drivers = Get-OrCreateSecurityGroup $config.DriversGroupName
$office = Get-OrCreateSecurityGroup $config.OfficeGroupName
$groupsByKey = @{ Pilot = $pilot; Drivers = $drivers; Office = $office }

# The enrollment profile contains the QR/token material and is therefore created
# deliberately in Intune. Once present, its naming and enrollment-time group are
# safe to make repeatable here.
$enrollmentProfiles = @(Get-GraphCollection "$graphRoot/deviceManagement/androidDeviceOwnerEnrollmentProfiles")
$enrollment = Get-OneByDisplayName $enrollmentProfiles $config.EnrollmentProfileName 'Enrollment profile'
if (-not $enrollment) {
    Add-Outcome 'Enrollment' $config.EnrollmentProfileName 'Manual prerequisite' 'Create a default corporate-owned fully managed token in Intune'
} elseif ($enrollment.enrollmentMode -ne 'corporateOwnedFullyManaged' -or $enrollment.enrollmentTokenType -ne 'default') {
    throw "Enrollment profile '$($config.EnrollmentProfileName)' is not a default corporate-owned fully managed profile."
} else {
    if ($enrollment.deviceNameTemplate -ne $config.DeviceNameTemplate) {
        if ($Apply) {
            Invoke-GraphJson -Method PATCH -Uri "$graphRoot/deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($enrollment.id)" -Body @{
                '@odata.type' = '#microsoft.graph.androidDeviceOwnerEnrollmentProfile'
                deviceNameTemplate = $config.DeviceNameTemplate
            } | Out-Null
            Add-Outcome 'Enrollment' 'Device naming' 'Updated' $config.DeviceNameTemplate
        } else { Add-Outcome 'Enrollment' 'Device naming' 'Would update' $config.DeviceNameTemplate }
    } else { Add-Outcome 'Enrollment' 'Device naming' 'Present' $config.DeviceNameTemplate }

    if ($pilot) {
        $targetResponse = Invoke-GraphJson -Method POST -Uri "$graphRoot/deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($enrollment.id)/retrieveEnrollmentTimeDeviceMembershipTarget"
        $targetResult = if ($null -ne $targetResponse.value) { $targetResponse.value } else { $targetResponse }
        $targets = @($targetResult.enrollmentTimeDeviceMembershipTargetValidationStatuses)
        $targetPresent = @($targets | Where-Object { $_.targetId -eq $pilot.id -and $_.validationSucceeded }).Count -gt 0
        if ($targetPresent) {
            Add-Outcome 'Enrollment' 'Enrollment-time pilot group' 'Present' $pilot.id
        } elseif ($Apply) {
            $setResponse = Invoke-GraphJson -Method POST -Uri "$graphRoot/deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($enrollment.id)/setEnrollmentTimeDeviceMembershipTarget" -Body @{
                enrollmentTimeDeviceMembershipTargets = @(@{
                    '@odata.type' = '#microsoft.graph.enrollmentTimeDeviceMembershipTarget'
                    targetType = 'staticSecurityGroup'
                    targetId = $pilot.id
                })
            }
            $setResult = if ($null -ne $setResponse.value) { $setResponse.value } else { $setResponse }
            if (-not $setResult.validationSucceeded) { throw 'Intune rejected the enrollment-time pilot group.' }
            Add-Outcome 'Enrollment' 'Enrollment-time pilot group' 'Set' $pilot.id
        } else { Add-Outcome 'Enrollment' 'Enrollment-time pilot group' 'Would set' $pilot.id }
    }
}

$deviceConfigurations = @(Get-GraphCollection "$graphRoot/deviceManagement/deviceConfigurations")
$compliancePolicies = @(Get-GraphCollection "$graphRoot/deviceManagement/deviceCompliancePolicies")
$appConfigurations = @(Get-GraphCollection "$graphRoot/deviceAppManagement/mobileAppConfigurations")
$restrictionPolicy = Get-OneByDisplayName $deviceConfigurations $config.Policies.Restrictions 'Device configuration'
$launcherPolicy = Get-OneByDisplayName $deviceConfigurations $config.Policies.Launcher 'Device configuration'
$compliancePolicy = Get-OneByDisplayName $compliancePolicies $config.Policies.Compliance 'Compliance policy'
$edgePolicy = Get-OneByDisplayName $appConfigurations $config.Policies.Edge 'App configuration'
foreach ($policyCheck in @(
    @{ Label = 'Restrictions'; Value = $restrictionPolicy; Uri = "$graphRoot/deviceManagement/deviceConfigurations" },
    @{ Label = 'Launcher'; Value = $launcherPolicy; Uri = "$graphRoot/deviceManagement/deviceConfigurations" },
    @{ Label = 'Compliance'; Value = $compliancePolicy; Uri = "$graphRoot/deviceManagement/deviceCompliancePolicies" },
    @{ Label = 'Edge'; Value = $edgePolicy; Uri = "$graphRoot/deviceAppManagement/mobileAppConfigurations" }
)) {
    Add-Outcome 'CIPP policies' $policyCheck.Label $(if ($policyCheck.Value) { 'Present' } else { 'Missing' }) $(if ($policyCheck.Value) { $policyCheck.Value.id } else { 'Deploy through the CIPP Android standards package' })
    if ($policyCheck.Value -and $pilot) {
        $policyAssignments = @(Get-GraphCollection "$($policyCheck.Uri)/$($policyCheck.Value.id)/assignments")
        $assigned = $policyAssignments.target.groupId -contains $pilot.id
        Add-Outcome 'CIPP assignments' "$($policyCheck.Label) -> Pilot" $(if ($assigned) { 'Present' } else { 'Missing' }) $(if ($assigned) { $pilot.id } else { 'Enable assignment verification/remediation in the CIPP Standards template' })
    }
}

if ($compliancePolicy) {
    $wantedAndroid = [string]$config.Compliance.MinimumAndroidVersion
    $wantedPatch = [string]$config.Compliance.MinimumSecurityPatchLevel
    $needsPatch = $compliancePolicy.osMinimumVersion -ne $wantedAndroid -or $compliancePolicy.minAndroidSecurityPatchLevel -ne $wantedPatch
    if ($needsPatch -and $Apply) {
        Invoke-GraphJson -Method PATCH -Uri "$graphRoot/deviceManagement/deviceCompliancePolicies/$($compliancePolicy.id)" -Body @{
            '@odata.type' = '#microsoft.graph.androidDeviceOwnerCompliancePolicy'
            osMinimumVersion = $wantedAndroid
            minAndroidSecurityPatchLevel = $wantedPatch
        } | Out-Null
        Add-Outcome 'Compliance' 'OS and patch floors' 'Updated' "Android $wantedAndroid; patch $wantedPatch"
    } elseif ($needsPatch) {
        Add-Outcome 'Compliance' 'OS and patch floors' 'Would update' "Android $wantedAndroid; patch $wantedPatch"
    } else { Add-Outcome 'Compliance' 'OS and patch floors' 'Present' "Android $wantedAndroid; patch $wantedPatch" }

    $expandedCompliance = Invoke-GraphJson -Method GET -Uri "$graphRoot/deviceManagement/deviceCompliancePolicies/$($compliancePolicy.id)?`$expand=scheduledActionsForRule(`$expand=scheduledActionConfigurations)"
    $scheduledActions = @($expandedCompliance.scheduledActionsForRule | ForEach-Object { $_.scheduledActionConfigurations })
    $blockAtSevenDays = @($scheduledActions | Where-Object { $_.actionType -eq 'block' -and [int]$_.gracePeriodHours -eq 168 }).Count -gt 0
    $notificationId = [string]$config.Compliance.NotificationTemplateId
    $notificationAtOneDay = -not [string]::IsNullOrWhiteSpace($notificationId) -and @($scheduledActions | Where-Object {
        $_.actionType -eq 'notification' -and [int]$_.gracePeriodHours -eq 24 -and $_.notificationTemplateId -eq $notificationId
    }).Count -gt 0
    if (-not $blockAtSevenDays -or (-not [string]::IsNullOrWhiteSpace($notificationId) -and -not $notificationAtOneDay)) {
        if ($Apply) {
            $wantedActions = [System.Collections.Generic.List[object]]::new()
            $wantedActions.Add(@{
                '@odata.type' = '#microsoft.graph.deviceComplianceActionItem'
                gracePeriodHours = 168
                actionType = 'block'
                notificationTemplateId = '00000000-0000-0000-0000-000000000000'
                notificationMessageCCList = @()
            })
            if (-not [string]::IsNullOrWhiteSpace($notificationId)) {
                $wantedActions.Add(@{
                    '@odata.type' = '#microsoft.graph.deviceComplianceActionItem'
                    gracePeriodHours = 24
                    actionType = 'notification'
                    notificationTemplateId = $notificationId
                    notificationMessageCCList = @()
                })
            }
            Invoke-GraphJson -Method POST -Uri "$graphRoot/deviceManagement/deviceCompliancePolicies/$($compliancePolicy.id)/scheduleActionsForRules" -Body @{
                deviceComplianceScheduledActionForRules = @(@{
                    '@odata.type' = '#microsoft.graph.deviceComplianceScheduledActionForRule'
                    ruleName = 'PasswordRequired'
                    scheduledActionConfigurations = @($wantedActions)
                })
            } | Out-Null
            Add-Outcome 'Compliance' 'Remediation actions' 'Updated' $(if ($notificationId) { 'Notify at 24h; block at 168h' } else { 'Block at 168h' })
        } else {
            Add-Outcome 'Compliance' 'Remediation actions' 'Would update' $(if ($notificationId) { 'Notify at 24h; block at 168h' } else { 'Block at 168h' })
        }
    } else {
        Add-Outcome 'Compliance' 'Remediation actions' 'Present' $(if ($notificationId) { 'Notify at 24h; block at 168h' } else { 'Block at 168h' })
    }
}

if ($restrictionPolicy) {
    $frp = [string]$config.FactoryResetRecoveryAccount
    $currentFrp = @($restrictionPolicy.factoryResetDeviceAdministratorEmails)
    if ($currentFrp -contains $frp) {
        Add-Outcome 'Restrictions' 'FRP recovery account' 'Present' $frp
    } elseif ($Apply) {
        Invoke-GraphJson -Method PATCH -Uri "$graphRoot/deviceManagement/deviceConfigurations/$($restrictionPolicy.id)" -Body @{
            '@odata.type' = '#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration'
            factoryResetDeviceAdministratorEmails = @($frp)
        } | Out-Null
        Add-Outcome 'Restrictions' 'FRP recovery account' 'Updated' $frp
    } else { Add-Outcome 'Restrictions' 'FRP recovery account' 'Would update' $frp }
}

# The key is deliberately absent from configuration and output. Existing keys are
# left untouched unless an operator explicitly requests rotation.
$wifiName = [string]$config.Wifi.DisplayName
$wifi = Get-OneByDisplayName $deviceConfigurations $wifiName 'Wi-Fi profile'
$needsWifiKey = -not $wifi -or $RotateWifiKey
$plainPsk = $null
$securePsk = $null
$bstr = [IntPtr]::Zero
try {
    if ($needsWifiKey -and $Apply) {
        $securePsk = Read-Host "Pre-shared key for SSID '$($config.Wifi.Ssid)'" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePsk)
        $plainPsk = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ([string]::IsNullOrWhiteSpace($plainPsk) -or $plainPsk.Length -lt 8) { throw 'The Wi-Fi PSK must be at least eight characters.' }
    }
    if ($wifi -and $wifi.'@odata.type' -ne '#microsoft.graph.androidDeviceOwnerWiFiConfiguration') {
        throw "'$wifiName' exists but is not a Basic Android Device Owner Wi-Fi profile."
    }
    $wifiBody = @{
        '@odata.type' = '#microsoft.graph.androidDeviceOwnerWiFiConfiguration'
        displayName = $wifiName
        description = 'Tenant-specific Android fully managed Wi-Fi; key is maintained outside the CIPP template repository.'
        roleScopeTagIds = @('0')
        networkName = [string]$config.Wifi.Ssid
        ssid = [string]$config.Wifi.Ssid
        connectAutomatically = $true
        connectWhenNetworkNameIsHidden = [bool]$config.Wifi.Hidden
        wiFiSecurityType = 'wpaPersonal'
        proxySettings = 'none'
        macAddressRandomizationMode = 'automatic'
    }
    if ($needsWifiKey -and $Apply) {
        $wifiBody.preSharedKey = $plainPsk
        $wifiBody.preSharedKeyIsSet = $true
    }
    if (-not $wifi) {
        if ($Apply) {
            $wifi = Invoke-GraphJson -Method POST -Uri "$graphRoot/deviceManagement/deviceConfigurations" -Body $wifiBody
            Add-Outcome 'Wi-Fi' $wifiName 'Created' "WPA/WPA2 Personal; auto-connect; $($config.Wifi.Ssid)"
        } else { Add-Outcome 'Wi-Fi' $wifiName 'Would create' 'Secure PSK prompt required during apply' }
    } elseif ($RotateWifiKey) {
        Invoke-GraphJson -Method PATCH -Uri "$graphRoot/deviceManagement/deviceConfigurations/$($wifi.id)" -Body $wifiBody | Out-Null
        Add-Outcome 'Wi-Fi' $wifiName 'Updated' 'Settings and PSK rotated'
    } else {
        $correct = $wifi.wiFiSecurityType -eq 'wpaPersonal' -and [bool]$wifi.connectAutomatically -and $wifi.ssid -eq [string]$config.Wifi.Ssid
        Add-Outcome 'Wi-Fi' $wifiName $(if ($correct) { 'Present' } else { 'Mismatch' }) "$($wifi.wiFiSecurityType); auto=$($wifi.connectAutomatically); SSID=$($wifi.ssid)"
    }
} finally {
    $plainPsk = $null
    $securePsk = $null
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
if ($wifi -and $pilot) {
    Ensure-GroupAssignment -AssignmentsUri "$graphRoot/deviceManagement/deviceConfigurations/$($wifi.id)/assignments" -GroupId $pilot.id -Kind Policy -Label "$wifiName -> Pilot"
}

$apps = @(Get-GraphCollection "$graphRoot/deviceAppManagement/mobileApps")
foreach ($wanted in @($config.Apps)) {
    if ($wanted.Group -notin @('Drivers', 'Office')) { throw "App '$($wanted.DisplayName)' has invalid Group '$($wanted.Group)'." }
    if ($wanted.Intent -notin @('required', 'available')) { throw "App '$($wanted.DisplayName)' has invalid Intent '$($wanted.Intent)'." }
    $app = Get-OneByDisplayName $apps $wanted.DisplayName 'Managed Google Play app'
    if (-not $app) {
        Add-Outcome 'Apps' $wanted.DisplayName 'Manual prerequisite' 'Approve in Managed Google Play and sync Intune'
        continue
    }
    $targetGroup = $groupsByKey[$wanted.Group]
    if (-not $targetGroup) {
        Add-Outcome 'Apps' "$($wanted.DisplayName) -> $($wanted.Group)" 'Waiting' 'Target group will be created during apply'
        continue
    }
    Ensure-GroupAssignment -AssignmentsUri "$graphRoot/deviceAppManagement/mobileApps/$($app.id)/assignments" -GroupId $targetGroup.id -Kind App -Intent $wanted.Intent -Label "$($wanted.DisplayName) -> $($wanted.Group)"
}

Write-Host ''
$outcomes | Format-Table Area, Item, State, Detail -Wrap -AutoSize
$manual = @($outcomes | Where-Object State -in @('Missing', 'Mismatch', 'Manual prerequisite', 'Waiting'))
Write-Host "`nCompleted: $($outcomes.Count) checks; $($manual.Count) item(s) require attention." -ForegroundColor $(if ($manual.Count) { 'Yellow' } else { 'Green' })
if (-not $Apply) { Write-Host 'No changes were made. Re-run with -Apply after reviewing the plan.' -ForegroundColor Cyan }
if ($manual.Count) { exit 1 }
