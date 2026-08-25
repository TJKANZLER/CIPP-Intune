<#
.SYNOPSIS
    Plans or applies tenant-specific Apple corporate-device bootstrap objects.

.DESCRIPTION
    Reusable iOS/iPadOS policy content and its lifecycle remain owned by CIPP
    templates and CIPP Standards. This script validates the Apple MDM push
    certificate, Apple Business Manager ADE token, Apps and Books token, ADE
    profile, Company Portal VPP association, exact live policy types and pilot
    assignments. It creates only missing static groups, an optional supervised
    iOS/iPadOS wallpaper profile, an iOS Basic WPA2 Personal Wi-Fi profile, and
    reviewed Apps and Books assignments.

    Read-only is the default. -Apply is required for any change. Apple token files,
    certificate material and enrollment payloads are never read or printed. The
    Wi-Fi PSK is requested as a SecureString only when creating or deliberately
    rotating the profile.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [switch]$Apply,
    [switch]$RotateWifiKey,
    [switch]$ComplianceWave
)

$ErrorActionPreference = 'Stop'
$graphRoot = 'https://graph.microsoft.com/beta'
$requiredScopes = @(
    'Group.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All',
    'DeviceManagementApps.ReadWrite.All',
    'DeviceManagementServiceConfig.ReadWrite.All',
    'DeviceManagementManagedDevices.Read.All',
    'Policy.Read.All'
)

function Invoke-GraphJson {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body
    )
    if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 40 -Compress
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

function Add-Outcome {
    param([string]$Area, [string]$Item, [string]$State, [string]$Detail)
    $script:outcomes.Add([pscustomobject]@{ Area = $Area; Item = $Item; State = $State; Detail = $Detail })
}

function Get-OneByDisplayName {
    param([object[]]$Items, [string]$DisplayName, [string]$Kind)
    $matches = @($Items | Where-Object { ($_.displayName ?? $_.name) -eq $DisplayName })
    if ($matches.Count -gt 1) { throw "$Kind '$DisplayName' has $($matches.Count) matches. Resolve duplicates before rerunning." }
    return $matches | Select-Object -First 1
}

function Get-OneIosVppAppByDisplayName {
    param([object[]]$Items, [string]$DisplayName)
    $matches = @($Items | Where-Object {
        $_.displayName -eq $DisplayName -and $_.'@odata.type' -eq '#microsoft.graph.iosVppApp'
    })
    if ($matches.Count -gt 1) { throw "Apps and Books app '$DisplayName' has $($matches.Count) iOS VPP matches. Resolve duplicates before rerunning." }
    return $matches | Select-Object -First 1
}

function Get-OrCreateSecurityGroup {
    param([Parameter(Mandatory)][string]$DisplayName)
    $escaped = $DisplayName.Replace("'", "''")
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
        displayName = $DisplayName
        description = 'Intune corporate iOS/iPadOS assignment group managed by the Apple bootstrap.'
        mailEnabled = $false
        mailNickname = $mailNickname
        securityEnabled = $true
        groupTypes = @()
    }
    Add-Outcome 'Groups' $DisplayName 'Created' $group.id
    return $group
}

function Ensure-Assignment {
    param(
        [Parameter(Mandatory)][string]$AssignmentsUri,
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][ValidateSet('Policy', 'App')][string]$Kind,
        [ValidateSet('available', 'required')][string]$Intent,
        [Parameter(Mandatory)][string]$Label
    )
    $assignments = @(Get-GraphCollection $AssignmentsUri)
    $sameGroup = @($assignments | Where-Object { $_.target.groupId -eq $GroupId })
    if ($Kind -eq 'App' -and $sameGroup -and $sameGroup.intent -notcontains $Intent) {
        throw "$Label already has a different assignment intent. Resolve it before rerunning."
    }
    $sameIntent = @($sameGroup | Where-Object { $Kind -eq 'Policy' -or $_.intent -eq $Intent })
    if ($Kind -eq 'App' -and $sameIntent -and @($sameIntent | Where-Object { -not $_.settings.useDeviceLicensing }).Count) {
        throw "$Label exists without device licensing. Resolve the assignment before rerunning."
    }
    $present = $sameIntent.Count -gt 0
    if ($present) { Add-Outcome 'Assignments' $Label 'Present' ($Intent ?? 'assigned'); return }
    if (-not $Apply) { Add-Outcome 'Assignments' $Label 'Would add' ($Intent ?? 'assigned'); return }

    if ($Kind -eq 'App') {
        $body = @{
            '@odata.type' = '#microsoft.graph.mobileAppAssignment'
            intent = $Intent
            target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId }
            settings = @{ '@odata.type' = '#microsoft.graph.iosVppAppAssignmentSettings'; useDeviceLicensing = $true }
        }
    } else {
        $body = @{
            '@odata.type' = '#microsoft.graph.deviceConfigurationAssignment'
            target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId }
        }
    }
    Invoke-GraphJson -Method POST -Uri $AssignmentsUri -Body $body | Out-Null
    $verified = @(Get-GraphCollection $AssignmentsUri | Where-Object {
        $_.target.groupId -eq $GroupId -and
        ($Kind -eq 'Policy' -or ($_.intent -eq $Intent -and $_.settings.useDeviceLicensing))
    })
    if ($verified.Count -eq 0) { throw "Assignment verification failed for '$Label'." }
    Add-Outcome 'Assignments' $Label 'Added' ($Intent ?? 'assigned')
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration not found: $ConfigPath" }
$config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
foreach ($required in @('TenantId','PilotGroupName','AdeTokenName','AppsAndBooksTokenName','EnrollmentProfileName','DeviceNameTemplate')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.$required)) { throw "Configuration is missing '$required'." }
}
foreach ($requiredPolicy in @('Restrictions','Updates','Compliance')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.Policies.$requiredPolicy)) { throw "Configuration is missing 'Policies.$requiredPolicy'." }
}
foreach ($requiredWifi in @('DisplayName','NetworkName','Ssid')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.Wifi.$requiredWifi)) { throw "Configuration is missing 'Wifi.$requiredWifi'." }
}
if ([bool]$config.Wifi.Hidden) { throw 'This corporate baseline requires a visible SSID; Wifi.Hidden must be false.' }
if ($RotateWifiKey -and -not $Apply) { throw '-RotateWifiKey requires -Apply.' }

$wallpaperEnabled = $null -ne $config.Wallpaper
$wallpaperPath = $null
$wallpaperBytes = $null
$wallpaperMimeType = $null
$wallpaperSha256 = $null
if ($wallpaperEnabled) {
    foreach ($requiredWallpaper in @('DisplayName','ImagePath','DisplayLocation')) {
        if ([string]::IsNullOrWhiteSpace([string]$config.Wallpaper.$requiredWallpaper)) { throw "Configuration is missing 'Wallpaper.$requiredWallpaper'." }
    }
    if ([string]$config.Wallpaper.DisplayLocation -notin @('lockScreen','homeScreen','lockAndHomeScreens')) {
        throw 'Wallpaper.DisplayLocation must be lockScreen, homeScreen, or lockAndHomeScreens.'
    }
    $configuredWallpaperPath = [string]$config.Wallpaper.ImagePath
    if (-not [IO.Path]::IsPathRooted($configuredWallpaperPath)) {
        $configuredWallpaperPath = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath).Path) $configuredWallpaperPath
    }
    if (-not (Test-Path -LiteralPath $configuredWallpaperPath -PathType Leaf)) { throw "Wallpaper image not found: $configuredWallpaperPath" }
    $wallpaperPath = (Resolve-Path -LiteralPath $configuredWallpaperPath).Path
    $wallpaperBytes = [IO.File]::ReadAllBytes($wallpaperPath)
    if ($wallpaperBytes.Length -eq 0 -or $wallpaperBytes.Length -ge 750KB) { throw 'Wallpaper image must be non-empty and less than 750 KB.' }
    $extension = [IO.Path]::GetExtension($wallpaperPath).ToLowerInvariant()
    if ($extension -in @('.jpg','.jpeg')) {
        if ($wallpaperBytes.Length -lt 3 -or $wallpaperBytes[0] -ne 0xFF -or $wallpaperBytes[1] -ne 0xD8 -or $wallpaperBytes[2] -ne 0xFF) { throw 'Wallpaper has a JPEG extension but not a JPEG signature.' }
        $wallpaperMimeType = 'image/jpeg'
    } elseif ($extension -eq '.png') {
        $pngSignature = @(0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)
        if ($wallpaperBytes.Length -lt 8 -or (Compare-Object -ReferenceObject $pngSignature -DifferenceObject @($wallpaperBytes[0..7]))) { throw 'Wallpaper has a PNG extension but not a PNG signature.' }
        $wallpaperMimeType = 'image/png'
    } else {
        throw 'Wallpaper image must have a .png, .jpg, or .jpeg extension.'
    }
    $wallpaperSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($wallpaperBytes)).ToLowerInvariant()
}

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
$hardBlockers = [System.Collections.Generic.List[string]]::new()
Write-Host "Mode: $(if ($Apply) { 'APPLY' } else { 'PLAN (no changes)' }); wave: $(if ($ComplianceWave) { 'COMPLIANCE' } else { 'CONFIGURATION' })" -ForegroundColor Cyan

# Resolve every Apple prerequisite before any possible write.
$apns = $null
try { $apns = Invoke-GraphJson -Method GET -Uri "$graphRoot/deviceManagement/applePushNotificationCertificate" } catch { }
if (-not $apns -or -not $apns.expirationDateTime) {
    Add-Outcome 'Apple prerequisites' 'APNs push certificate' 'Missing/unreadable' 'Confirm in Intune; enrollment cannot proceed'
    $hardBlockers.Add('Apple MDM push certificate')
} else {
    $expired = [datetime]$apns.expirationDateTime -le (Get-Date).ToUniversalTime()
    Add-Outcome 'Apple prerequisites' 'APNs push certificate' $(if ($expired) { 'Expired' } else { 'Present' }) "Apple account $($apns.appleIdentifier); expires $($apns.expirationDateTime)"
    if ($expired) { $hardBlockers.Add('Expired Apple MDM push certificate') }
}

$depTokens = @(Get-GraphCollection "$graphRoot/deviceManagement/depOnboardingSettings")
$dep = Get-OneByDisplayName $depTokens $config.AdeTokenName 'ADE token'
if (-not $dep) {
    Add-Outcome 'Apple prerequisites' $config.AdeTokenName 'Missing' 'Upload the ABM MDM server token in Intune'
    $hardBlockers.Add('Apple Business Manager ADE token')
} else {
    $depExpired = [datetime]$dep.tokenExpirationDateTime -le (Get-Date).ToUniversalTime()
    Add-Outcome 'Apple prerequisites' $config.AdeTokenName $(if ($depExpired) { 'Expired' } else { 'Present' }) "Apple account $($dep.appleIdentifier); expires $($dep.tokenExpirationDateTime); last sync $($dep.lastSuccessfulSyncDateTime)"
    if ($depExpired) { $hardBlockers.Add('Expired ADE token') }
}

$vppTokens = @(Get-GraphCollection "$graphRoot/deviceAppManagement/vppTokens")
$vpp = Get-OneByDisplayName $vppTokens $config.AppsAndBooksTokenName 'Apps and Books token'
if (-not $vpp) {
    Add-Outcome 'Apple prerequisites' $config.AppsAndBooksTokenName 'Missing' 'Upload the ABM location token in Intune'
    $hardBlockers.Add('Apple Apps and Books token')
} else {
    $vppExpired = [datetime]$vpp.expirationDateTime -le (Get-Date).ToUniversalTime()
    Add-Outcome 'Apple prerequisites' $config.AppsAndBooksTokenName $(if ($vppExpired) { 'Expired' } else { 'Present' }) "Apple account $($vpp.appleId); expires $($vpp.expirationDateTime); last sync $($vpp.lastSyncDateTime)"
    if ($vppExpired) { $hardBlockers.Add('Expired Apps and Books token') }
}

$profile = $null
if ($dep) {
    $profiles = @(Get-GraphCollection "$graphRoot/deviceManagement/depOnboardingSettings/$($dep.id)/enrollmentProfiles")
    $profile = Get-OneByDisplayName $profiles $config.EnrollmentProfileName 'ADE enrollment profile'
}
if (-not $profile) {
    Add-Outcome 'ADE profile' $config.EnrollmentProfileName 'Manual prerequisite' 'Create supervised user-affinity profile with Setup Assistant modern authentication and Company Portal via Apps and Books'
    $hardBlockers.Add('ADE enrollment profile')
} else {
    $profileCorrect =
        $profile.'@odata.type' -eq '#microsoft.graph.depIOSEnrollmentProfile' -and
        [bool]$profile.requiresUserAuthentication -and
        [bool]$profile.enableAuthenticationViaCompanyPortal -and
        [bool]$profile.requireCompanyPortalOnSetupAssistantEnrolledDevices -and
        [bool]$profile.supervisedModeEnabled -and
        [bool]$profile.isMandatory -and
        [bool]$profile.profileRemovalDisabled -and
        -not [bool]$profile.enableSharedIPad -and
        $vpp -and $profile.companyPortalVppTokenId -eq $vpp.id
    Add-Outcome 'ADE profile' $config.EnrollmentProfileName $(if ($profileCorrect) { 'Present' } else { 'Mismatch' }) "type=$($profile.'@odata.type'); supervised=$($profile.supervisedModeEnabled); userAuth=$($profile.requiresUserAuthentication); SetupAssistantModern=$($profile.enableAuthenticationViaCompanyPortal); CompanyPortalRequired=$($profile.requireCompanyPortalOnSetupAssistantEnrolledDevices); VPP=$($profile.companyPortalVppTokenId)"
    if (-not $profileCorrect) { $hardBlockers.Add('ADE enrollment profile mismatch') }
    if ($profile.deviceNameTemplate -and $profile.deviceNameTemplate -ne $config.DeviceNameTemplate) {
        Add-Outcome 'ADE profile' 'Device name template' 'Mismatch' "$($profile.deviceNameTemplate); expected $($config.DeviceNameTemplate)"
        $hardBlockers.Add('ADE device naming mismatch')
    }
}

if ($Apply -and $hardBlockers.Count) {
    throw "No changes made. Resolve Apple prerequisite(s): $($hardBlockers -join '; ')."
}

$pilot = Get-OrCreateSecurityGroup $config.PilotGroupName
$drivers = if ($config.DriversGroupName) { Get-OrCreateSecurityGroup $config.DriversGroupName } else { $null }
$office = if ($config.OfficeGroupName) { Get-OrCreateSecurityGroup $config.OfficeGroupName } else { $null }
$groupsByKey = @{ Pilot = $pilot; Drivers = $drivers; Office = $office }

# CIPP owns these definitions and assignments. This script audits rather than duplicates that lifecycle.
$deviceConfigs = @(Get-GraphCollection "$graphRoot/deviceManagement/deviceConfigurations")
$catalogPolicies = @(Get-GraphCollection "$graphRoot/deviceManagement/configurationPolicies")
$compliancePolicies = @(Get-GraphCollection "$graphRoot/deviceManagement/deviceCompliancePolicies")
$restrictions = Get-OneByDisplayName $deviceConfigs $config.Policies.Restrictions 'Device configuration'
$updates = Get-OneByDisplayName $catalogPolicies $config.Policies.Updates 'Settings catalog policy'
$compliance = Get-OneByDisplayName $compliancePolicies $config.Policies.Compliance 'Compliance policy'
foreach ($check in @(
    @{ Label='Restrictions'; Value=$restrictions; Type='#microsoft.graph.iosGeneralDeviceConfiguration'; Base="$graphRoot/deviceManagement/deviceConfigurations"; ShouldAssign=$true },
    @{ Label='Managed updates'; Value=$updates; Type='#microsoft.graph.deviceManagementConfigurationPolicy'; Base="$graphRoot/deviceManagement/configurationPolicies"; ShouldAssign=$true },
    @{ Label='Compliance'; Value=$compliance; Type='#microsoft.graph.iosCompliancePolicy'; Base="$graphRoot/deviceManagement/deviceCompliancePolicies"; ShouldAssign=$ComplianceWave }
)) {
    if (-not $check.Value) { Add-Outcome 'CIPP policy' $check.Label 'Missing' 'Deploy through the correct CIPP package'; continue }
    if ($check.Value.'@odata.type' -ne $check.Type) { throw "$($check.Label) has concrete type '$($check.Value.'@odata.type')', expected '$($check.Type)'." }
    Add-Outcome 'CIPP policy' $check.Label 'Present' $check.Value.id
    if ($pilot) {
        $assignments = @(Get-GraphCollection "$($check.Base)/$($check.Value.id)/assignments")
        $assigned = $assignments.target.groupId -contains $pilot.id
        $wanted = [bool]$check.ShouldAssign
        Add-Outcome 'CIPP assignment' "$($check.Label) -> Pilot" $(if ($assigned -eq $wanted) { 'Correct for wave' } else { 'Mismatch' }) "assigned=$assigned; expected=$wanted; remediate with CIPP Standards"
    }
}

if ($wallpaperEnabled -and -not $ComplianceWave) {
    $wallpaperName = [string]$config.Wallpaper.DisplayName
    $wallpaper = Get-OneByDisplayName $deviceConfigs $wallpaperName 'Wallpaper profile'
    if ($wallpaper -and $wallpaper.'@odata.type' -ne '#microsoft.graph.iosDeviceFeaturesConfiguration') {
        throw "'$wallpaperName' exists but is not an iOS/iPadOS Device features profile."
    }
    $wallpaperDescription = "Tenant-specific supervised iOS/iPadOS wallpaper. Source SHA256: $wallpaperSha256"
    $wallpaperCorrect = $wallpaper -and
        $wallpaper.wallpaperDisplayLocation -eq [string]$config.Wallpaper.DisplayLocation -and
        $wallpaper.description -eq $wallpaperDescription
    if ($wallpaperCorrect) {
        Add-Outcome 'Wallpaper' $wallpaperName 'Present' "location=$($wallpaper.wallpaperDisplayLocation); sha256=$($wallpaperSha256.Substring(0, 12))..."
    } elseif (-not $Apply) {
        Add-Outcome 'Wallpaper' $wallpaperName $(if ($wallpaper) { 'Would update' } else { 'Would create' }) "location=$($config.Wallpaper.DisplayLocation); image validated; bytes=$($wallpaperBytes.Length); sha256=$($wallpaperSha256.Substring(0, 12))..."
    } else {
        $wallpaperBody = @{
            '@odata.type' = '#microsoft.graph.iosDeviceFeaturesConfiguration'
            displayName = $wallpaperName
            description = $wallpaperDescription
            roleScopeTagIds = @('0')
            wallpaperDisplayLocation = [string]$config.Wallpaper.DisplayLocation
            wallpaperImage = @{
                '@odata.type' = '#microsoft.graph.mimeContent'
                type = $wallpaperMimeType
                value = [Convert]::ToBase64String($wallpaperBytes)
            }
        }
        if ($wallpaper) {
            Invoke-GraphJson -Method PATCH -Uri "$graphRoot/deviceManagement/deviceConfigurations/$($wallpaper.id)" -Body $wallpaperBody | Out-Null
        } else {
            $wallpaper = Invoke-GraphJson -Method POST -Uri "$graphRoot/deviceManagement/deviceConfigurations" -Body $wallpaperBody
        }
        $readBack = Invoke-GraphJson -Method GET -Uri "$graphRoot/deviceManagement/deviceConfigurations/$($wallpaper.id)"
        if ($readBack.'@odata.type' -ne '#microsoft.graph.iosDeviceFeaturesConfiguration' -or
            $readBack.wallpaperDisplayLocation -ne [string]$config.Wallpaper.DisplayLocation -or
            $readBack.description -ne $wallpaperDescription -or
            $readBack.wallpaperImage.type -ne $wallpaperMimeType -or
            [string]::IsNullOrWhiteSpace([string]$readBack.wallpaperImage.value)) {
            throw 'Wallpaper read-back verification failed.'
        }
        $readBackBytes = [Convert]::FromBase64String([string]$readBack.wallpaperImage.value)
        $readBackSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($readBackBytes)).ToLowerInvariant()
        if ($readBackSha256 -ne $wallpaperSha256) { throw 'Wallpaper image hash read-back verification failed.' }
        Add-Outcome 'Wallpaper' $wallpaperName 'Written and verified' "location=$($readBack.wallpaperDisplayLocation); bytes=$($readBackBytes.Length); sha256=$($wallpaperSha256.Substring(0, 12))..."
    }
    if ($wallpaper -and $pilot) {
        Ensure-Assignment -AssignmentsUri "$graphRoot/deviceManagement/deviceConfigurations/$($wallpaper.id)/assignments" -GroupId $pilot.id -Kind Policy -Label "$wallpaperName -> Pilot"
    }
}

$wifiName = [string]$config.Wifi.DisplayName
$wifi = Get-OneByDisplayName $deviceConfigs $wifiName 'Wi-Fi profile'
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
    if ($wifi -and $wifi.'@odata.type' -ne '#microsoft.graph.iosWiFiConfiguration') {
        throw "'$wifiName' exists but is not an iOS Basic Wi-Fi profile."
    }
    $wifiBody = @{
        '@odata.type' = '#microsoft.graph.iosWiFiConfiguration'
        displayName = $wifiName
        description = 'Tenant-specific corporate iOS/iPadOS WPA2 Personal Wi-Fi; PSK is maintained outside Git and CIPP templates.'
        roleScopeTagIds = @('0')
        networkName = [string]$config.Wifi.NetworkName
        ssid = [string]$config.Wifi.Ssid
        connectAutomatically = $true
        connectWhenNetworkNameIsHidden = [bool]$config.Wifi.Hidden
        wiFiSecurityType = 'wpa2Personal'
        proxySettings = 'none'
        disableMacAddressRandomization = $false
    }
    if ($needsWifiKey -and $Apply) { $wifiBody.preSharedKey = $plainPsk }
    if (-not $wifi) {
        if ($Apply) {
            $wifi = Invoke-GraphJson -Method POST -Uri "$graphRoot/deviceManagement/deviceConfigurations" -Body $wifiBody
            $readBack = Invoke-GraphJson -Method GET -Uri "$graphRoot/deviceManagement/deviceConfigurations/$($wifi.id)"
            if ($readBack.'@odata.type' -ne '#microsoft.graph.iosWiFiConfiguration' -or $readBack.wiFiSecurityType -ne 'wpa2Personal' -or -not $readBack.connectAutomatically -or $readBack.connectWhenNetworkNameIsHidden -or $readBack.ssid -ne [string]$config.Wifi.Ssid -or $readBack.proxySettings -ne 'none' -or [bool]$readBack.disableMacAddressRandomization) {
                throw 'Wi-Fi read-back verification failed.'
            }
            Add-Outcome 'Wi-Fi' $wifiName 'Created and verified' 'iOS Basic; WPA2 Personal; auto-connect; visible SSID'
        } else { Add-Outcome 'Wi-Fi' $wifiName 'Would create' 'Secure PSK prompt required during apply' }
    } elseif ($RotateWifiKey) {
        Invoke-GraphJson -Method PATCH -Uri "$graphRoot/deviceManagement/deviceConfigurations/$($wifi.id)" -Body $wifiBody | Out-Null
        $readBack = Invoke-GraphJson -Method GET -Uri "$graphRoot/deviceManagement/deviceConfigurations/$($wifi.id)"
        if ($readBack.'@odata.type' -ne '#microsoft.graph.iosWiFiConfiguration' -or $readBack.wiFiSecurityType -ne 'wpa2Personal' -or -not $readBack.connectAutomatically -or $readBack.connectWhenNetworkNameIsHidden -or $readBack.ssid -ne [string]$config.Wifi.Ssid -or $readBack.proxySettings -ne 'none' -or [bool]$readBack.disableMacAddressRandomization -or -not $readBack.preSharedKeyIsSet) {
            throw 'Wi-Fi rotation read-back verification failed.'
        }
        Add-Outcome 'Wi-Fi' $wifiName 'Updated and verified' 'PSK rotated; secret not displayed'
    } else {
        $correct = $wifi.wiFiSecurityType -eq 'wpa2Personal' -and [bool]$wifi.connectAutomatically -and -not [bool]$wifi.connectWhenNetworkNameIsHidden -and $wifi.ssid -eq [string]$config.Wifi.Ssid -and $wifi.networkName -eq [string]$config.Wifi.NetworkName -and $wifi.proxySettings -eq 'none' -and -not [bool]$wifi.disableMacAddressRandomization
        Add-Outcome 'Wi-Fi' $wifiName $(if ($correct) { 'Present' } else { 'Mismatch' }) "$($wifi.'@odata.type'); $($wifi.wiFiSecurityType); auto=$($wifi.connectAutomatically); hidden=$($wifi.connectWhenNetworkNameIsHidden)"
    }
} finally {
    $plainPsk = $null
    $securePsk = $null
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
if ($wifi -and $pilot -and -not $ComplianceWave) {
    Ensure-Assignment -AssignmentsUri "$graphRoot/deviceManagement/deviceConfigurations/$($wifi.id)/assignments" -GroupId $pilot.id -Kind Policy -Label "$wifiName -> Pilot"
}

$apps = @(Get-GraphCollection "$graphRoot/deviceAppManagement/mobileApps")
foreach ($wanted in @($config.Apps)) {
    if ($wanted.Group -notin @('Pilot','Drivers','Office')) { throw "App '$($wanted.DisplayName)' has invalid Group '$($wanted.Group)'." }
    if (-not $groupsByKey.ContainsKey([string]$wanted.Group) -or -not $config."$($wanted.Group)GroupName") {
        throw "App '$($wanted.DisplayName)' targets '$($wanted.Group)', but that optional role group is not configured."
    }
    if ($wanted.Intent -notin @('required','available')) { throw "App '$($wanted.DisplayName)' has invalid Intent '$($wanted.Intent)'." }
    $app = Get-OneIosVppAppByDisplayName $apps $wanted.DisplayName
    if (-not $app) { Add-Outcome 'Apps' $wanted.DisplayName 'Manual prerequisite' 'Acquire in Apple Business Manager Apps and Books and sync Intune'; continue }
    if ($vpp -and $app.vppTokenId -ne $vpp.id) { throw "'$($wanted.DisplayName)' is linked to a different Apps and Books token." }
    if (-not [bool]$app.licensingType.supportsDeviceLicensing) { throw "'$($wanted.DisplayName)' does not support Apps and Books device licensing." }
    $target = $groupsByKey[$wanted.Group]
    if (-not $target) { Add-Outcome 'Apps' "$($wanted.DisplayName) -> $($wanted.Group)" 'Waiting' 'Target group will be created during apply'; continue }
    Ensure-Assignment -AssignmentsUri "$graphRoot/deviceAppManagement/mobileApps/$($app.id)/assignments" -GroupId $target.id -Kind App -Intent $wanted.Intent -Label "$($wanted.DisplayName) -> $($wanted.Group)"
}

Write-Host ''
$outcomes | Format-Table Area, Item, State, Detail -Wrap -AutoSize
$attention = @($outcomes | Where-Object State -in @('Missing','Missing/unreadable','Expired','Mismatch','Manual prerequisite','Waiting'))
Write-Host "`nCompleted: $($outcomes.Count) checks; $($attention.Count) item(s) require attention." -ForegroundColor $(if ($attention.Count) { 'Yellow' } else { 'Green' })
if (-not $Apply) { Write-Host 'No changes were made. Resolve all Apple prerequisites and review the plan before using -Apply.' -ForegroundColor Cyan }
if ($attention.Count) { exit 1 }
