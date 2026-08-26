<#
.SYNOPSIS
    Deep read-only audit for an Apple corporate iOS/iPadOS Intune rollout.

.DESCRIPTION
    Resolves every object by exact display name, refuses duplicates, validates
    concrete Graph types, safety-critical fields, assignments, Apple certificate
    and token dates, ADE profile settings, Apps and Books app identities, managed
    update content, enrollment restrictions, Conditional Access and pilot devices.
    It never requests or prints certificate/token material, enrollment payloads,
    Wi-Fi PSKs or Activation Lock bypass codes.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$CippConfigPath = (Join-Path ($env:XDG_DATA_HOME ? $env:XDG_DATA_HOME : (Join-Path $HOME '.local/share')) 'cipp-mcp/config.json')
)

$ErrorActionPreference = 'Stop'
$graphRoot = 'https://graph.microsoft.com/beta'
$scopes = @(
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementApps.Read.All',
    'DeviceManagementServiceConfig.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'Group.Read.All',
    'Policy.Read.All'
)

function Invoke-GraphGet { param([string]$Uri) Invoke-MgGraphRequest -Method GET -Uri $Uri }
function Get-GraphCollection {
    param([string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    do {
        $page = Invoke-GraphGet $Uri
        foreach ($item in @($page.value)) { $items.Add($item) }
        $Uri = $page.'@odata.nextLink'
    } while ($Uri)
    return @($items)
}
function Get-OneByName {
    param([object[]]$Items, [string]$Name, [string]$Kind)
    $matches = @($Items | Where-Object { $candidate = if ($_.displayName) { $_.displayName } else { $_.name }; $candidate -eq $Name })
    if ($matches.Count -gt 1) { throw "$Kind '$Name' has $($matches.Count) matches." }
    return $matches | Select-Object -First 1
}
function Get-OneIosVppAppByName {
    param([object[]]$Items, [string]$Name)
    $matches = @($Items | Where-Object {
        $_.displayName -eq $Name -and $_.'@odata.type' -eq '#microsoft.graph.iosVppApp'
    })
    if ($matches.Count -gt 1) { throw "Apps and Books app '$Name' has $($matches.Count) iOS VPP matches." }
    return $matches | Select-Object -First 1
}

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string]$Area, [string]$Check, [string]$Expected, $Actual, [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Status)
    $results.Add([pscustomobject]@{
        Area=$Area; Check=$Check; Expected=$Expected
        Actual=if ($null -eq $Actual -or "$Actual" -eq '') { '(blank)' } else { "$Actual" }
        Status=$Status
    })
}
function Test-Value {
    param([string]$Area, [string]$Check, $Expected, $Actual)
    Add-Result $Area $Check $Expected $Actual $(if ("$Actual" -ceq "$Expected") { 'PASS' } else { 'FAIL' })
}
function Get-SettingInstances {
    param($Node)
    $found = [System.Collections.Generic.List[object]]::new()
    function Walk($Value) {
        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and $Value -isnot [System.Collections.IDictionary]) {
            foreach ($entry in $Value) { Walk $entry }
        } elseif ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
            if ($Value.settingDefinitionId) { $found.Add($Value) }
            foreach ($property in $Value.PSObject.Properties) { Walk $property.Value }
        }
    }
    Walk $Node
    return @($found)
}

function Get-PlainTextSecret {
    param([string]$EncryptedSecret, [string]$ConfigDirectory)
    $key = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath (Join-Path $ConfigDirectory 'key.bin')))
    $parts = $EncryptedSecret -split ':', 2
    if ($parts.Count -ne 2) { throw 'Malformed encrypted CIPP secret.' }
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.Key=$key; $aes.IV=[Convert]::FromBase64String($parts[0])
        $bytes=[Convert]::FromBase64String($parts[1]); $decryptor=$aes.CreateDecryptor()
        return [Text.Encoding]::UTF8.GetString($decryptor.TransformFinalBlock($bytes,0,$bytes.Length))
    } finally { $aes.Dispose() }
}
function Get-CippTemplates {
    if (-not (Test-Path -LiteralPath $CippConfigPath -PathType Leaf)) { return $null }
    $settings = Get-Content -Raw -LiteralPath $CippConfigPath | ConvertFrom-Json
    $secret = Get-PlainTextSecret $settings.EncryptedClientSecret (Split-Path -Parent $CippConfigPath)
    try {
        $token = Invoke-RestMethod -Method Post -ContentType 'application/x-www-form-urlencoded' -Uri "https://login.microsoftonline.com/$($settings.TenantId)/oauth2/v2.0/token" -Body @{
            client_id=[string]$settings.ClientId; client_secret=$secret
            scope=if ($settings.Scope) { [string]$settings.Scope } else { "api://$($settings.ClientId)/.default" }
            grant_type='client_credentials'
        }
    } finally { $secret=$null }
    $apiBase = ([string]$settings.CippMcpUrl) -replace '(?i)/api/ExecMcp/?$',''
    $response = Invoke-RestMethod -Method Get -Uri "$apiBase/api/ListIntuneTemplates?View=true" -Headers @{Authorization="Bearer $($token.access_token)";Accept='application/json'}
    if ($response.Results) { return @($response.Results) }
    return @($response)
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration not found: $ConfigPath" }
$config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
$wave = if ($config.RolloutWave) { [string]$config.RolloutWave } else { 'Prerequisites' }
if ($wave -notin @('Prerequisites','Configuration','Compliance')) { throw "Invalid RolloutWave '$wave'." }

$context = Get-MgContext
$mustConnect = -not $context -or @($scopes | Where-Object { $_ -notin $context.Scopes }).Count -gt 0
if (-not $mustConnect) { try { Invoke-GraphGet "$graphRoot/deviceManagement/deviceConfigurations?`$top=1" | Out-Null } catch { $mustConnect=$true } }
if ($mustConnect) {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -TenantId $config.TenantId -Scopes $scopes -ContextScope Process -NoWelcome
}

Write-Host "Auditing corporate iOS/iPadOS rollout; expected wave: $wave. No changes will be made." -ForegroundColor Cyan

# Apple prerequisites
try {
    $apns = Invoke-GraphGet "$graphRoot/deviceManagement/applePushNotificationCertificate"
    $apnsOk = $apns.expirationDateTime -and [datetime]$apns.expirationDateTime -gt (Get-Date).ToUniversalTime() -and $apns.certificateUploadStatus -notmatch 'fail'
    Add-Result 'Apple prerequisites' 'APNs certificate' 'Present and unexpired' "Apple account $($apns.appleIdentifier); expires $($apns.expirationDateTime); status $($apns.certificateUploadStatus)" $(if ($apnsOk) {'PASS'} else {'FAIL'})
} catch { Add-Result 'Apple prerequisites' 'APNs certificate' 'Present and unexpired' 'Missing or Graph returned no certificate object' 'FAIL' }

$depTokens = @(Get-GraphCollection "$graphRoot/deviceManagement/depOnboardingSettings")
$dep = Get-OneByName $depTokens $config.AdeTokenName 'ADE token'
if (-not $dep) { Add-Result 'Apple prerequisites' 'ADE token' $config.AdeTokenName 'Missing' 'FAIL' }
else {
    $ok=[datetime]$dep.tokenExpirationDateTime -gt (Get-Date).ToUniversalTime() -and [int]$dep.lastSyncErrorCode -eq 0
    Add-Result 'Apple prerequisites' 'ADE token' 'Unexpired; last sync successful' "ID $($dep.id); Apple account $($dep.appleIdentifier); expires $($dep.tokenExpirationDateTime); last sync $($dep.lastSuccessfulSyncDateTime); devices $($dep.syncedDeviceCount); error $($dep.lastSyncErrorCode)" $(if($ok){'PASS'}else{'FAIL'})
}

$vppTokens = @(Get-GraphCollection "$graphRoot/deviceAppManagement/vppTokens")
$vpp = Get-OneByName $vppTokens $config.AppsAndBooksTokenName 'Apps and Books token'
if (-not $vpp) { Add-Result 'Apple prerequisites' 'Apps and Books token' $config.AppsAndBooksTokenName 'Missing' 'FAIL' }
else {
    $ok=[datetime]$vpp.expirationDateTime -gt (Get-Date).ToUniversalTime() -and $vpp.state -notmatch 'invalid|expired'
    Add-Result 'Apple prerequisites' 'Apps and Books token' 'Unexpired; healthy sync' "ID $($vpp.id); Apple account $($vpp.appleId); organization $($vpp.organizationName); location $($vpp.locationName); expires $($vpp.expirationDateTime); last sync $($vpp.lastSyncDateTime); status $($vpp.lastSyncStatus)" $(if($ok){'PASS'}else{'FAIL'})
}

# ADE profile and ABM device inventory
$profile=$null; $abmDevices=@()
if ($dep) {
    $profiles=@(Get-GraphCollection "$graphRoot/deviceManagement/depOnboardingSettings/$($dep.id)/enrollmentProfiles")
    $profile=Get-OneByName $profiles $config.EnrollmentProfileName 'ADE enrollment profile'
    $abmDevices=@(Get-GraphCollection "$graphRoot/deviceManagement/depOnboardingSettings/$($dep.id)/importedAppleDeviceIdentities")
}
if (-not $profile) { Add-Result 'ADE' 'Enrollment profile' $config.EnrollmentProfileName 'Missing' 'FAIL' }
else {
    Test-Value 'ADE' 'Concrete profile type' '#microsoft.graph.depIOSEnrollmentProfile' $profile.'@odata.type'
    Test-Value 'ADE' 'Supervised' 'True' ([bool]$profile.supervisedModeEnabled)
    Test-Value 'ADE' 'User affinity/authentication required' 'True' ([bool]$profile.requiresUserAuthentication)
    Test-Value 'ADE' 'Setup Assistant modern authentication' 'True' ([bool]$profile.enableAuthenticationViaCompanyPortal)
    Test-Value 'ADE' 'Company Portal required after Setup Assistant' 'True' ([bool]$profile.requireCompanyPortalOnSetupAssistantEnrolledDevices)
    Test-Value 'ADE' 'Company Portal Apps and Books token' $vpp.id $profile.companyPortalVppTokenId
    Test-Value 'ADE' 'MDM profile mandatory' 'True' ([bool]$profile.isMandatory)
    Test-Value 'ADE' 'MDM profile removal blocked' 'True' ([bool]$profile.profileRemovalDisabled)
    Test-Value 'ADE' 'Single-user, not Shared iPad' 'False' ([bool]$profile.enableSharedIPad)
    if ($profile.deviceNameTemplate) { Test-Value 'ADE' 'Device naming' $config.DeviceNameTemplate $profile.deviceNameTemplate }
}
Add-Result 'ADE' 'Available ABM/ADE devices' 'Customer-supported models identified and pilot device assigned' "$($abmDevices.Count) synchronized device(s)" $(if($abmDevices.Count){'INFO'}else{'WARN'})
foreach ($device in $abmDevices) {
    Add-Result 'ADE devices' "Serial ending $(([string]$device.serialNumber).Substring([Math]::Max(0,([string]$device.serialNumber).Length-4)))" 'Profile assigned before wipe' "model=$($device.model); enrollment=$($device.enrollmentState); profile=$($device.profileStatus)" 'INFO'
}

# Groups
$allGroups=@(Get-GraphCollection "$graphRoot/groups?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes")
$groups=@{}
foreach($pair in @(@('Pilot',$config.PilotGroupName),@('Drivers',$config.DriversGroupName),@('Office',$config.OfficeGroupName)) | Where-Object { $_[1] }){
    $group=Get-OneByName $allGroups $pair[1] 'Security group'; $groups[$pair[0]]=$group
    if(-not $group){Add-Result 'Groups' $pair[1] 'Static security group' 'Missing' 'FAIL'}
    else {Add-Result 'Groups' $pair[1] 'Static security group' $group.id $(if($group.securityEnabled -and -not $group.mailEnabled -and $group.groupTypes -notcontains 'DynamicMembership'){'PASS'}else{'FAIL'})}
}
$pilot=$groups.Pilot

# CIPP saved templates and live policy definitions
try {
    $templates=Get-CippTemplates
    if($null -eq $templates){throw 'CIPP configuration unavailable'}
    foreach($name in @($config.Policies.Restrictions,$config.Policies.Updates,$config.Policies.Compliance)){
        $matches=@($templates|Where-Object {($_.displayName ?? $_.Displayname ?? $_.name)-eq $name})
        Add-Result 'CIPP templates' $name 'Exactly one saved template; no unintended duplicate' "$($matches.Count) match(es); source $($matches.source -join ','); usage $($matches.usage.Count)" $(if($matches.Count -eq 1){'PASS'}else{'FAIL'})
    }
} catch { Add-Result 'CIPP templates' 'Saved-template audit' 'Readable' $_.Exception.Message 'WARN' }

$deviceConfigs=@(Get-GraphCollection "$graphRoot/deviceManagement/deviceConfigurations")
$catalogPolicies=@(Get-GraphCollection "$graphRoot/deviceManagement/configurationPolicies")
$compliancePolicies=@(Get-GraphCollection "$graphRoot/deviceManagement/deviceCompliancePolicies")
$restrictions=Get-OneByName $deviceConfigs $config.Policies.Restrictions 'Device configuration'
$updates=Get-OneByName $catalogPolicies $config.Policies.Updates 'Settings catalog policy'
$compliance=Get-OneByName $compliancePolicies $config.Policies.Compliance 'Compliance policy'

$expectConfiguration=$wave -in @('Configuration','Compliance')
$expectCompliance=$wave -eq 'Compliance'
if(-not $restrictions){Add-Result 'Restrictions' 'Live policy' $config.Policies.Restrictions 'Missing' $(if($expectConfiguration){'FAIL'}else{'INFO'})}
else {
    $r=Invoke-GraphGet "$graphRoot/deviceManagement/deviceConfigurations/$($restrictions.id)"
    Test-Value 'Restrictions' 'Concrete type' '#microsoft.graph.iosGeneralDeviceConfiguration' $r.'@odata.type'
    foreach($test in @(
        @('Six-digit passcode',6,$r.passcodeMinimumLength),@('Simple passcodes blocked',$true,$r.passcodeBlockSimple),
        @('Managed documents blocked from unmanaged apps',$true,$r.documentsBlockManagedDocumentsInUnmanagedApps),
        @('Unmanaged documents allowed in managed apps',$false,$r.documentsBlockUnmanagedDocumentsInManagedApps),
        @('User account changes blocked',$true,$r.accountBlockModification),
        @('User Activation Lock not permitted',$false,$r.activationLockAllowWhenSupervised),
        @('User App Store installations blocked',$true,$r.appStoreBlockUIAppInstallation),
        @('Device-name changes blocked',$true,$r.deviceBlockNameModification),
        @('Personal Hotspot allowed',$false,$r.cellularBlockPersonalHotspot),
        @('Mobile data roaming allowed',$false,$r.cellularBlockDataRoaming),
        @('Voice-call roaming allowed',$false,$r.cellularBlockVoiceRoaming),
        @('Camera allowed',$false,$r.cameraBlocked),
        @('Bluetooth settings remain user-controllable',$false,$r.bluetoothBlockModification),
        @('iCloud backup blocked',$true,$r.iCloudBlockBackup),
        @('iCloud managed-app sync blocked',$true,$r.iCloudBlockManagedAppsSync),
        @('iCloud document sync blocked',$true,$r.iCloudBlockDocumentSync),
        @('iCloud Photos blocked',$true,$r.iCloudBlockPhotoLibrary),
        @('iCloud Photo Stream blocked',$true,$r.iCloudBlockPhotoStreamSync),
        @('iCloud Shared Photo Stream blocked',$true,$r.iCloudBlockSharedPhotoStream),
        @('iCloud Private Relay blocked',$true,$r.iCloudPrivateRelayBlocked),
        @('iCloud Keychain sync blocked',$true,$r.keychainBlockCloudSync),
        @('AirDrop blocked',$true,$r.airDropBlocked),@('AirDrop treated unmanaged',$true,$r.airDropForceUnmanagedDropTarget),
        @('Screenshots allowed',$false,$r.screenCaptureBlocked),@('USB Files access blocked',$true,$r.filesUsbDriveAccessBlocked),
        @('Computer pairing blocked',$true,$r.hostPairingBlocked),
        @('Apple Watch pairing blocked',$true,$r.appleWatchBlockPairing),
        @('Wallpaper changes blocked',$true,$r.wallpaperBlockModification),
        @('Other Wi-Fi networks remain allowed',$false,$r.wiFiConnectToAllowedNetworksOnlyForced)
    )){Test-Value 'Restrictions' $test[0] $test[1] $test[2]}
    if($pilot){$a=@(Get-GraphCollection "$graphRoot/deviceManagement/deviceConfigurations/$($r.id)/assignments");$assigned=$a.target.groupId -contains $pilot.id;Test-Value 'Restrictions' 'Pilot assignment' $expectConfiguration $assigned}
}

if(-not $updates){Add-Result 'Updates' 'Live DDM policy' $config.Policies.Updates 'Missing' $(if($expectConfiguration){'FAIL'}else{'INFO'})}
else {
    Test-Value 'Updates' 'Concrete type' '#microsoft.graph.deviceManagementConfigurationPolicy' $updates.'@odata.type'
    Test-Value 'Updates' 'Technology' 'mdm,appleRemoteManagement' $updates.technologies
    $settings=Get-GraphCollection "$graphRoot/deviceManagement/configurationPolicies/$($updates.id)/settings"
    $instances=Get-SettingInstances $settings
    $byId=@{};foreach($instance in $instances){$byId[$instance.settingDefinitionId]=$instance}
    Test-Value 'Updates' 'Latest version enforced' 'ddm-latestsoftwareupdate_enforcelatestsoftwareupdateversion_0' $byId['ddm-latestsoftwareupdate_enforcelatestsoftwareupdateversion'].choiceSettingValue.value
    Test-Value 'Updates' 'Deadline after release' 7 $byId['ddm-latestsoftwareupdate_delayindays'].simpleSettingValue.value
    Test-Value 'Updates' 'Install time' '03:00' $byId['ddm-latestsoftwareupdate_installtime'].simpleSettingValue.value
    if($pilot){$a=@(Get-GraphCollection "$graphRoot/deviceManagement/configurationPolicies/$($updates.id)/assignments");$assigned=$a.target.groupId -contains $pilot.id;Test-Value 'Updates' 'Pilot assignment' $expectConfiguration $assigned}
}

if(-not $compliance){Add-Result 'Compliance' 'Live policy' $config.Policies.Compliance 'Missing' $(if($expectCompliance){'FAIL'}else{'INFO'})}
else {
    $c=Invoke-GraphGet "$graphRoot/deviceManagement/deviceCompliancePolicies/$($compliance.id)?`$expand=scheduledActionsForRule(`$expand=scheduledActionConfigurations)"
    Test-Value 'Compliance' 'Concrete type' '#microsoft.graph.iosCompliancePolicy' $c.'@odata.type'
    Test-Value 'Compliance' 'Minimum OS' $config.Compliance.MinimumOsVersion $c.osMinimumVersion
    Test-Value 'Compliance' 'Jailbreak blocked' 'True' ([bool]$c.securityBlockJailbrokenDevices)
    $actions=@($c.scheduledActionsForRule|ForEach-Object{$_.scheduledActionConfigurations})
    Test-Value 'Compliance' '24-hour notification' 'True' ([bool]($actions|Where-Object{$_.actionType -eq 'notification' -and [int]$_.gracePeriodHours -eq 24 -and $_.notificationTemplateId -eq $config.Compliance.NotificationTemplateId}))
    Test-Value 'Compliance' '168-hour block' 'True' ([bool]($actions|Where-Object{$_.actionType -eq 'block' -and [int]$_.gracePeriodHours -eq 168}))
    if($pilot){$a=@(Get-GraphCollection "$graphRoot/deviceManagement/deviceCompliancePolicies/$($c.id)/assignments");$assigned=$a.target.groupId -contains $pilot.id;Test-Value 'Compliance' 'Pilot assignment' $expectCompliance $assigned}
}

# Optional supervised wallpaper; compare the live binary by hash and never print its content.
if($config.Wallpaper){
    $configuredWallpaperPath=[string]$config.Wallpaper.ImagePath
    if(-not [IO.Path]::IsPathRooted($configuredWallpaperPath)){$configuredWallpaperPath=Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath).Path) $configuredWallpaperPath}
    $wallpaperFileOk=Test-Path -LiteralPath $configuredWallpaperPath -PathType Leaf
    Add-Result 'Wallpaper' 'Private source image' 'Readable local PNG/JPEG below 750 KB' $(if($wallpaperFileOk){$configuredWallpaperPath}else{'Missing'}) $(if($wallpaperFileOk){'PASS'}else{'FAIL'})
    $wallpaper=Get-OneByName $deviceConfigs $config.Wallpaper.DisplayName 'Wallpaper profile'
    if(-not $wallpaper){Add-Result 'Wallpaper' 'Live profile' $config.Wallpaper.DisplayName 'Missing' $(if($expectConfiguration){'FAIL'}else{'INFO'})}
    elseif($wallpaperFileOk){
        $wallpaperBytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $configuredWallpaperPath).Path)
        $expectedHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($wallpaperBytes)).ToLowerInvariant()
        $expectedMime=if([IO.Path]::GetExtension($configuredWallpaperPath).ToLowerInvariant() -eq '.png'){'image/png'}else{'image/jpeg'}
        $liveWallpaper=Invoke-GraphGet "$graphRoot/deviceManagement/deviceConfigurations/$($wallpaper.id)"
        Test-Value 'Wallpaper' 'Concrete type' '#microsoft.graph.iosDeviceFeaturesConfiguration' $liveWallpaper.'@odata.type'
        Test-Value 'Wallpaper' 'Display location' $config.Wallpaper.DisplayLocation $liveWallpaper.wallpaperDisplayLocation
        Test-Value 'Wallpaper' 'MIME type' $expectedMime $liveWallpaper.wallpaperImage.type
        if([string]::IsNullOrWhiteSpace([string]$liveWallpaper.wallpaperImage.value)){Add-Result 'Wallpaper' 'Image hash' $expectedHash 'Graph returned no image content' 'FAIL'}
        else{$liveBytes=[Convert]::FromBase64String([string]$liveWallpaper.wallpaperImage.value);$liveHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($liveBytes)).ToLowerInvariant();Test-Value 'Wallpaper' 'Image SHA256' $expectedHash $liveHash}
        if($pilot){$a=@(Get-GraphCollection "$graphRoot/deviceManagement/deviceConfigurations/$($wallpaper.id)/assignments");Test-Value 'Wallpaper' 'Pilot assignment' $expectConfiguration ($a.target.groupId -contains $pilot.id)}
    }
}

# Wi-Fi and Apps and Books apps; never read or display the PSK.
$wifi=Get-OneByName $deviceConfigs $config.Wifi.DisplayName 'Wi-Fi profile'
if(-not $wifi){Add-Result 'Wi-Fi' 'Managed LAF profile' $config.Wifi.DisplayName 'Missing' $(if($expectConfiguration){'FAIL'}else{'INFO'})}
else {
    Test-Value 'Wi-Fi' 'Concrete type' '#microsoft.graph.iosWiFiConfiguration' $wifi.'@odata.type'
    Test-Value 'Wi-Fi' 'SSID' $config.Wifi.Ssid $wifi.ssid
    Test-Value 'Wi-Fi' 'WPA2 Personal' 'wpa2Personal' $wifi.wiFiSecurityType
    Test-Value 'Wi-Fi' 'Auto-connect' 'True' ([bool]$wifi.connectAutomatically)
    Test-Value 'Wi-Fi' 'Visible SSID' 'False' ([bool]$wifi.connectWhenNetworkNameIsHidden)
    Test-Value 'Wi-Fi' 'No proxy' 'none' $wifi.proxySettings
    Test-Value 'Wi-Fi' 'Private MAC remains enabled' 'False' ([bool]$wifi.disableMacAddressRandomization)
    if($pilot){$a=@(Get-GraphCollection "$graphRoot/deviceManagement/deviceConfigurations/$($wifi.id)/assignments");Test-Value 'Wi-Fi' 'Pilot assignment' $expectConfiguration ($a.target.groupId -contains $pilot.id)}
}

$apps=@(Get-GraphCollection "$graphRoot/deviceAppManagement/mobileApps")
foreach($wanted in @($config.Apps)){
    $app=Get-OneIosVppAppByName $apps $wanted.DisplayName
    if(-not $app){Add-Result 'Apps' $wanted.DisplayName 'One iOS Apps and Books app' 'Missing' $(if($expectConfiguration){'FAIL'}else{'INFO'});continue}
    $typeOk=$app.'@odata.type' -eq '#microsoft.graph.iosVppApp' -and (-not $vpp -or $app.vppTokenId -eq $vpp.id) -and [bool]$app.licensingType.supportsDeviceLicensing
    Add-Result 'Apps' "$($wanted.DisplayName) identity" 'iosVppApp linked to expected token; device licensing supported' "ID $($app.id); type $($app.'@odata.type'); VPP $($app.vppTokenId); device licensing=$($app.licensingType.supportsDeviceLicensing)" $(if($typeOk){'PASS'}else{'FAIL'})
    $target=$groups[$wanted.Group]
    if($target){$a=@(Get-GraphCollection "$graphRoot/deviceAppManagement/mobileApps/$($app.id)/assignments");$match=$a|Where-Object{$_.target.groupId -eq $target.id -and $_.intent -eq $wanted.Intent -and $_.settings.useDeviceLicensing};Add-Result 'Apps' "$($wanted.DisplayName) -> $($wanted.Group)" "$($wanted.Intent), device licensed" ([bool]$match) $(if($match){'PASS'}elseif($expectConfiguration){'FAIL'}else{'INFO'})}
}

# Enrollment restrictions
$enrollmentConfigs=@(Get-GraphCollection "$graphRoot/deviceManagement/deviceEnrollmentConfigurations")
$platformRestriction=@($enrollmentConfigs|Where-Object{$_.deviceEnrollmentConfigurationType -eq 'platformRestrictions'}|Sort-Object priority|Select-Object -First 1)
if($platformRestriction){Add-Result 'Enrollment restrictions' 'Personal iOS MDM enrollment' 'Separate BYOD/MAM project; decision documented' "blocked=$($platformRestriction.iosRestriction.personalDeviceEnrollmentBlocked); policy=$($platformRestriction.displayName)" 'WARN'}

# Pilot devices
$iosDevices=@(Get-GraphCollection "$graphRoot/deviceManagement/managedDevices?`$filter=operatingSystem eq 'iOS'&`$select=id,deviceName,model,osVersion,complianceState,lastSyncDateTime,userPrincipalName,isSupervised,enrollmentProfileName,deviceEnrollmentType")
if(-not $iosDevices){Add-Result 'Devices' 'Enrolled iOS/iPadOS pilot' 'At least one healthy pilot before completion' '0 devices' $(if($wave -eq 'Prerequisites'){'WARN'}else{'FAIL'})}
foreach($d in $iosDevices){$healthy=$d.isSupervised -and $d.enrollmentProfileName -eq $config.EnrollmentProfileName -and $d.complianceState -notin @('noncompliant','unknown');Add-Result 'Devices' $d.deviceName 'Supervised ADE; expected profile; healthy compliance' "$($d.model); iOS $($d.osVersion); supervised=$($d.isSupervised); profile=$($d.enrollmentProfileName); compliance=$($d.complianceState); sync=$($d.lastSyncDateTime)" $(if($healthy){'PASS'}else{'FAIL'})}

# Conditional Access and Security Defaults
$ca=@(Get-GraphCollection "$graphRoot/identity/conditionalAccess/policies")
$iosCa=@($ca|Where-Object{$_.state -ne 'disabled' -and ((-not $_.conditions.platforms) -or $_.conditions.platforms.includePlatforms -contains 'all' -or $_.conditions.platforms.includePlatforms -contains 'iOS') -and $_.conditions.platforms.excludePlatforms -notcontains 'iOS'})
$complianceCa=@($iosCa|Where-Object{$_.grantControls.builtInControls -contains 'compliantDevice'})
Add-Result 'Conditional Access' 'Applicable iOS policies' 'Reviewed' (@($iosCa|ForEach-Object{"$($_.displayName) [$($_.state)]"}) -join '; ') 'INFO'
Add-Result 'Conditional Access' 'Compliant-device requirement' 'None until pilot healthy; report-only next' (@($complianceCa|ForEach-Object{"$($_.displayName) [$($_.state)]"}) -join '; ') $(if($wave -eq 'Prerequisites' -and @($complianceCa|Where-Object{$_.state -eq 'enabled'}).Count -eq 0){'PASS'}else{'WARN'})
$securityDefaults=Invoke-GraphGet 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
Add-Result 'Conditional Access' 'Security Defaults' 'Known and reviewed' $securityDefaults.isEnabled $(if($securityDefaults.isEnabled){'WARN'}else{'PASS'})

Write-Host "`n=== FAILURES ===" -ForegroundColor Red
$results|Where-Object Status -eq 'FAIL'|Format-Table Area,Check,Expected,Actual -Wrap -AutoSize
Write-Host "`n=== WARNINGS / DECISIONS ===" -ForegroundColor Yellow
$results|Where-Object Status -eq 'WARN'|Format-Table Area,Check,Expected,Actual -Wrap -AutoSize
Write-Host "`n=== PASSES ===" -ForegroundColor Green
$results|Where-Object Status -eq 'PASS'|Format-Table Area,Check,Actual -Wrap -AutoSize
Write-Host "`n=== INFORMATION ===" -ForegroundColor Cyan
$results|Where-Object Status -eq 'INFO'|Format-Table Area,Check,Actual -Wrap -AutoSize
$summary=[pscustomobject]@{Passed=@($results|Where-Object Status -eq 'PASS').Count;Failed=@($results|Where-Object Status -eq 'FAIL').Count;Warnings=@($results|Where-Object Status -eq 'WARN').Count;Information=@($results|Where-Object Status -eq 'INFO').Count}
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
$summary|Format-List
if($summary.Failed){exit 2};if($summary.Warnings){exit 1};exit 0
