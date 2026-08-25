<#
.SYNOPSIS
    Bulk-import this baseline's policies into CIPP as Intune Templates.

.DESCRIPTION
    Reads manifest.cipp and POSTs each policy to CIPP's AddIntuneTemplate endpoint, so the
    18 policies land as reusable templates in one pass instead of 18 rounds of copy-paste
    through the CIPP UI.

    Authentication reuses the CIPP app registration already configured for the CIPP MCP
    bridge (~/.local/share/cipp-mcp/config.json on Linux). No new secret is created or
    stored. The client secret stays AES-encrypted at rest and is decrypted only in memory
    for the token request.

    This writes to CIPP. It defaults to -WhatIf: nothing is sent until you pass
    -Execute explicitly.

.PARAMETER ConfigPath
    Path to the cipp-mcp config.json. Defaults to the standard per-user location.

.PARAMETER Execute
    Actually create the templates. Without this the script only reports what it would do.

.PARAMETER Prefix
    Prepended to each template's display name in CIPP. Use this to make the client-specific
    set distinguishable from the generic baseline, e.g. -Prefix 'Lloyds '.

    .PARAMETER Only
    Import just the named files (matched on the manifest 'file' value). Repeatable.

    .PARAMETER ExistingAction
    What to do when CIPP already contains a template with the resolved display name. The default,
    Fail, aborts before creating anything. Skip supports safe resume after a partial run. Duplicate
    is an explicit escape hatch when a same-named second copy is genuinely intended.

.EXAMPLE
    ./Import-CippIntuneTemplates.ps1
    Dry run. Lists every template that would be created, with its resolved name and type.

.EXAMPLE
    ./Import-CippIntuneTemplates.ps1 -Execute
    Creates all 18 templates in CIPP under their generic baseline names.

    .EXAMPLE
    ./Import-CippIntuneTemplates.ps1 -Execute -Prefix 'Lloyds - ' -Only 01-compliance-windows.json
    Creates a single client-specific template.

    .EXAMPLE
    ./Import-CippIntuneTemplates.ps1 -Execute -ExistingAction Skip
    Safely resumes a partial import by skipping display names already stored in CIPP.

.NOTES
    Templates created here are NOT assigned to anything. Assignment stays a deliberate,
    separate step in CIPP or the Intune portal - see README.md for the rollout order.
#>
# PositionalBinding is off deliberately: with it on, a stray extra argument after
# -Only binds to $ConfigPath, and because the policy files sit in this directory the
# script would happily read a policy as its own config and derive a garbage endpoint.
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$ConfigPath = (Join-Path ($env:XDG_DATA_HOME ? $env:XDG_DATA_HOME : (Join-Path $HOME '.local/share')) 'cipp-mcp/config.json'),
    [switch]$Execute,
    [string]$Prefix = '',
    [string[]]$Only,
    [ValidateSet('Fail', 'Skip', 'Duplicate')]
    [string]$ExistingAction = 'Fail'
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

function Get-PlainTextSecret {
    # Mirrors cipp-mcp-bridge.ps1: AES with a key file beside the config.
    # Format: "<base64 iv>:<base64 ciphertext>".
    param([Parameter(Mandatory)][string]$EncryptedSecret, [Parameter(Mandatory)][string]$ConfigDirectory)

    $keyPath = Join-Path $ConfigDirectory 'key.bin'
    if (-not (Test-Path -LiteralPath $keyPath)) {
        throw "Encryption key not found at '$keyPath'."
    }
    $parts = $EncryptedSecret -split ':', 2
    if ($parts.Count -ne 2) { throw 'Malformed encrypted secret (expected "<iv>:<ciphertext>").' }

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Key = [Convert]::FromBase64String((Get-Content -LiteralPath $keyPath -Raw))
        $aes.IV = [Convert]::FromBase64String($parts[0])
        $cipherBytes = [Convert]::FromBase64String($parts[1])
        $decryptor = $aes.CreateDecryptor()
        return [Text.Encoding]::UTF8.GetString($decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length))
    } finally {
        $aes.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "CIPP configuration not found at '$ConfigPath'. Run setup-cipp-mcp.ps1 (in ~/Documents/Scripts/MCP/cipp-mcp) first, or pass -ConfigPath."
}
$settings = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json

# Fail loudly on a file that parses as JSON but is not a CIPP config, rather than
# deriving an empty endpoint and only discovering it at the first POST.
foreach ($required in @('CippMcpUrl', 'TenantId', 'ClientId', 'EncryptedClientSecret')) {
    if ([string]::IsNullOrWhiteSpace([string]$settings.$required)) {
        throw "'$ConfigPath' is missing '$required' - this does not look like a cipp-mcp config.json."
    }
}
$configDir = Split-Path -Parent $ConfigPath

# The stored URL points at the MCP entrypoint; derive the CIPP API base from it.
$apiBase = ($settings.CippMcpUrl -replace '(?i)/api/ExecMcp/?$', '')
if ($apiBase -notmatch '^https://') { throw "Could not derive an HTTPS CIPP API base from '$($settings.CippMcpUrl)'." }
$endpoint = "$apiBase/api/AddIntuneTemplate"

$manifestPath = Join-Path $scriptRoot 'manifest.cipp'
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "manifest.cipp not found next to this script." }
$policies = (Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json).policies

if ($Only) {
    # `pwsh -File script.ps1 -Only a,b` hands the whole list over as a single string,
    # so split on commas here. Harmless when invoked with a real array from a shell.
    $wanted = $Only |
        ForEach-Object { $_ -split ',' } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }

    $policies = $policies | Where-Object { $wanted -contains $_.file }
    $missing = $wanted | Where-Object { $policies.file -notcontains $_ }
    if ($missing) {
        throw "Not in manifest: $($missing -join ', '). Valid values: $(((Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json).policies.file) -join ', ')"
    }
}

# Resolve every policy up front so a bad file aborts before anything is sent.
$work = foreach ($policy in $policies) {
    $path = Join-Path $scriptRoot $policy.file
    if (-not (Test-Path -LiteralPath $path)) { throw "Policy file missing: $($policy.file)" }

    $raw = Get-Content -Raw -LiteralPath $path
    try { $parsed = $raw | ConvertFrom-Json } catch { throw "$($policy.file): invalid JSON - $($_.Exception.Message)" }

    # Settings Catalog policies name themselves with 'name'; the rest use 'displayName'.
    $name = if ($parsed.PSObject.Properties.Name -contains 'displayName') { $parsed.displayName } else { $parsed.name }
    if ([string]::IsNullOrWhiteSpace($name)) { throw "$($policy.file): no displayName or name field." }

    [pscustomobject]@{
        File         = $policy.file
        Name         = "$Prefix$name"
        Description  = [string]$parsed.description
        TemplateType = $policy.templateType
        AssignOrder  = $policy.assignOrder
        RawJSON      = $raw
    }
}

Write-Host ''
Write-Host "CIPP endpoint : $endpoint"
Write-Host "Templates     : $($work.Count)"
Write-Host "Mode          : $(if ($Execute) { 'EXECUTE - templates will be created' } else { 'DRY RUN - nothing will be sent' })"
Write-Host ''
$work | Sort-Object AssignOrder, File |
    Format-Table @{L='Wave';E={$_.AssignOrder}}, @{L='Type';E={$_.TemplateType}}, @{L='Template name';E={$_.Name}} -AutoSize

if (-not $Execute) {
    Write-Host 'Dry run complete. Re-run with -Execute to create these templates in CIPP.'
    return
}

$clientSecret = Get-PlainTextSecret -EncryptedSecret $settings.EncryptedClientSecret -ConfigDirectory $configDir
try {
    $token = Invoke-RestMethod -Method Post -ContentType 'application/x-www-form-urlencoded' `
        -Uri "https://login.microsoftonline.com/$($settings.TenantId)/oauth2/v2.0/token" `
        -Body @{
            client_id     = [string]$settings.ClientId
            client_secret = $clientSecret
            scope         = if ($settings.Scope) { [string]$settings.Scope } else { "api://$($settings.ClientId)/.default" }
            grant_type    = 'client_credentials'
        }
} finally {
    $clientSecret = $null
}
if (-not $token.access_token) { throw 'Microsoft Entra did not return an access token.' }
$headers = @{ Authorization = "Bearer $($token.access_token)"; Accept = 'application/json' }

# AddIntuneTemplate always creates a new GUID. Preflight the saved-template list so retries do not
# silently create same-named twins. This check happens before the first write.
try {
    $existingResponse = Invoke-RestMethod -Uri "$apiBase/api/ListIntuneTemplates?View=true" -Method Get -Headers $headers
    $existingTemplates = if ($existingResponse.Results) { @($existingResponse.Results) } else { @($existingResponse) }
} catch {
    throw "Could not preflight existing CIPP templates; no templates were created. $($_.Exception.Message)"
}

$existingByName = @{}
foreach ($existing in $existingTemplates) {
    if (-not [string]::IsNullOrWhiteSpace([string]$existing.displayName)) {
        $existingByName[[string]$existing.displayName] = $existing
    }
}
$collisions = @($work | Where-Object { $existingByName.ContainsKey($_.Name) })
if ($collisions -and $ExistingAction -eq 'Fail') {
    throw "CIPP already contains template(s) named: $($collisions.Name -join ', '). No templates were created. Use -ExistingAction Skip to resume safely, or Duplicate to create intentional twins."
}
if ($collisions -and $ExistingAction -eq 'Skip') {
    foreach ($collision in $collisions) {
        Write-Host "  skip $($collision.Name)  -  already exists in CIPP"
    }
    $work = @($work | Where-Object { -not $existingByName.ContainsKey($_.Name) })
}
if (-not $work) {
    Write-Host 'Nothing to create after the existing-template preflight.'
    return
}

$created = 0
$failed = @()
foreach ($item in $work) {
    $body = @{
        displayName  = $item.Name
        description  = $item.Description
        RawJSON      = $item.RawJSON
        TemplateType = $item.TemplateType
    } | ConvertTo-Json -Depth 5 -Compress

    try {
        $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -ContentType 'application/json' -Body $body
        $result = if ($response.Results) { $response.Results } else { 'created' }
        Write-Host "  ok   $($item.Name)  -  $result"
        $created++
    } catch {
        $detail = $_.Exception.Message
        if ($_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
        Write-Warning "  FAIL $($item.Name): $detail"
        $failed += [pscustomobject]@{ Template = $item.Name; File = $item.File; Error = $detail }
    }
}

Write-Host ''
Write-Host "Created $created of $($work.Count) templates."
if ($failed) {
    Write-Host ''
    Write-Warning "$($failed.Count) failed:"
    $failed | Format-Table -AutoSize
    Write-Host 'If a Settings Catalog policy was rejected, re-run "python3 build.py --plain" to drop the'
    Write-Host 'endpoint-security template linkage, then retry just that file with -Only.'
    exit 1
}
Write-Host ''
Write-Host 'Templates are created but NOT assigned. See README.md for the rollout order before assigning.'
