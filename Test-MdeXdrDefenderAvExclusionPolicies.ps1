[CmdletBinding()]
param(
    [string]$AppPrivatePath = ".\out\mde-xdr-upload-app-private.json",
    [string]$NamePrefix = "MDE AV Exclusions",
    [ValidateSet("Global", "USGov", "USGovDoD")]
    [string]$Cloud = "USGov"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $AppPrivatePath)) {
    throw "App private file not found: $AppPrivatePath"
}

$graphHost = switch ($Cloud) {
    "Global" { "https://graph.microsoft.com" }
    "USGov" { "https://graph.microsoft.us" }
    "USGovDoD" { "https://dod-graph.microsoft.us" }
}

$loginHost = switch ($Cloud) {
    "Global" { "https://login.microsoftonline.com" }
    "USGov" { "https://login.microsoftonline.us" }
    "USGovDoD" { "https://login.microsoftonline.us" }
}

$app = Get-Content $AppPrivatePath -Raw | ConvertFrom-Json
$token = Invoke-RestMethod -Method POST -Uri "$loginHost/$($app.TenantId)/oauth2/v2.0/token" -Body @{
    client_id = $app.ClientId
    client_secret = $app.ClientSecret
    scope = "$graphHost/.default"
    grant_type = "client_credentials"
}

$headers = @{ Authorization = "Bearer $($token.access_token)" }
$policies = @()
$nextUri = "$graphHost/beta/deviceManagement/configurationPolicies?`$top=100"

while ($nextUri) {
    $response = Invoke-RestMethod -Method GET -Uri $nextUri -Headers $headers
    $policies += @($response.value)
    $nextLinkProperty = $response.PSObject.Properties["@odata.nextLink"]
    $nextUri = if ($nextLinkProperty) { $nextLinkProperty.Value } else { $null }
}

$matches = @($policies | Where-Object { $_.name -like "$NamePrefix*" } | Sort-Object name)

foreach ($policy in $matches) {
    $assignmentsUri = "$graphHost/beta/deviceManagement/configurationPolicies/$($policy.id)/assignments"
    $assignments = Invoke-RestMethod -Method GET -Uri $assignmentsUri -Headers $headers
    $settingsUri = "$graphHost/beta/deviceManagement/configurationPolicies/$($policy.id)/settings"
    $settings = Invoke-RestMethod -Method GET -Uri $settingsUri -Headers $headers
    $valueCount = @($settings.value | ForEach-Object { $_.settingInstance.simpleSettingCollectionValue.Count } | Measure-Object -Sum).Sum
    [pscustomobject]@{
        Name = $policy.name
        Id = $policy.id
        Platforms = $policy.platforms
        Technologies = $policy.technologies
        SettingCount = @($settings.value).Count
        ValueCount = $valueCount
        AssignmentCount = @($assignments.value).Count
    }
}

if ($matches.Count -eq 0) {
    Write-Warning "No policies found matching '$NamePrefix*'. Total policies visible to app: $($policies.Count)."
}