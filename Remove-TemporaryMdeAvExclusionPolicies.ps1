[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$AppPrivatePath = ".\out\mde-xdr-upload-app-private.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$graphHost = "https://graph.microsoft.us"
$loginHost = "https://login.microsoftonline.us"

$finalPolicyNames = @(
    "MDE AV Exclusions - Windows",
    "MDE AV Exclusions - macOS",
    "MDE AV Exclusions - Linux"
)

$temporaryNamePatterns = @(
    "MDE AV Exclusions - Windows - Pilot*",
    "MDE AV Exclusions - Windows SINGLE POLICY TEST*",
    "Windows Master AV Exclusions XML - Windows - Pilot*"
)

if (-not (Test-Path $AppPrivatePath)) { throw "App private file not found: $AppPrivatePath" }
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
    $nextLink = $response.PSObject.Properties["@odata.nextLink"]
    $nextUri = if ($nextLink) { $nextLink.Value } else { $null }
}

$temporaryPolicies = @($policies | Where-Object {
    $policyName = $_.name
    ($finalPolicyNames -notcontains $policyName) -and
    @($temporaryNamePatterns | Where-Object { $policyName -like $_ }).Count -gt 0
} | Sort-Object name)

foreach ($policy in $temporaryPolicies) {
    if ($PSCmdlet.ShouldProcess($policy.name, "Delete temporary/test policy")) {
        Invoke-RestMethod -Method DELETE -Uri "$graphHost/beta/deviceManagement/configurationPolicies/$($policy.id)" -Headers $headers | Out-Null
        [pscustomobject]@{ Name = $policy.name; Id = $policy.id; Status = "Deleted" }
    }
    else {
        [pscustomobject]@{ Name = $policy.name; Id = $policy.id; Status = "WhatIf" }
    }
}

if ($temporaryPolicies.Count -eq 0) {
    Write-Host "No temporary policies found."
}