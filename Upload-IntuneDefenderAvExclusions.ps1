<#
.SYNOPSIS
Uploads a generated Defender AV exclusion payload to Intune through Microsoft Graph.

.REQUIREMENTS
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Permission: DeviceManagementConfiguration.ReadWrite.All

.NOTES
This creates an Intune device configuration profile. Assignments are intentionally separate so the imported policy can
be reviewed before targeting production devices.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PayloadPath = ".\out\intune-deviceconfiguration-defender-av-exclusions.json",
    [ValidateSet("Global", "USGov", "USGovDoD")]
    [string]$Cloud = "Global",
    [switch]$UseBeta
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $PayloadPath)) {
    throw "Payload not found: $PayloadPath. Run New-IntuneDefenderAvExclusionPayload.ps1 first."
}

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication module not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}

Import-Module Microsoft.Graph.Authentication

$graphHost = switch ($Cloud) {
    "Global" { "https://graph.microsoft.com" }
    "USGov" { "https://graph.microsoft.us" }
    "USGovDoD" { "https://dod-graph.microsoft.us" }
}

$graphEnvironment = switch ($Cloud) {
    "Global" { "Global" }
    "USGov" { "USGov" }
    "USGovDoD" { "USGovDoD" }
}

$profileUri = if ($UseBeta) {
    "$graphHost/beta/deviceManagement/deviceConfigurations"
} else {
    "$graphHost/v1.0/deviceManagement/deviceConfigurations"
}

Connect-MgGraph -Environment $graphEnvironment -Scopes "DeviceManagementConfiguration.ReadWrite.All" | Out-Null
$body = Get-Content -Path $PayloadPath -Raw

if ($PSCmdlet.ShouldProcess($profileUri, "Create Intune Defender AV exclusion device configuration")) {
    $created = Invoke-MgGraphRequest -Method POST -Uri $profileUri -Body $body -ContentType "application/json"
    $created | ConvertTo-Json -Depth 10
    Write-Host "Created policy id: $($created.id)"
    Write-Host "Review the policy in Intune before assigning it."
}
