<#
.SYNOPSIS
Creates a temporary Entra app registration for app-only MDE/XDR AV exclusion uploads.

.DESCRIPTION
Uses the current Az PowerShell context to create an app registration and service principal, add the
Microsoft Graph application permission DeviceManagementConfiguration.ReadWrite.All, grant admin consent,
and create a client secret. Intended for one-time Defender AV exclusion policy imports.

.EXAMPLE
Connect-AzAccount -Environment AzureUSGovernment
.\New-MdeXdrGraphUploadApp.ps1 -Cloud USGov -DisplayName 'MDE AV Exclusion Import'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Global", "USGov", "USGovDoD")]
    [string]$Cloud = "USGov",

    [string]$DisplayName = "MDE AV Exclusion Import",

    [int]$SecretLifetimeHours = 8,

    [string]$OutDir = ".\out"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Module -ListAvailable Az.Accounts)) {
    throw "Az.Accounts module is required. Install-Module Az.Accounts -Scope CurrentUser"
}

Import-Module Az.Accounts

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$graphHost = switch ($Cloud) {
    "Global" { "https://graph.microsoft.com" }
    "USGov" { "https://graph.microsoft.us" }
    "USGovDoD" { "https://dod-graph.microsoft.us" }
}

function ConvertFrom-SecureStringToPlainText {
    param([securestring]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

$context = Get-AzContext
if (-not $context) {
    throw "No Az context found. Run: Connect-AzAccount -Environment AzureUSGovernment"
}

$tenantId = $context.Tenant.Id
$tokenResult = Get-AzAccessToken -ResourceUrl $graphHost
$accessToken = if ($tokenResult.Token -is [securestring]) {
    ConvertFrom-SecureStringToPlainText -SecureString $tokenResult.Token
}
else {
    [string]$tokenResult.Token
}

$headers = @{ Authorization = "Bearer $accessToken" }

function Invoke-LocalGraphRequest {
    param(
        [ValidateSet("GET", "POST")]
        [string]$Method,
        [string]$Uri,
        $Body
    )

    if ($PSBoundParameters.ContainsKey("Body")) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 20) -ContentType "application/json"
    }

    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
}

$graphServicePrincipal = Invoke-LocalGraphRequest -Method GET -Uri "$graphHost/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'"
$graphSp = @($graphServicePrincipal.value | Select-Object -First 1)
if (-not $graphSp) { throw "Could not find Microsoft Graph service principal in tenant $tenantId." }

$role = @($graphSp.appRoles | Where-Object {
    $_.value -eq "DeviceManagementConfiguration.ReadWrite.All" -and
    $_.allowedMemberTypes -contains "Application" -and
    $_.isEnabled
} | Select-Object -First 1)

if (-not $role) { throw "Could not find Microsoft Graph app role DeviceManagementConfiguration.ReadWrite.All." }

$appBody = [ordered]@{
    displayName = $DisplayName
    signInAudience = "AzureADMyOrg"
    requiredResourceAccess = @(
        [ordered]@{
            resourceAppId = "00000003-0000-0000-c000-000000000000"
            resourceAccess = @(
                [ordered]@{
                    id = $role.id
                    type = "Role"
                }
            )
        }
    )
}

if ($PSCmdlet.ShouldProcess($DisplayName, "Create app registration, service principal, secret, and Graph app-role assignment")) {
    $app = Invoke-LocalGraphRequest -Method POST -Uri "$graphHost/v1.0/applications" -Body $appBody
    $servicePrincipal = Invoke-LocalGraphRequest -Method POST -Uri "$graphHost/v1.0/servicePrincipals" -Body @{ appId = $app.appId }

    $assignmentBody = [ordered]@{
        principalId = $servicePrincipal.id
        resourceId = $graphSp.id
        appRoleId = $role.id
    }
    $assignment = Invoke-LocalGraphRequest -Method POST -Uri "$graphHost/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments" -Body $assignmentBody

    $secretEnd = (Get-Date).ToUniversalTime().AddHours($SecretLifetimeHours).ToString("o")
    $secret = Invoke-LocalGraphRequest -Method POST -Uri "$graphHost/v1.0/applications/$($app.id)/addPassword" -Body @{
        passwordCredential = [ordered]@{
            displayName = "one-time-import-$(Get-Date -Format yyyyMMddHHmmss)"
            endDateTime = $secretEnd
        }
    }

    $result = [ordered]@{
        TenantId = $tenantId
        ClientId = $app.appId
        ApplicationObjectId = $app.id
        ServicePrincipalObjectId = $servicePrincipal.id
        GraphAppRole = "DeviceManagementConfiguration.ReadWrite.All"
        GraphAppRoleId = $role.id
        AppRoleAssignmentId = $assignment.id
        SecretExpires = $secret.endDateTime
        ClientSecret = $secret.secretText
    }

    $privatePath = Join-Path $OutDir "mde-xdr-upload-app-private.json"
    $publicPath = Join-Path $OutDir "mde-xdr-upload-app.json"

    $result | ConvertTo-Json -Depth 10 | Set-Content -Path $privatePath -Encoding UTF8
    $public = [ordered]@{
        TenantId = $tenantId
        ClientId = $app.appId
        ApplicationObjectId = $app.id
        ServicePrincipalObjectId = $servicePrincipal.id
        GraphAppRole = "DeviceManagementConfiguration.ReadWrite.All"
        SecretExpires = $secret.endDateTime
        PrivateSecretFile = $privatePath
    }
    $public | ConvertTo-Json -Depth 10 | Set-Content -Path $publicPath -Encoding UTF8

    [pscustomobject]$public
}