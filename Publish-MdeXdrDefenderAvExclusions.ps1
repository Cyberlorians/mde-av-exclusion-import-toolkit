<#
.SYNOPSIS
Creates Microsoft Defender portal / MDE Security Settings Management AV exclusion policies through Microsoft Graph.

.DESCRIPTION
Publishes platform-specific Defender Antivirus exclusion policies using the Intune deviceManagement
configurationPolicies Graph endpoint that backs Microsoft Defender portal Endpoint security policies.

This is intended for customers using MDE Security Settings Management from Defender XDR, not classic
Intune device enrollment workflows. The script creates policies unassigned by default. Use -AssignToGroupId
or -AssignToAllDevices only when the policy has been reviewed and the target scope is approved.

.REQUIREMENTS
Delegated testing: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Production automation: App registration with DeviceManagementConfiguration.ReadWrite.All application permission and admin consent

.EXAMPLE
.\Publish-MdeXdrDefenderAvExclusions.ps1 -Cloud USGov -Platform Windows -WhatIf

.EXAMPLE
.\Publish-MdeXdrDefenderAvExclusions.ps1 -Cloud USGov -Platform Windows

.EXAMPLE
.\Publish-MdeXdrDefenderAvExclusions.ps1 -Cloud USGov -Platform Windows -AssignToGroupId '00000000-0000-0000-0000-000000000000'

.EXAMPLE
.\Publish-MdeXdrDefenderAvExclusions.ps1 -Cloud USGov -Platform Windows -TenantId '<TENANT-ID>' -ClientId '<APP-ID>' -ClientSecret '<SECRET>'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Global", "USGov", "USGovDoD")]
    [string]$Cloud = "USGov",

    [ValidateSet("Windows", "macOS", "Linux", "All")]
    [string]$Platform = "Windows",

    [string]$OutDir = ".\out",

    [string]$PolicyNamePrefix = "MDE AV Exclusions",

    [string]$FilePrefixOverride,

    [string]$AssignToGroupId,

    [switch]$AssignToAllDevices,

    [switch]$UseDeviceCode,

    [string]$TenantId,

    [string]$ClientId,

    [string]$ClientSecret,

    [int]$MaxValuesPerSetting = 600,

    [switch]$PackPathsAsSingleCspValue,

    [switch]$SkipExisting,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($AssignToGroupId -and $AssignToAllDevices) {
    throw "Use either -AssignToGroupId or -AssignToAllDevices, not both."
}

if ($MaxValuesPerSetting -lt 1 -or $MaxValuesPerSetting -gt 600) {
    throw "MaxValuesPerSetting must be between 1 and 600. Graph rejected larger lists for Defender AV exclusions."
}

$useAppOnlyAuth = -not [string]::IsNullOrWhiteSpace($TenantId) -and -not [string]::IsNullOrWhiteSpace($ClientId) -and -not [string]::IsNullOrWhiteSpace($ClientSecret)

if (-not $UseDeviceCode -and -not $useAppOnlyAuth -and -not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication module not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}

if (-not $UseDeviceCode -and -not $useAppOnlyAuth) {
    Import-Module Microsoft.Graph.Authentication
}

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

$loginHost = switch ($Cloud) {
    "Global" { "https://login.microsoftonline.com" }
    "USGov" { "https://login.microsoftonline.us" }
    "USGovDoD" { "https://login.microsoftonline.us" }
}

$script:GraphConnected = $false
$script:GraphAccessToken = $null

function Connect-GraphWithClientSecret {
    $tokenUri = "$loginHost/$TenantId/oauth2/v2.0/token"
    $token = Invoke-RestMethod -Method POST -Uri $tokenUri -Body @{
        client_id = $ClientId
        client_secret = $ClientSecret
        scope = "$graphHost/.default"
        grant_type = "client_credentials"
    }

    $script:GraphAccessToken = $token.access_token
}

function Connect-GraphWithRawDeviceCode {
    $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    $scope = "$graphHost/DeviceManagementConfiguration.ReadWrite.All offline_access openid profile"
    $deviceCodeUri = "$loginHost/organizations/oauth2/v2.0/devicecode"
    $tokenUri = "$loginHost/organizations/oauth2/v2.0/token"

    $deviceCode = Invoke-RestMethod -Method POST -Uri $deviceCodeUri -Body @{
        client_id = $clientId
        scope = $scope
    }

    Write-Host ""
    Write-Host $deviceCode.message
    Write-Host ""

    $expiresAt = (Get-Date).AddSeconds([int]$deviceCode.expires_in)
    $interval = [Math]::Max([int]$deviceCode.interval, 5)

    while ((Get-Date) -lt $expiresAt) {
        Start-Sleep -Seconds $interval
        try {
            $token = Invoke-RestMethod -Method POST -Uri $tokenUri -Body @{
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                client_id = $clientId
                device_code = $deviceCode.device_code
            }

            $script:GraphAccessToken = $token.access_token
            return
        }
        catch {
            $errorBody = $_.ErrorDetails.Message
            if ($errorBody -match "authorization_pending") { continue }
            if ($errorBody -match "slow_down") {
                $interval += 5
                continue
            }
            throw
        }
    }

    throw "Device-code authentication timed out. Run the command again and complete sign-in at $($deviceCode.verification_uri)."
}

function Connect-GraphIfNeeded {
    if ($script:GraphConnected) { return }

    if ($UseDeviceCode) {
        Connect-GraphWithRawDeviceCode
    }
    elseif ($useAppOnlyAuth) {
        Connect-GraphWithClientSecret
    }
    else {
        Connect-MgGraph -Environment $graphEnvironment -Scopes "DeviceManagementConfiguration.ReadWrite.All" | Out-Null
    }

    $script:GraphConnected = $true
}

function Invoke-GraphApiRequest {
    param(
        [ValidateSet("GET", "POST")]
        [string]$Method,
        [string]$Uri,
        $Body,
        [string]$ContentType = "application/json"
    )

    if ($script:GraphAccessToken) {
        $headers = @{ Authorization = "Bearer $script:GraphAccessToken" }
        if ($PSBoundParameters.ContainsKey("Body") -and $null -ne $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $Body -ContentType $ContentType
        }
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }

    if ($PSBoundParameters.ContainsKey("Body") -and $null -ne $Body) {
        return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ContentType $ContentType
    }
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Test-IsGuidString {
    param([AllowNull()][string]$Value)
    return ($Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Get-ValuesFromPipeFile {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return @() }
    $raw = Get-Content -Path $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    return @($raw -split "\|" | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Split-ValueList {
    param(
        [string[]]$Values,
        [int]$Size
    )

    $items = @($Values)
    if ($items.Count -eq 0) { return ,@() }

    $chunks = @()
    for ($index = 0; $index -lt $items.Count; $index += $Size) {
        $endIndex = [Math]::Min($index + $Size - 1, $items.Count - 1)
        $chunks += ,@($items[$index..$endIndex])
    }
    return $chunks
}

function New-StringCollectionSetting {
    param(
        [string]$SettingDefinitionId,
        [AllowEmptyString()]
        [string]$SettingInstanceTemplateId,
        [AllowEmptyString()]
        [string]$SettingValueTemplateId,
        [string[]]$Values
    )

    if (-not $Values -or $Values.Count -eq 0) { return $null }

    $settingInstance = [ordered]@{
        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance"
        settingDefinitionId = $SettingDefinitionId
        simpleSettingCollectionValue = @($Values | ForEach-Object {
            [ordered]@{
                "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                value = $_
            }
        })
    }

    if (Test-IsGuidString -Value $SettingInstanceTemplateId) {
        $settingInstance.settingInstanceTemplateReference = [ordered]@{
            settingInstanceTemplateId = $SettingInstanceTemplateId
        }
    }

    return [ordered]@{
        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationSetting"
        settingInstance = $settingInstance
    }
}

function Get-PlatformConfig {
    param([string]$Name)

    switch ($Name) {
        "Windows" {
            return [pscustomobject]@{
                Name = "Windows"
                DisplayName = "Windows"
                FilePrefix = "mde-xdr-windows"
                GraphPlatform = "windows10"
                Technology = "microsoftSense"
                TemplateId = "45fea5e9-280d-4da1-9792-fb5736da0ca9_1"
                TemplateFamily = "endpointSecurityAntivirus"
                PathsDefinitionId = "device_vendor_msft_policy_config_defender_excludedpaths"
                PathsTemplateId = $null
                PathsValueTemplateId = $null
                ProcessesDefinitionId = "device_vendor_msft_policy_config_defender_excludedprocesses"
                ProcessesTemplateId = $null
                ProcessesValueTemplateId = $null
                ExtensionsDefinitionId = "device_vendor_msft_policy_config_defender_excludedextensions"
                ExtensionsTemplateId = $null
                ExtensionsValueTemplateId = $null
            }
        }
        "macOS" {
            return [pscustomobject]@{
                Name = "macOS"
                DisplayName = "macOS"
                FilePrefix = "mde-xdr-macos"
                GraphPlatform = "macOS"
                Technology = "microsoftSense"
                TemplateId = $null
                TemplateFamily = "endpointSecurityAntivirus"
            }
        }
        "Linux" {
            return [pscustomobject]@{
                Name = "Linux"
                DisplayName = "Linux"
                FilePrefix = "mde-xdr-linux"
                GraphPlatform = "linux"
                Technology = "microsoftSense"
                TemplateId = $null
                TemplateFamily = "endpointSecurityAntivirus"
            }
        }
        default { throw "Unknown platform: $Name" }
    }
}

function Resolve-TemplateMetadata {
    param([pscustomobject]$Config)

    if ($Config.TemplateId) {
        return $Config
    }

    Connect-GraphIfNeeded
    $templatesUri = "$graphHost/beta/deviceManagement/configurationPolicyTemplates?`$filter=templateFamily eq '$($Config.TemplateFamily)'"
    $templates = Invoke-GraphApiRequest -Method GET -Uri $templatesUri
    $match = @($templates.value | Where-Object {
        $_.platforms -eq $Config.GraphPlatform -or $_.platforms -match $Config.GraphPlatform
    } | Sort-Object displayName | Select-Object -First 1)

    if (-not $match) {
        throw "Could not discover $($Config.Name) Defender Antivirus exclusions template. Create one manually once in the portal or update this script with the tenant's template ID."
    }

    $Config | Add-Member -NotePropertyName TemplateId -NotePropertyValue $match.id -Force
    return $Config
}

function Resolve-WindowsSettingTemplateIds {
    param([pscustomobject]$Config)

    Connect-GraphIfNeeded
    $uri = "$graphHost/beta/deviceManagement/configurationPolicyTemplates('$($Config.TemplateId)')/settingTemplates?`$expand=settingDefinitions&`$top=1000"
    $response = Invoke-GraphApiRequest -Method GET -Uri $uri
    $templates = @($response.value)

    foreach ($template in $templates) {
        $settingInstanceTemplate = Get-ObjectPropertyValue -InputObject $template -Name "settingInstanceTemplate"
        $templateId = $null
        if ($settingInstanceTemplate) {
            $templateId = Get-ObjectPropertyValue -InputObject $settingInstanceTemplate -Name "settingInstanceTemplateId"
        }
        if (-not $templateId) {
            $templateId = Get-ObjectPropertyValue -InputObject $template -Name "settingInstanceTemplateId"
        }
        if (-not (Test-IsGuidString -Value $templateId)) { $templateId = $null }

        $valueTemplateId = $null
        $valueTemplates = $null
        if ($settingInstanceTemplate) {
            $valueTemplates = Get-ObjectPropertyValue -InputObject $settingInstanceTemplate -Name "simpleSettingCollectionValueTemplate"
        }
        if ($valueTemplates) {
            $valueTemplateId = @($valueTemplates | ForEach-Object { Get-ObjectPropertyValue -InputObject $_ -Name "settingValueTemplateId" } | Where-Object { Test-IsGuidString -Value $_ } | Select-Object -First 1)
        }

        $definitionIds = @()
        $settingDefinitionId = $null
        if ($settingInstanceTemplate) {
            $settingDefinitionId = Get-ObjectPropertyValue -InputObject $settingInstanceTemplate -Name "settingDefinitionId"
        }
        if (-not $settingDefinitionId) {
            $settingDefinitionId = Get-ObjectPropertyValue -InputObject $template -Name "settingDefinitionId"
        }
        $settingDefinitions = Get-ObjectPropertyValue -InputObject $template -Name "settingDefinitions"
        if ($settingDefinitionId) { $definitionIds += $settingDefinitionId }
        if ($settingDefinitions) {
            $definitionIds += @($settingDefinitions | ForEach-Object { Get-ObjectPropertyValue -InputObject $_ -Name "id" })
        }

        foreach ($definitionId in $definitionIds) {
            switch -Regex ($definitionId) {
                "excludedpaths$" {
                    $Config.PathsTemplateId = $templateId
                    $Config.PathsValueTemplateId = $valueTemplateId
                }
                "excludedprocesses$" {
                    $Config.ProcessesTemplateId = $templateId
                    $Config.ProcessesValueTemplateId = $valueTemplateId
                }
                "excludedextensions$" {
                    $Config.ExtensionsTemplateId = $templateId
                    $Config.ExtensionsValueTemplateId = $valueTemplateId
                }
            }
        }
    }

    return $Config
}

function New-PolicyAssignments {
    $assignments = @()
    if ($AssignToGroupId) {
        $assignments = @(
            [ordered]@{
                target = [ordered]@{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId = $AssignToGroupId
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    elseif ($AssignToAllDevices) {
        $assignments = @(
            [ordered]@{
                target = [ordered]@{
                    "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }

    return $assignments
}

function New-PolicyPayload {
    param(
        [pscustomobject]$Config,
        [string]$PolicyName,
        [string[]]$Paths,
        [string[]]$Processes,
        [string[]]$Extensions
    )

    $settings = @(@(
        New-StringCollectionSetting -SettingDefinitionId $Config.PathsDefinitionId -SettingInstanceTemplateId $Config.PathsTemplateId -SettingValueTemplateId $Config.PathsValueTemplateId -Values $Paths
        New-StringCollectionSetting -SettingDefinitionId $Config.ProcessesDefinitionId -SettingInstanceTemplateId $Config.ProcessesTemplateId -SettingValueTemplateId $Config.ProcessesValueTemplateId -Values $Processes
        New-StringCollectionSetting -SettingDefinitionId $Config.ExtensionsDefinitionId -SettingInstanceTemplateId $Config.ExtensionsTemplateId -SettingValueTemplateId $Config.ExtensionsValueTemplateId -Values $Extensions
    ) | Where-Object { $_ })

    return [ordered]@{
        name = $PolicyName
        description = "Imported from SCCM/ConfigMgr and NewExclusions.xlsx for MDE Security Settings Management. Review risky exclusions before broad assignment."
        platforms = $Config.GraphPlatform
        technologies = $Config.Technology
        roleScopeTagIds = @("0")
        templateReference = [ordered]@{
            templateId = $Config.TemplateId
            templateFamily = $Config.TemplateFamily
        }
        settings = @($settings)
        assignments = @(New-PolicyAssignments)
    }
}

function New-PolicyPayloads {
    param([pscustomobject]$Config)

    $paths = @(Get-ValuesFromPipeFile -Path (Join-Path $OutDir "$($Config.FilePrefix)-defender-av-exclusion-paths.txt"))
    $processes = @(Get-ValuesFromPipeFile -Path (Join-Path $OutDir "$($Config.FilePrefix)-defender-av-exclusion-processes.txt"))
    $extensions = @(Get-ValuesFromPipeFile -Path (Join-Path $OutDir "$($Config.FilePrefix)-defender-av-exclusion-extensions.txt"))

    if (($paths.Count + $processes.Count + $extensions.Count) -eq 0) {
        throw "No exclusions found for $($Config.Name) in $OutDir. Run New-MdeXdrDefenderAvExclusionFiles.ps1 first."
    }

    if ($Config.Name -ne "Windows") {
        throw "$($Config.Name) Graph upload metadata is not hardcoded yet. Use this script for Windows first, then discover macOS/Linux template metadata before upload."
    }

    if ($PackPathsAsSingleCspValue -and $paths.Count -gt 0) {
        $packedPaths = $paths -join "|"
        if ($packedPaths.Length -gt 87516) {
            throw "Packed ExcludedPaths value is $($packedPaths.Length) characters, which exceeds the setting maximumLength of 87516."
        }
        $paths = @($packedPaths)
    }

    if ($processes.Count -gt $MaxValuesPerSetting -or $extensions.Count -gt $MaxValuesPerSetting) {
        throw "Processes or extensions exceed $MaxValuesPerSetting values. Add chunking for those lists before publishing."
    }

    $pathChunks = [System.Collections.ArrayList]::new()
    if ($paths.Count -eq 0) {
        [void]$pathChunks.Add(@())
    }
    else {
        for ($index = 0; $index -lt $paths.Count; $index += $MaxValuesPerSetting) {
            $endIndex = [Math]::Min($index + $MaxValuesPerSetting - 1, $paths.Count - 1)
            [void]$pathChunks.Add(@($paths[$index..$endIndex]))
        }
    }

    $payloads = @()
    for ($chunkIndex = 0; $chunkIndex -lt $pathChunks.Count; $chunkIndex++) {
        $partNumber = $chunkIndex + 1
        $policyName = "$PolicyNamePrefix - $($Config.DisplayName) - Pilot"
        if ($pathChunks.Count -gt 1) {
            $policyName = "$policyName - Part $partNumber of $($pathChunks.Count)"
        }

        $payloads += [pscustomobject]@{
            PartNumber = $partNumber
            Payload = New-PolicyPayload `
                -Config $Config `
                -PolicyName $policyName `
                -Paths @($pathChunks[$chunkIndex]) `
                -Processes $(if ($chunkIndex -eq 0) { $processes } else { @() }) `
                -Extensions $(if ($chunkIndex -eq 0) { $extensions } else { @() })
        }
    }

    return $payloads
}

function Publish-Policy {
    param([string]$PlatformName)

    $config = Resolve-TemplateMetadata -Config (Get-PlatformConfig -Name $PlatformName)
    if (-not [string]::IsNullOrWhiteSpace($FilePrefixOverride)) {
        $config.FilePrefix = $FilePrefixOverride
    }
    if ($PlatformName -eq "Windows" -and (-not $WhatIfPreference -or $useAppOnlyAuth -or $UseDeviceCode)) {
        $config = Resolve-WindowsSettingTemplateIds -Config $config
    }
    $payloadItems = New-PolicyPayloads -Config $config

    $uri = "$graphHost/beta/deviceManagement/configurationPolicies"
    foreach ($payloadItem in $payloadItems) {
        $payload = $payloadItem.Payload
        $payloadPathPrefix = if (-not [string]::IsNullOrWhiteSpace($Config.FilePrefix)) { $Config.FilePrefix } else { "$($PlatformName.ToLowerInvariant())-mde-av-exclusions" }
        $payloadPath = Join-Path $OutDir "graph-upload-$payloadPathPrefix-part-$($payloadItem.PartNumber).json"
        $payload | ConvertTo-Json -Depth 100 | Set-Content -Path $payloadPath -Encoding UTF8 -WhatIf:$false

        $totalValues = @($payload.settings | ForEach-Object { $_.settingInstance.simpleSettingCollectionValue.Count } | Measure-Object -Sum).Sum
        $action = "Create $($payload.name) with $totalValues values"

        if ($PSCmdlet.ShouldProcess($uri, $action)) {
            Connect-GraphIfNeeded
            $existingUri = "$graphHost/beta/deviceManagement/configurationPolicies?`$filter=name eq '$($payload.name.Replace("'", "''"))'"
            $existing = Invoke-GraphApiRequest -Method GET -Uri $existingUri
            if ($existing.value.Count -gt 0 -and $SkipExisting) {
                $existingPolicy = @($existing.value | Select-Object -First 1)
                [pscustomobject]@{
                    Platform = $PlatformName
                    PolicyName = $existingPolicy.name
                    PolicyId = $existingPolicy.id
                    Assigned = [bool]($AssignToGroupId -or $AssignToAllDevices)
                    ValueCount = $totalValues
                    PayloadPath = $payloadPath
                    Status = "SkippedExisting"
                }
                continue
            }
            if ($existing.value.Count -gt 0 -and -not $Force) {
                throw "Policy already exists: $($payload.name). Use -Force to create another policy with the same name, or rename -PolicyNamePrefix."
            }

            $created = Invoke-GraphApiRequest -Method POST -Uri $uri -Body ($payload | ConvertTo-Json -Depth 100) -ContentType "application/json"
            [pscustomobject]@{
                Platform = $PlatformName
                PolicyName = $created.name
                PolicyId = $created.id
                Assigned = [bool]($AssignToGroupId -or $AssignToAllDevices)
                ValueCount = $totalValues
                PayloadPath = $payloadPath
                Status = "Created"
            }
        }
        else {
            [pscustomobject]@{
                Platform = $PlatformName
                PolicyName = $payload.name
                PolicyId = "WHATIF"
                Assigned = [bool]($AssignToGroupId -or $AssignToAllDevices)
                ValueCount = $totalValues
                PayloadPath = $payloadPath
                Status = "WhatIf"
            }
        }
    }
}

$selectedPlatforms = if ($Platform -eq "All") { @("Windows", "macOS", "Linux") } else { @($Platform) }
$results = foreach ($platformName in $selectedPlatforms) {
    Publish-Policy -PlatformName $platformName
}

$results | Format-Table -AutoSize