<#
.SYNOPSIS
Creates a Microsoft Graph payload for Windows Defender AV exclusions from normalized-exclusions.csv.

.DESCRIPTION
This creates an Intune Windows endpoint protection device configuration payload. This is the simplest Graph upload
path for Defender AV exclusions. It is suitable for Intune/co-managed Windows devices.

For Defender portal Endpoint security policies / MDE Security Settings Management, the same normalized exclusions
can be used, but the exact Settings Catalog/Endpoint Security template IDs should be discovered in the destination
tenant before automated creation.
#>
[CmdletBinding()]
param(
    [string]$CsvPath = ".\out\normalized-exclusions.csv",
    [string]$PolicyName = "Windows - MDE AV - Imported SCCM Exclusions - Pilot",
    [string]$OutPath = ".\out\intune-deviceconfiguration-defender-av-exclusions.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $CsvPath)) {
    throw "CSV not found: $CsvPath. Run Convert-AvExclusions.ps1 first."
}

$rows = Import-Csv -Path $CsvPath | Where-Object {
    $_.Platform -match "(?i)windows|server|workstation|unknown" -and
    $_.Type -in @("Path", "Process", "Extension", "ExtensionCandidate") -and
    -not [string]::IsNullOrWhiteSpace($_.Value)
}

$paths = @($rows | Where-Object Type -eq "Path" | Select-Object -ExpandProperty Value -Unique | Sort-Object)
$processes = @($rows | Where-Object Type -eq "Process" | Select-Object -ExpandProperty Value -Unique | Sort-Object)
$extensions = @($rows | Where-Object { $_.Type -in @("Extension", "ExtensionCandidate") } | ForEach-Object {
    $value = $_.Value.Trim()
    if ($value.StartsWith(".")) { $value.Substring(1) } else { $value }
} | Select-Object -Unique | Sort-Object)

$payload = [ordered]@{
    "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
    displayName = $PolicyName
    description = "Imported from ConfigMgr/SCCM AV exclusions. Review before production assignment."
    defenderFilesAndFoldersToExclude = $paths
    defenderProcessesToExclude = $processes
    defenderFileExtensionsToExclude = $extensions
}

$payload | ConvertTo-Json -Depth 10 | Set-Content -Path $OutPath -Encoding UTF8

Write-Host "Wrote $OutPath"
Write-Host "Path exclusions: $($paths.Count)"
Write-Host "Process exclusions: $($processes.Count)"
Write-Host "Extension exclusions: $($extensions.Count)"
Write-Host ""
Write-Host "Graph create command after Connect-MgGraph with DeviceManagementConfiguration.ReadWrite.All:"
Write-Host "Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations' -Body (Get-Content '$OutPath' -Raw) -ContentType 'application/json'"
