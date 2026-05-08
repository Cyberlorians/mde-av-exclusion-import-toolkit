<#
.SYNOPSIS
Creates Defender portal / MDE Security Settings Management friendly exclusion files.

.DESCRIPTION
Uses out\normalized-exclusions.csv from Convert-AvExclusions.ps1 and emits reviewable files for
Microsoft Defender portal Endpoint security policies. This is for customers managing Defender Antivirus
through Microsoft Defender for Endpoint Security Settings Management, not classic Intune device enrollment.

Outputs platform-specific bundles for Windows, macOS, and Linux.
#>
[CmdletBinding()]
param(
    [string]$CsvPath = ".\out\normalized-exclusions.csv",
    [string]$OutDir = ".\out",

    [string[]]$SourceFilter,

    [switch]$WindowsOnly,

    [string]$WindowsPrefix = "mde-xdr-windows"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $CsvPath)) {
    throw "CSV not found: $CsvPath. Run Convert-AvExclusions.ps1 first."
}

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$allRows = Import-Csv -Path $CsvPath | Where-Object {
    $_.Type -in @("Path", "Process", "Extension", "ExtensionCandidate") -and
    -not [string]::IsNullOrWhiteSpace($_.Value)
}

if ($SourceFilter -and $SourceFilter.Count -gt 0) {
    $allRows = @($allRows | Where-Object { $_.Source -in $SourceFilter })
}

function Get-PlatformRows {
    param(
        [object[]]$Rows,
        [string]$PlatformName
    )

    switch ($PlatformName) {
        "windows" { return @($Rows | Where-Object { $_.Platform -match "(?i)windows|server|workstation|unknown" }) }
        "macos" { return @($Rows | Where-Object { $_.Platform -match "(?i)^mac|macos|os x" }) }
        "linux" { return @($Rows | Where-Object { $_.Platform -match "(?i)^linux$|linux" }) }
        default { throw "Unknown platform: $PlatformName" }
    }
}

function New-PlatformBundle {
    param(
        [object[]]$Rows,
        [string]$Prefix,
        [string]$DisplayPlatform,
        [string]$PolicyTemplate
    )

    $paths = @($Rows | Where-Object Type -eq "Path" | Select-Object -ExpandProperty Value -Unique | Sort-Object)
    $processes = @($Rows | Where-Object Type -eq "Process" | Select-Object -ExpandProperty Value -Unique | Sort-Object)
    $extensions = @($Rows | Where-Object { $_.Type -in @("Extension", "ExtensionCandidate") } | ForEach-Object {
        $value = $_.Value.Trim()
        $value -split "[|,;]"
    } | ForEach-Object {
        $extension = $_.Trim()
        if ($extension.StartsWith(".")) { $extension.Substring(1) } else { $extension }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique | Sort-Object)

    $portalCsv = Join-Path $OutDir "$Prefix-defender-av-exclusions.csv"
    $pathsTxt = Join-Path $OutDir "$Prefix-defender-av-exclusion-paths.txt"
    $processesTxt = Join-Path $OutDir "$Prefix-defender-av-exclusion-processes.txt"
    $extensionsTxt = Join-Path $OutDir "$Prefix-defender-av-exclusion-extensions.txt"
    $jsonPath = Join-Path $OutDir "$Prefix-defender-av-exclusions.json"

    $exportRows = @()
    $exportRows += $paths | ForEach-Object { [pscustomobject]@{ Type = "Path"; Value = $_ } }
    $exportRows += $processes | ForEach-Object { [pscustomobject]@{ Type = "Process"; Value = $_ } }
    $exportRows += $extensions | ForEach-Object { [pscustomobject]@{ Type = "Extension"; Value = $_ } }

    $exportRows | Export-Csv -Path $portalCsv -NoTypeInformation
    ($paths -join "|") | Set-Content -Path $pathsTxt -Encoding UTF8
    ($processes -join "|") | Set-Content -Path $processesTxt -Encoding UTF8
    ($extensions -join "|") | Set-Content -Path $extensionsTxt -Encoding UTF8

    [ordered]@{
        Target = "Microsoft Defender portal Endpoint security policy / MDE Security Settings Management"
        PolicyTemplate = $PolicyTemplate
        Platform = $DisplayPlatform
        ExcludedPaths = $paths
        ExcludedProcesses = $processes
        ExcludedExtensions = $extensions
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8

    return [pscustomobject]@{
        Platform = $DisplayPlatform
        Prefix = $Prefix
        Csv = $portalCsv
        PathsFile = $pathsTxt
        ProcessesFile = $processesTxt
        ExtensionsFile = $extensionsTxt
        Json = $jsonPath
        Paths = $paths.Count
        Processes = $processes.Count
        Extensions = $extensions.Count
        Total = $exportRows.Count
    }
}

$bundles = @(
    New-PlatformBundle -Rows (Get-PlatformRows -Rows $allRows -PlatformName "windows") -Prefix $WindowsPrefix -DisplayPlatform "Windows 10, Windows 11, and Windows Server" -PolicyTemplate "Microsoft Defender Antivirus exclusions"
)

if (-not $WindowsOnly) {
    $bundles += @(
        New-PlatformBundle -Rows (Get-PlatformRows -Rows $allRows -PlatformName "macos") -Prefix "mde-xdr-macos" -DisplayPlatform "macOS" -PolicyTemplate "Microsoft Defender Antivirus exclusions"
        New-PlatformBundle -Rows (Get-PlatformRows -Rows $allRows -PlatformName "linux") -Prefix "mde-xdr-linux" -DisplayPlatform "Linux" -PolicyTemplate "Microsoft Defender Antivirus exclusions"
    )
}

$windowsBundle = $bundles | Select-Object -First 1

if ($WindowsPrefix -eq "mde-xdr-windows" -and -not $SourceFilter) {
    Copy-Item -Path $windowsBundle.Csv -Destination (Join-Path $OutDir "mde-xdr-defender-av-exclusions.csv") -Force
    Copy-Item -Path $windowsBundle.PathsFile -Destination (Join-Path $OutDir "mde-xdr-defender-av-exclusion-paths.txt") -Force
    Copy-Item -Path $windowsBundle.ProcessesFile -Destination (Join-Path $OutDir "mde-xdr-defender-av-exclusion-processes.txt") -Force
    Copy-Item -Path $windowsBundle.ExtensionsFile -Destination (Join-Path $OutDir "mde-xdr-defender-av-exclusion-extensions.txt") -Force
    Copy-Item -Path $windowsBundle.Json -Destination (Join-Path $OutDir "mde-xdr-defender-av-exclusions.json") -Force
}

$summaryFileName = if ($WindowsPrefix -eq "mde-xdr-windows" -and -not $SourceFilter) { "mde-xdr-policy-summary.csv" } else { "$WindowsPrefix-policy-summary.csv" }
$summaryPath = Join-Path $OutDir $summaryFileName
$bundles | Export-Csv -Path $summaryPath -NoTypeInformation

$runbookFileName = if ($WindowsPrefix -eq "mde-xdr-windows" -and -not $SourceFilter) { "mde-xdr-import-runbook.md" } else { "$WindowsPrefix-import-runbook.md" }
$runbookPath = Join-Path $OutDir $runbookFileName
$runbook = @"
# Defender AV Exclusions - MDE/XDR Import Runbook

Target: Microsoft Defender portal Endpoint security policies using MDE Security Settings Management.

GCC High portal: https://security.microsoft.us

## Windows policy

Create path:
Endpoints > Configuration management > Endpoint security policies > Windows policies > Create new policy

Platform: Windows 10, Windows 11, and Windows Server
Template: Microsoft Defender Antivirus exclusions

Use these files:
- Paths: out\\mde-xdr-windows-defender-av-exclusion-paths.txt
- Processes: out\\mde-xdr-windows-defender-av-exclusion-processes.txt
- Extensions: out\\mde-xdr-windows-defender-av-exclusion-extensions.txt
- Review CSV: out\\mde-xdr-windows-defender-av-exclusions.csv

Windows counts:
- Paths: $($windowsBundle.Paths)
- Processes: $($windowsBundle.Processes)
- Extensions: $($windowsBundle.Extensions)

## macOS policy

Create a separate macOS Microsoft Defender Antivirus exclusions policy if macOS devices are in scope.

Use these files:
- Paths: out\\mde-xdr-macos-defender-av-exclusion-paths.txt
- Processes: out\\mde-xdr-macos-defender-av-exclusion-processes.txt
- Extensions: out\\mde-xdr-macos-defender-av-exclusion-extensions.txt
- Review CSV: out\\mde-xdr-macos-defender-av-exclusions.csv

## Linux policy

Create a separate Linux Microsoft Defender Antivirus exclusions policy if Linux devices are in scope.

Use these files:
- Paths: out\\mde-xdr-linux-defender-av-exclusion-paths.txt
- Processes: out\\mde-xdr-linux-defender-av-exclusion-processes.txt
- Extensions: out\\mde-xdr-linux-defender-av-exclusion-extensions.txt
- Review CSV: out\\mde-xdr-linux-defender-av-exclusions.csv

## Review before assignment

Review out\\risky-exclusions.csv before assigning broadly. The current findings are broad user profile, ProgramData, temp path, and high-risk process exclusions.

Do not use out\\intune-deviceconfiguration-defender-av-exclusions.json for this customer unless they explicitly choose classic Intune device configuration.
"@
$runbook | Set-Content -Path $runbookPath -Encoding UTF8

Write-Host "Wrote $summaryPath"
Write-Host "Wrote $runbookPath"
Write-Host ""
Write-Host "MDE/XDR Defender portal counts:"
$bundles | Select-Object Platform,Paths,Processes,Extensions,Total | Format-Table -AutoSize