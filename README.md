# MDE AV Exclusion Import Toolkit

PowerShell toolkit for turning an Excel workbook of Microsoft Defender Antivirus exclusions into Microsoft Defender portal / MDE Security Settings Management policies.

The standard workflow creates three unassigned policies:

- `MDE AV Exclusions - Windows`
- `MDE AV Exclusions - macOS`
- `MDE AV Exclusions - Linux`

The customer can review the policies in the Defender portal before assigning them to device groups.

## What This Does

- Reads `NewExclusions.xlsx` from the script folder.
- Normalizes exclusions into path, process, and extension categories.
- Splits exclusions by platform: Windows, macOS, and Linux.
- Creates one Defender portal endpoint security policy per platform.
- Creates the required temporary Entra app registration for Graph upload automation.
- Keeps generated payloads, customer Excel files, XML exports, and private app secrets out of Git by default.

## Quick Start

Copy the Excel workbook into the script folder and name it:

```text
NewExclusions.xlsx
```

Run PowerShell from the script folder:

```powershell
Set-Location C:\tools\mde-av-exclusion-import
Connect-AzAccount -Environment AzureUSGovernment

.\Convert-AvExclusions.ps1

.\New-MdeXdrDefenderAvExclusionFiles.ps1 `
    -SourceFilter Excel `
    -WindowsPrefix mde-xdr-windows-excel-master

.\New-MdeXdrGraphUploadApp.ps1 `
    -Cloud USGov `
    -DisplayName 'MDE AV Exclusion Import'

.\Publish-FinalExcelMdeAvExclusionPolicies.ps1 -WhatIf
.\Publish-FinalExcelMdeAvExclusionPolicies.ps1 -SkipExisting
```

Full customer instructions are in [DEPLOY_FROM_XLSX.md](DEPLOY_FROM_XLSX.md).

## Defender Portal Location

For GCC High, open:

```text
https://security.microsoft.us
```

Then go to:

```text
Endpoints > Configuration management > Endpoint security policies
```

## App Registration Piece

The app registration is automated by:

```powershell
.\New-MdeXdrGraphUploadApp.ps1
```

It creates an Entra app registration and service principal, grants Microsoft Graph application permission `DeviceManagementConfiguration.ReadWrite.All`, grants admin consent, and writes app details to:

```text
out\mde-xdr-upload-app-private.json
```

Keep that private file secure. It contains the temporary client secret and is intentionally ignored by Git.

## Important Files

- `DEPLOY_FROM_XLSX.md`: simple customer step-by-step guide.
- `Convert-AvExclusions.ps1`: parses Excel and optional SCCM/ConfigMgr XML exports.
- `New-MdeXdrDefenderAvExclusionFiles.ps1`: builds platform-specific policy input files.
- `New-MdeXdrGraphUploadApp.ps1`: creates the temporary upload app registration.
- `Publish-FinalExcelMdeAvExclusionPolicies.ps1`: creates one policy each for Windows, macOS, and Linux.
- `Remove-TemporaryMdeAvExclusionPolicies.ps1`: removes old test policies created by earlier runs.
- `Test-MdeXdrDefenderAvExclusionPolicies.ps1`: verifies policy counts through Graph.

## Notes

- The final policies are created unassigned by default.
- The scripts target GCC High by default where applicable.
- The Graph-backed policy creation path is used because Microsoft Graph is the backend for Defender portal Security Settings Management.
- Excel is required on the workstation that runs the parser because the workbook is read through Excel automation.
- If the Excel file changes, rerun the workflow from `Convert-AvExclusions.ps1` onward.