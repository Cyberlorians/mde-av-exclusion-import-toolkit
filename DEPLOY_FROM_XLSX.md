# Deploy Defender AV Exclusions from Excel

This guide creates three Microsoft Defender portal / MDE Security Settings Management policies from one Excel workbook:

- `MDE AV Exclusions - Windows`
- `MDE AV Exclusions - macOS`
- `MDE AV Exclusions - Linux`

The policies are created unassigned so they can be reviewed before deployment to devices.

## Prerequisites

- A Windows workstation with PowerShell.
- Microsoft Excel installed locally. The parser reads the `.xlsx` file through Excel automation.
- Az PowerShell module installed.
- Permission to create an Entra app registration and grant Microsoft Graph application consent.
- Permission to create Defender portal endpoint security policies.
- GCC High tenant access.

Install Az PowerShell if needed:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
```

## Step 1: Put the Excel File in the Script Folder

Copy the Excel workbook into the same folder as the scripts:

```text
C:\tools\mde-av-exclusion-import\NewExclusions.xlsx
```

The file must be named exactly:

```text
NewExclusions.xlsx
```

## Step 2: Open PowerShell in the Script Folder

```powershell
Set-Location C:\tools\mde-av-exclusion-import
```

All commands below assume PowerShell is running from this folder.

## Step 3: Sign in to GCC High

```powershell
Connect-AzAccount -Environment AzureUSGovernment
```

Confirm the correct tenant is selected:

```powershell
Get-AzContext
```

## Step 4: Parse the Excel Workbook

```powershell
.\Convert-AvExclusions.ps1
```

This creates normalized exclusion files in:

```text
C:\tools\mde-av-exclusion-import\out
```

## Step 5: Build the Defender Policy Files

```powershell
.\New-MdeXdrDefenderAvExclusionFiles.ps1 `
    -SourceFilter Excel `
    -WindowsPrefix mde-xdr-windows-excel-master
```

This splits the workbook into Windows, macOS, and Linux policy input files.

## Step 6: Create the Upload App Registration

```powershell
.\New-MdeXdrGraphUploadApp.ps1 `
    -Cloud USGov `
    -DisplayName 'MDE AV Exclusion Import'
```

This creates a temporary Entra app registration with Microsoft Graph application permission `DeviceManagementConfiguration.ReadWrite.All` and grants admin consent.

The private app details are saved here:

```text
C:\tools\mde-av-exclusion-import\out\mde-xdr-upload-app-private.json
```

Keep this file private. It contains the temporary app secret.

## Step 7: Preview the Policy Creation

```powershell
.\Publish-FinalExcelMdeAvExclusionPolicies.ps1 -WhatIf
```

Expected result: PowerShell shows that it would create three unassigned policies:

- Windows
- macOS
- Linux

## Step 8: Create the Three Defender Policies

```powershell
.\Publish-FinalExcelMdeAvExclusionPolicies.ps1 -SkipExisting
```

Expected result:

```text
MDE AV Exclusions - Windows
MDE AV Exclusions - macOS
MDE AV Exclusions - Linux
```

## Step 9: Confirm in the Defender Portal

Open the Defender portal:

```text
https://security.microsoft.us
```

Go to:

```text
Endpoints > Configuration management > Endpoint security policies
```

Confirm the three policies exist. They should be unassigned by default.

## Step 10: Assign the Policies After Review

In the Defender portal, open each policy and assign it to the approved device group for that platform.

Recommended assignment pattern:

- Windows policy: assign to Windows MDE-managed devices.
- macOS policy: assign to macOS MDE-managed devices.
- Linux policy: assign to Linux MDE-managed devices.

## Optional: Remove Old Test Policies

Only run this if previous test or split policies were created and should be removed.

Preview cleanup:

```powershell
.\Remove-TemporaryMdeAvExclusionPolicies.ps1 -WhatIf
```

Delete the old test policies:

```powershell
.\Remove-TemporaryMdeAvExclusionPolicies.ps1
```

This does not delete the final three policies.

## Notes

- The scripts publish to GCC High by default.
- The default Excel filename is `NewExclusions.xlsx`. If a different filename is used, either rename it or run `.\Convert-AvExclusions.ps1 -ExcelPath .\YourFile.xlsx`.
- The policies are created through Microsoft Graph because that is the backend for Defender portal Security Settings Management.
- The customer does not need Intune device enrollment to use these MDE Security Settings Management policies.
- The policies are intentionally created unassigned so they can be reviewed before deployment.
- If the Excel file changes, rerun the steps from Step 4 onward.