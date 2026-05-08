# MDE AV Exclusion Import Toolkit

This toolkit creates Microsoft Defender portal / MDE Security Settings Management antivirus exclusion policies from an Excel workbook.

The default deployment creates three unassigned policies:

- `MDE AV Exclusions - Windows`
- `MDE AV Exclusions - macOS`
- `MDE AV Exclusions - Linux`

The policies are created unassigned so they can be reviewed before deployment.

## Who Does What

There are two roles in this workflow:

- **Global Admin / Privileged Admin**: creates the temporary Entra app registration and grants Microsoft Graph consent.
- **Operator**: places the Excel workbook in the script folder, runs the import scripts, and creates the unassigned Defender policies by using the app registration file from the admin.

The operator does **not** need permission to create app registrations if the Global Admin completes Step 3 and gives the operator the generated private app file.

## Prerequisites

- Windows workstation with PowerShell.
- Microsoft Excel installed locally. The workbook parser uses Excel automation.
- Az PowerShell module installed.
- GCC High tenant access.
- Excel workbook named `NewExclusions.xlsx`.

Install Az PowerShell if needed:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
```

Clone or download this repository, then open PowerShell from the repository folder.

Example folder:

```powershell
Set-Location C:\tools\mde-av-exclusion-import
```

## Step 1: Add the Excel Workbook

Copy the workbook into the same folder as the scripts and name it exactly:

```text
NewExclusions.xlsx
```

If you use a different filename, pass it to the parser later with `-ExcelPath`.

## Step 2: Sign in to GCC High

The Global Admin or operator should sign in depending on which step they are performing.

```powershell
Connect-AzAccount -Environment AzureUSGovernment
Get-AzContext
```

Confirm the selected tenant is correct before continuing.

## Step 3: Global Admin Creates the Upload App

Run this step as a Global Admin or another account that can create app registrations, add Microsoft Graph application permissions, and grant admin consent.

```powershell
.\New-MdeXdrGraphUploadApp.ps1 `
    -Cloud USGov `
    -DisplayName 'MDE AV Exclusion Import'
```

This script creates:

- Entra app registration
- Service principal
- Microsoft Graph application permission `DeviceManagementConfiguration.ReadWrite.All`
- Admin consent for that permission
- Temporary client secret

The script writes two files:

```text
out\mde-xdr-upload-app.json
out\mde-xdr-upload-app-private.json
```

The private file is required by the publish script:

```text
out\mde-xdr-upload-app-private.json
```

Keep that file secure. It contains the temporary client secret. It is ignored by Git and should not be uploaded to GitHub.

### Admin Handoff

After Step 3, the Global Admin gives the operator this file through a secure channel:

```text
out\mde-xdr-upload-app-private.json
```

The operator places it in the same path on the workstation where the import will run:

```text
<repo folder>\out\mde-xdr-upload-app-private.json
```

After that, the Global Admin does not need to run the remaining import steps.

## Step 4: Operator Parses the Excel Workbook

Run from the repository folder:

```powershell
.\Convert-AvExclusions.ps1
```

If the workbook has a different filename:

```powershell
.\Convert-AvExclusions.ps1 -ExcelPath .\YourFile.xlsx
```

This creates normalized output under:

```text
out\
```

## Step 5: Operator Builds the Platform Policy Files

```powershell
.\New-MdeXdrDefenderAvExclusionFiles.ps1 `
    -SourceFilter Excel `
    -WindowsPrefix mde-xdr-windows-excel-master
```

This builds Windows, macOS, and Linux policy input files from the workbook.

## Step 6: Operator Previews Policy Creation

```powershell
.\Publish-FinalExcelMdeAvExclusionPolicies.ps1 -WhatIf
```

Expected result: PowerShell reports that it would create three unassigned policies:

- `MDE AV Exclusions - Windows`
- `MDE AV Exclusions - macOS`
- `MDE AV Exclusions - Linux`

## Step 7: Operator Creates the Three Policies

```powershell
.\Publish-FinalExcelMdeAvExclusionPolicies.ps1 -SkipExisting
```

The publish script reads the app registration file from:

```text
out\mde-xdr-upload-app-private.json
```

No interactive Graph login is required for this step.

## Step 8: Verify in the Defender Portal

Open the Defender portal for GCC High:

```text
https://security.microsoft.us
```

Go to:

```text
Endpoints > Configuration management > Endpoint security policies
```

Confirm the three policies exist:

```text
MDE AV Exclusions - Windows
MDE AV Exclusions - macOS
MDE AV Exclusions - Linux
```

They should be unassigned by default.

## Step 9: Assign Policies After Review

After the exclusions are reviewed, assign each policy to the correct MDE-managed device group:

- Windows policy: Windows MDE-managed devices
- macOS policy: macOS MDE-managed devices
- Linux policy: Linux MDE-managed devices

## Step 10: Optional Verification from PowerShell

```powershell
.\Test-MdeXdrDefenderAvExclusionPolicies.ps1
```

This queries Microsoft Graph and reports policy settings and assignment counts.

## Step 11: Optional Cleanup

Only use this if older test policies were created by previous runs.

Preview cleanup:

```powershell
.\Remove-TemporaryMdeAvExclusionPolicies.ps1 -WhatIf
```

Delete old test policies:

```powershell
.\Remove-TemporaryMdeAvExclusionPolicies.ps1
```

The cleanup script preserves the final three policy names listed above.

## Important Security Notes

- Do not commit or share `out\mde-xdr-upload-app-private.json` publicly.
- Delete or rotate the temporary app secret after the import is complete if it is no longer needed.
- The policies are created unassigned so changes do not immediately affect devices.
- Review broad path, extension, and process exclusions before assignment.

## Files in This Repository

- `Convert-AvExclusions.ps1`: parses Excel and optional SCCM/ConfigMgr XML exports.
- `New-MdeXdrDefenderAvExclusionFiles.ps1`: builds platform-specific policy input files.
- `New-MdeXdrGraphUploadApp.ps1`: creates the temporary upload app registration and grants Graph consent.
- `Publish-FinalExcelMdeAvExclusionPolicies.ps1`: creates one unassigned policy each for Windows, macOS, and Linux.
- `Test-MdeXdrDefenderAvExclusionPolicies.ps1`: verifies policy counts through Graph.
- `Remove-TemporaryMdeAvExclusionPolicies.ps1`: removes old test policies.
- `DEPLOY_FROM_XLSX.md`: shorter copy/paste deployment guide.