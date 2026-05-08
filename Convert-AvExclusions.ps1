<#
.SYNOPSIS
Parses SCCM/ConfigMgr and Excel AV exclusion exports into normalized Defender AV exclusion rows.

.DESCRIPTION
Inputs:
  - master-exclusions.xml from ConfigMgr/SCCM
  - optional NewExclusions.xlsx workbook if Excel is installed locally

Outputs:
  - normalized-exclusions.csv
  - risky-exclusions.csv
  - summary.json

The XML parser is intentionally discovery-oriented because ConfigMgr exports can vary by version/export path.
It extracts likely exclusion values from element/attribute names containing: exclude, exclusion, path, process, extension.
#>
[CmdletBinding()]
param(
    [string]$XmlPath = ".\master-exclusions.xml",
    [string]$ExcelPath = ".\NewExclusions.xlsx",
    [string]$OutDir = ".\out"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-OutputFolder {
    param([string]$Path)
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Get-ExclusionType {
    param([string]$Name, [string]$Value)

    $nameValue = (($Name, $Value) -join " ").ToLowerInvariant()

    if ($Value -match "\\|/|%[a-z0-9_]+%|\*|\." -or $nameValue -match "path|folder|file|directory|excludedpath") { return "Path" }
    if ($nameValue -match "extension|filetype|file type|excludedextensions") { return "Extension" }
    if ($nameValue -match "process|executable|excludedprocess") { return "Process" }
    if ($Value -match "^[a-z0-9]{1,12}$" -and $Value -notmatch "[\\/:]" -and $Value -notmatch "\*") { return "ExtensionCandidate" }
    return "Unknown"
}

function Get-ExclusionTypeFromPolicy {
    param([string]$Policy)

    if ($Policy -match "(?i)\\exclusions\\paths$") { return "Path" }
    if ($Policy -match "(?i)\\exclusions\\processes$") { return "Process" }
    if ($Policy -match "(?i)\\exclusions\\extensions$") { return "Extension" }
    return $null
}

function Test-UsableExclusionValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $clean = $Value.Trim()
    if ($clean.Length -lt 2) { return $false }
    if ($clean -match "^\{.*\}$") { return $false }
    if ($clean -match "^(?i:true|false|reg_[a-z0-9_]+|0|1)$") { return $false }
    if ($clean -match "^https?://") { return $false }
    if ($clean -match "^(?i)software\\policies\\") { return $false }
    if ($clean -match "^[0]+$") { return $false }
    return $true
}

function Test-RiskyExclusion {
    param([string]$Type, [string]$Value)

    $v = $Value.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($v)) { return "Empty" }

    $risky = @()
    if ($Type -eq "Path" -or $Type -eq "Unknown") {
        if ($v -in @("c:\", "c:\*", "%systemdrive%\", "%systemdrive%\*", "\\*", "*")) { $risky += "RootOrWildcardPath" }
        if ($v -match "^c:\\users(\\|$)" -or $v -match "^%userprofile%") { $risky += "UserProfileBroadPath" }
        if ($v -match "^c:\\programdata(\\|$)" -or $v -match "^%programdata%") { $risky += "ProgramDataBroadPath" }
        if ($v -match "\\temp(\\|$)|%temp%|%tmp%") { $risky += "TempPath" }
        if ($v -match "\*\.exe$|\*\.dll$|\*\.ps1$|\*\.bat$|\*\.cmd$|\*\.vbs$|\*\.js$") { $risky += "ExecutableWildcard" }
    }
    if ($Type -eq "Process" -or $Type -eq "Unknown") {
        $dangerousProcesses = @("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "python.exe", "java.exe", "node.exe")
        if ($dangerousProcesses -contains (Split-Path $v -Leaf)) { $risky += "HighRiskProcessExclusion" }
    }
    if ($Type -eq "Extension" -or $Type -eq "ExtensionCandidate") {
        $dangerousExtensions = @("exe", ".exe", "dll", ".dll", "ps1", ".ps1", "bat", ".bat", "cmd", ".cmd", "js", ".js", "vbs", ".vbs")
        if ($dangerousExtensions -contains $v) { $risky += "HighRiskExtensionExclusion" }
    }

    if ($risky.Count -eq 0) { return $null }
    return ($risky -join ";")
}

function Add-Row {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [string]$Source,
        [string]$Policy,
        [string]$RawName,
        [string]$Value,
        [string]$ExplicitType,
        [string]$Platform = "Windows"
    )

    if (-not (Test-UsableExclusionValue -Value $Value)) { return }
    $clean = $Value.Trim()

    if ($Source -eq "XML" -and [string]::IsNullOrWhiteSpace((Get-ExclusionTypeFromPolicy -Policy $Policy))) { return }

    $policyType = Get-ExclusionTypeFromPolicy -Policy $Policy
    $type = if (-not [string]::IsNullOrWhiteSpace($ExplicitType)) {
        $ExplicitType
    }
    elseif (-not [string]::IsNullOrWhiteSpace($policyType)) {
        $policyType
    }
    else {
        Get-ExclusionType -Name $RawName -Value $clean
    }
    $risk = Test-RiskyExclusion -Type $type -Value $clean

    $Rows.Add([pscustomobject]@{
        Source        = $Source
        Platform      = $Platform
        Policy        = $Policy
        Type          = $type
        Value         = $clean
        RawName       = $RawName
        RiskFinding   = $risk
    }) | Out-Null
}

function Read-XmlExclusions {
    param([string]$Path)

    $rows = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path $Path)) { return $rows }

    [xml]$xml = Get-Content -Path $Path -Raw
    $nodes = $xml.SelectNodes("//*")

    foreach ($keyNode in ($nodes | Where-Object { $_.Name -eq "AddKey" -and $_.Attributes -and $_.Attributes["Name"] })) {
        $policyName = $keyNode.Attributes["Name"].Value
        $explicitType = Get-ExclusionTypeFromPolicy -Policy $policyName
        if (-not $explicitType) { continue }

        foreach ($valueNode in ($keyNode.ChildNodes | Where-Object { $_.Name -eq "AddValue" -and $_.Attributes -and $_.Attributes["Name"] })) {
            Add-Row -Rows $rows -Source "XML" -Policy $policyName -RawName "AddValue.Name" -Value $valueNode.Attributes["Name"].Value -ExplicitType $explicitType
        }
    }

    if ($rows.Count -gt 0) { return $rows }

    foreach ($node in $nodes) {
        $nodeName = $node.Name
        $policy = ""
        $ancestor = $node.ParentNode
        while ($ancestor -and [string]::IsNullOrWhiteSpace($policy)) {
            foreach ($attrName in @("name", "Name", "displayName", "DisplayName", "policyName", "PolicyName")) {
                if ($ancestor.Attributes -and $ancestor.Attributes[$attrName]) {
                    $policy = $ancestor.Attributes[$attrName].Value
                    break
                }
            }
            $ancestor = $ancestor.ParentNode
        }

        if ($node.Attributes) {
            foreach ($attr in $node.Attributes) {
                $combinedName = "$nodeName.$($attr.Name)"
                if ($combinedName -match "(?i)exclude|exclusion|path|process|extension|filetype|folder|directory") {
                    Add-Row -Rows $rows -Source "XML" -Policy $policy -RawName $combinedName -Value $attr.Value
                }
            }
        }

        $text = ($node.InnerText | ForEach-Object { $_ })
        if (($nodeName -match "(?i)exclude|exclusion|path|process|extension|filetype|folder|directory") -and -not [string]::IsNullOrWhiteSpace($text)) {
            $splitValues = $text -split "[`r`n;,]" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($value in $splitValues) {
                Add-Row -Rows $rows -Source "XML" -Policy $policy -RawName $nodeName -Value $value
            }
        }
    }

    return $rows
}

function Read-ExcelExclusions {
    param([string]$Path)

    $rows = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path $Path)) { return $rows }

    $excel = $null
    $workbook = $null
    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $workbook = $excel.Workbooks.Open((Resolve-Path $Path).Path)

        foreach ($sheet in $workbook.Worksheets) {
            $used = $sheet.UsedRange
            if (-not $used) { continue }
            $rowCount = $used.Rows.Count
            $colCount = $used.Columns.Count
            if ($rowCount -lt 1 -or $colCount -lt 1) { continue }

            $headers = @{}
            for ($col = 1; $col -le $colCount; $col++) {
                $header = [string]($sheet.Cells.Item(1, $col).Text)
                if (-not [string]::IsNullOrWhiteSpace($header)) { $headers[$col] = $header.Trim() }
            }

            for ($row = 2; $row -le $rowCount; $row++) {
                $platform = ""
                $type = ""
                $value = ""
                $policy = $sheet.Name

                for ($col = 1; $col -le $colCount; $col++) {
                    $header = if ($headers.ContainsKey($col)) { $headers[$col] } else { "Column$col" }
                    $cell = [string]($sheet.Cells.Item($row, $col).Text)
                    if ([string]::IsNullOrWhiteSpace($cell)) { continue }

                    if ($header -match "(?i)platform|os") { $platform = $cell.Trim() }
                    elseif ($header -match "(?i)type|category") { $type = $cell.Trim() }
                    elseif ($header -match "(?i)value|exclusion|exception|item|path|process|extension|file|folder") { $value = $cell.Trim() }
                }

                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    Add-Row -Rows $rows -Source "Excel" -Policy $policy -RawName $type -Value $value -Platform ($(if ($platform) { $platform } else { "Unknown" }))
                }
            }
        }
    }
    catch {
        Write-Warning "Excel parse skipped/failed: $($_.Exception.Message)"
    }
    finally {
        if ($workbook) { $workbook.Close($false) | Out-Null }
        if ($excel) { $excel.Quit() | Out-Null }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }

    return $rows
}

New-OutputFolder -Path $OutDir

$allRows = [System.Collections.Generic.List[object]]::new()
foreach ($row in (Read-XmlExclusions -Path $XmlPath)) { $allRows.Add($row) | Out-Null }
foreach ($row in (Read-ExcelExclusions -Path $ExcelPath)) { $allRows.Add($row) | Out-Null }

$deduped = $allRows |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } |
    Sort-Object Platform, Type, Value -Unique

$normalCsv = Join-Path $OutDir "normalized-exclusions.csv"
$riskyCsv = Join-Path $OutDir "risky-exclusions.csv"
$summaryJson = Join-Path $OutDir "summary.json"

$deduped | Export-Csv -Path $normalCsv -NoTypeInformation
$deduped | Where-Object { $_.RiskFinding } | Export-Csv -Path $riskyCsv -NoTypeInformation

$summary = [pscustomobject]@{
    GeneratedAt = (Get-Date).ToString("o")
    XmlPath = $XmlPath
    ExcelPath = $ExcelPath
    TotalRows = @($deduped).Count
    BySource = $deduped | Group-Object Source | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } }
    ByPlatform = $deduped | Group-Object Platform | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } }
    ByType = $deduped | Group-Object Type | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } }
    RiskyCount = @($deduped | Where-Object { $_.RiskFinding }).Count
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryJson -Encoding UTF8

Write-Host "Wrote $normalCsv"
Write-Host "Wrote $riskyCsv"
Write-Host "Wrote $summaryJson"
$summary | ConvertTo-Json -Depth 5
