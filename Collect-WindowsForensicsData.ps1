$startTime = Get-Date

$stagingRoot = "C:\IRStaging"

if (-not (Test-Path $stagingRoot)) { 
    New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null 
}

$logfile = Join-Path -Path $stagingRoot -ChildPath "datacollection.log"
$logDateFormat = "[yyyy-MM-dd HH:mm:ss]"

function Write-LogEntry {

    param (
        [string]$LogEntry,
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timeStamp = Get-Date -Format $logDateFormat
    
    Add-Content -LiteralPath $logfile -Value "$($timeStamp)[$($Level)] - $($LogEntry)"
}

function ConvertFrom-Rot13Char {
    
    param (
        [char]$InputChar
        )
        
        if (-not [char]::IsLetter($InputChar)) {
            return $InputChar
        }
        
        $shift = 97
        if ([char]::IsUpper($InputChar)) {
            $shift = 65
        }
        
        # Get the numeric representation of the input character
        $num = [int][char]$InputChar
        
        # Subtract the shift offset to get to 0
        $num = $num - $shift
        
        # Add 13 to the input number to get a cipher number
        # Mod 26 to wrap letters past nN to the beginning of the alphabet
        $rot_num = ($num + 13) % 26
        
        # Add the shift back to the ROT number and convert it back to a letter
        return [char]($rot_num + $shift)
}

function ConvertFrom-Rot13String {
    param (
        [string]$InputString
    )

    if ($InputString -eq "HRZR_PGYFRFFVBA") {
        return $null
    }
    
    return -join ($InputString.ToCharArray() | ForEach-Object { ConvertFrom-Rot13Char -InputChar $_ })
}

function ConvertFrom-UserAssistBlob {

    param (
        [byte[]]$RawData
        )
        
    if ($RawData.Length -ne 72) {
        Write-LogEntry -Level "WARNING" -LogEntry "Unexpected blob length: $($RawData.Length) bytes (expected 72)."
        return $null
    }
    
    $sessionId   = [BitConverter]::ToInt32($RawData, 0)
    $rawRunCount = [BitConverter]::ToInt32($RawData, 4)
    $focusCount  = [BitConverter]::ToInt32($RawData, 8)
    $focusTimeMs = [BitConverter]::ToInt32($RawData, 12)
    $fileTime    = [BitConverter]::ToInt64($RawData, 60)
    
    $lastRun = if ($fileTime -gt 0) {
        [DateTime]::FromFileTime($fileTime)
    } else {
        $null
    }
    
    [PSCustomObject]@{
        SessionId  = $sessionId
        RunCount   = $rawRunCount + 5
        FocusCount = $focusCount
        FocusTimeMs = $focusTimeMs
        LastRun    = $lastRun
    }
}
    
function Get-PrintableStrings {
    param (
        [byte[]]$RawData,
        [int]$MinLength = 4
        )
        
    $results = [System.Collections.Generic.List[string]]::new()
    
    # ASCII strings (single-byte, printable range)
    $asciiPattern = [regex]('[\x20-\x7E]{' + $MinLength + ',}')
    $asciiText = -join ($RawData | ForEach-Object { [char]$_ })
    $asciiPattern.Matches($asciiText) | ForEach-Object { $results.Add($_.Value) }
    
    # UTF-16LE strings
    $unicodeText = [System.Text.Encoding]::Unicode.GetString($RawData)
    $unicodePattern = [regex]('[\x20-\x7E]{' + $MinLength + ',}')
    $unicodePattern.Matches($unicodeText) | ForEach-Object { $results.Add($_.Value) }
    
    return $results | Select-Object -Unique
}
        
function Get-MRUListExOrder {
    param (
        [byte[]]$RawData
    )

    $order = [System.Collections.Generic.List[int]]::new()

    for ($i = 0; $i -lt $RawData.Length; $i += 4) {
        $index = [BitConverter]::ToInt32($RawData, $i)

        if ($index -eq -1) {
            break
        }

        $order.Add($index)
    }

    return $order
}

function Get-MRUListExKeyData {
    param (
        [string]$KeyPath,
        [string]$Type
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not (Test-Path -LiteralPath $KeyPath)) { return $results }

    $key = Get-Item -LiteralPath $KeyPath
    $mruData = $key.GetValue('MRUListEx')

    if (-not $mruData) { return $results }

    $order = Get-MRUListExOrder -RawData $mruData

    for ($position = 0; $position -lt $order.Count; $position++) {
        $index = $order[$position]
        $valueName = "$index"
        $rawData = $key.GetValue($valueName)

        if (-not $rawData) { continue }

        $strings = Get-PrintableStrings -RawData $rawData

        $obj = [PSCustomObject]@{
            Type        = $Type
            Index       = $index
            MRUPosition = $position
            Filename    = $strings -join ' | '
        }

        $results.Add($obj)
    }

    return $results
}
function Get-HkcuUserAssistData {
    
    $userAssistRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not (Test-Path $userAssistRoot)) {
        Write-LogEntry -Level "WARNING" -LogEntry "$($userAssistRoot) Key not found. Skipping."
        return
    }
    
    Get-ChildItem -LiteralPath $userAssistRoot | ForEach-Object {
        $guidKey = $_
        $countPath = Join-Path -Path $guidKey.PSPath -ChildPath 'Count'
        
        if (-not (Test-Path -LiteralPath $countPath)) { return }
        
        $countKey = Get-Item -LiteralPath $countPath
        $realEntries = $countKey.GetValueNames() | Where-Object { $_ -ne 'HRZR_PGYFRFFVBA' -and $_ }
        
        if ($realEntries.Count -eq 0) { return }
        
        foreach ($valueName in $realEntries) {
            $decodedName = ConvertFrom-Rot13String -InputString $valueName
            $rawData = $countKey.GetValue($valueName)
            $parsed = ConvertFrom-UserAssistBlob -RawData $rawData
            
            if ($parsed) {
                $obj = [PSCustomObject]@{
                    Path        = $decodedName
                    RunCount    = $parsed.RunCount
                    LastRun     = $parsed.LastRun
                    FocusTimeMs = $parsed.FocusTimeMs
                }
            
                $results.add($obj)
            }   
        }
    }

    $outputFile = Join-Path -Path $stagingRoot -ChildPath "userassist-reg-data.csv"
    $results | Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath $outputFile
    Write-LogEntry -LogEntry "HKCU User Assist entries logged to $($outputFile)."
}
    
function Get-HkcuRunData {
        
    $runPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    if (-not (Test-Path $runPath)) {
        Write-LogEntry -Level WARNING -LogEntry "$($runPath) Key not found. Skipping."
        return
    }

    $runKey = Get-Item -LiteralPath $runPath


    Write-LogEntry -LogEntry "Found $($runKey.ValueCount) item(s) in key $($runPath)"
    $runEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($valueName in $runKey.GetValueNames()) {
        $obj = [PSCustomObject]@{
            Name = $valueName
            Data = $runKey.GetValue($valueName)
        }

        $runEntries.Add($obj)
    }

    $subKeys = Get-ChildItem -LiteralPath $runPath -ErrorAction SilentlyContinue
    if ($subKeys) {
        Write-LogEntry -Level WARNING -LogEntry "Found subkeys under Run"

        $subKeys | ForEach-Object { Write-LogEntry -LogEntry "$($_.PSChildName)" }
    }

    $outfile = Join-Path -Path $stagingRoot -ChildPath "hkcu-run.csv"
    $runEntries | Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath $outfile
    Write-LogEntry -LogEntry "HKCU Run entries logged to $($outfile)"

}

function Get-HkcuRunOnceData {

    $runOncePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    if (-not (Test-Path -Path $runOncePath)) {
        Write-LogEntry -Level WARNING -LogEntry "$($runOncePath) Key not found. Skipping."
        return
    }

    $runOnceKey = Get-Item -LiteralPath $runOncePath

    
    if ($runOnceKey.ValueCount -gt 0) {
        $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($valuename in $runOnceKey.GetValueNames()) {
            $obj = [PSCustomObject]@{
                Name = $valuename
                Data = $runOnceKey.GetValue($valuename)
            }

            $entries.Add($obj)
        }
    }

    else {
        Write-LogEntry -Level WARNING -LogEntry "No entries found in $($runOnceKey) key. Skipping"
    }

    $subKeys = Get-ChildItem -LiteralPath $runOncePath -ErrorAction SilentlyContinue
    if ($subKeys) {
        Write-LogEntry -LogEntry "[Warning]: found subkeys under RunOnce"
        $subKeys | ForEach-Object { Write-LogEntry -LogEntry "$($_.PSChildName) "}
    }

    if (($null -eq $entries) -or ($entries.Count -eq 0)) { return }

    $outfile = Join-Path -Path $stagingRoot -ChildPath "hkcu-run-once.csv"
    $entries | Export-Csv -NoTypeInformation -Encoding utf8 -Path $outfile
    Write-LogEntry -LogEntry "HKCU RunOnce entries logged to $($outfile)"

}

function Get-HkcuRecentDocsData {
    $recentDocsRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
    if (-not (Test-Path -LiteralPath $recentDocsRoot)) {
        Write-LogEntry -Level WARNING -LogEntry "$($recentDocsRoot) Key not found. Skipping."
        return
    }

    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    # root key first
    $rootResults = Get-MRUListExKeyData -KeyPath $recentDocsRoot -Type 'Root'

    foreach ($result in $rootResults) { $allResults.Add($result) }

    # then each extension subkey
    Get-ChildItem -LiteralPath $recentDocsRoot | ForEach-Object {
        $subKeyResults = Get-MRUListExKeyData -KeyPath $_.PSPath -Type $_.PSChildName
        
        foreach ($result in $subKeyResults) { $allResults.Add($result) }
    }

    $outfile = Join-Path -Path $stagingRoot -ChildPath "hkcu-recent-docs.csv"
    $allResults | Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath $outfile
    Write-LogEntry -LogEntry "HKCU RecentDocs entries logged to $($outfile)"
    
}

function Get-HkcuComDlg32Data {

    $comDlg32Root = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
    if (-not (Test-Path -LiteralPath $comDlg32Root)) {
        Write-LogEntry -Level WARNING -LogEntry "$($comDlg32Root) Key not found. Skipping."
    }
    
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    Get-ChildItem -LiteralPath $comDlg32Root | ForEach-Object {

        $subKeyResults = Get-MRUListExKeyData -KeyPath $_.PSPath -Type $_.PSChildName
    
        foreach ($result in $subKeyResults) { $allResults.Add($result) }
    }

    $openSavePidlMRUPath = Join-Path -Path $comDlg32Root -ChildPath "OpenSavePidlMRU"

    if (Test-Path $openSavePidlMRUPath) {

        Get-ChildItem -Path $openSavePidlMRUPath | ForEach-Object {
            $results = Get-MRUListExKeyData -KeyPath $_.PSPath -Type $_.PSChildName

            foreach ($result in $results) { $allResults.Add($result) }
        }
    }

    $outfile = Join-Path -Path $stagingRoot -ChildPath "hkcu-comdlg32-data.csv"
    $allResults | Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath $outfile
    Write-LogEntry -LogEntry "HKCU ComDlg32 entries logged to $($outfile)"

}

function Get-HkcuTypedPathData {

    $typedPathsRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
    if (-not (Test-Path -LiteralPath $typedPathsRoot)) {
        Write-LogEntry -Level WARNING -LogEntry "$($typedPathsRoot) Key not found. Skipping."
    }
    
    $typedPathsKey = Get-Item -LiteralPath $typedPathsRoot

    Write-LogEntry -LogEntry "Found $($typedPathsKey.ValueCount) item(s) in key $($typedPathsRoot)"
    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($valueName in $typedPathsKey.GetValueNames()) {
        $obj = [PSCustomObject]@{
            Name = $valueName
            Data = $typedPathsKey.GetValue($valueName)
        }

        $entries.Add($obj)
    }

    $outfile = Join-Path -Path $stagingRoot -ChildPath "hkcu-typed-paths.csv"
    $entries | Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath $outfile
    Write-LogEntry -LogEntry "HKCU TypedPath entries logged to $($outfile)"

}

function Get-BrowserData {

    $edgeDataPath       = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Edge\User Data\Default"
    $chromeDatapath     = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Google\Chrome\User Data\Default"
    $browser_db_files   = @("History", "Cookies", "Login Data", "Web Data")
    $browser_json_files = @("Bookmarks", "Preferences")

    $browsers = @(
        [PSCustomObject]@{ Name = "Edge"; Path = $edgeDataPath }
        [PSCustomObject]@{ Name = "Chrome"; Path = $chromeDatapath }
    )

    foreach ($browser in $browsers) {
        if (-not (Test-Path -LiteralPath $browser.Path)) {
            Write-LogEntry -Level WARNING -LogEntry "$($browser.Name) profile not found. Skipping."
            continue
        }

        $destDir = Join-Path -Path $stagingRoot -ChildPath $browser.Name
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null

        foreach ($file in ($browser_db_files + $browser_json_files)) {
            $sourceFile = Join-Path -Path $browser.Path -ChildPath $file
            if (Test-Path -LiteralPath $sourceFile) {
                Copy-Item -Path $sourceFile -Destination $destDir -Force
                Write-LogEntry -LogEntry "$($browser.Name) profile data copied to $($destDir)."
            }
            else {
                Write-LogEntry -Level WARNING -LogEntry "$($sourceFile) not found for $($browser.Name) browser. Skipping."
            }
        }
    }
}

Write-LogEntry -LogEntry "Data collection started."
Get-HkcuTypedPathData
Get-HkcuComDlg32Data
Get-HkcuRecentDocsData
Get-HkcuRunData
Get-HkcuRunOnceData
Get-HkcuUserAssistData
Get-BrowserData

$endTime = Get-Date
$duration = $endTime - $startTime
Write-LogEntry -LogEntry "Data collection finished - runtime: $($duration.TotalSeconds) seconds."



