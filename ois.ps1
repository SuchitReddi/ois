# Opens given Domain/IP/url/hash in reputed OSINT sites.
# Author - Suchit Reddi

# <----Define OSINT URLs---->
$osintUrls = @{
    # <----All round---->
    "vt" = "https://www.virustotal.com/gui/search"
    "valkyrie" = "https://verdict.valkyrie.comodo.com" #testing

    # <----Domain, IP, Hash---->
    "ibm" = "https://exchange.xforce.ibmcloud.com"
    
    # <----Domain, IP, URL---->
    "talos" = "https://talosintelligence.com/reputation_center/lookup?search"

    # <----Domain, URL, Hash---->

    # <----Domain, URL---->
    "norton" = "https://sitereview.bluecoat.com/#/lookup-result"
   
    # <----Domain, IP---->
    "abip" = "https://www.abuseipdb.com/check"
    "whois" = "https://www.whois.com/whois"
    "urlscan" = "https://urlscan.io/domain"
    "shodan" = "https://www.shodan.io/search?query"
	
    # <----Just Hash---->
    "kasper" = "https://opentip.kaspersky.com"
    "otx" = "https://otx.alienvault.com/browse/global/pulses?q"

    # <----Just IP---->
    "bgp" = "https://bgpview.io/ip"
}

# Ask user if they want to use urlscan or not
function Get-UseUrlscanPreference {
    param([string]$configPath)
    $config = Get-Content $configPath | ConvertFrom-Json

    if (-not $config.PSObject.Properties['useurlscan']) {
        $config | Add-Member -MemberType NoteProperty -Name 'useurlscan' -Value ""
    }

    if ([string]::IsNullOrWhiteSpace($config.useurlscan)) {
        do {
            Write-Host "This script allows you to use URLScan API to get better URL search results."
            Write-Host "If you don't have an account, create one at https://urlscan.io/user/signup"
            Write-Host "If you already have an account, get the API key here https://urlscan.io/user/profile/"
            Write-Host "If you want to change the choice later, go to the edit menu"
            Write-Host ""
            $yorn = Read-Host "Do you want to use URLScan API? Select Y only if you have an API key (Y/N)"
        } while ($yorn -notmatch '^[YyNn]$')
        $config.useurlscan = $yorn.ToUpper()
        $config | ConvertTo-Json | Set-Content $configPath
    }
    return $config.useurlscan
}

# <----URL encoding function---->
Function Encode-URL {
    Param (
        [string]$url
    )
    $encoded = [System.Net.WebUtility]::UrlEncode($url)
    # Double encoding by replacing % with %25
    $doubleEncoded = $encoded -replace "%", "%25"
    return @{Single = $encoded; Double = $doubleEncoded}
}

# <----Input Validation---->
Function Classify-IOC {
    Param (
        [string]$ioc
    )

    # Regex patterns for each type
    $domainRegex = '^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$'  # Simple domain
    $urlRegex = '^((https?|http?|ftp?):\/\/)?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|({{{{\[[0-9a-fA-F:]+\]}}}}|[0-9a-fA-F:]+))(:\d+)?(\/.*)?(\?.*)?$'  # URL with optional protocol and path
    $ipRegex = '^(\d{1,3}\.){3}\d{1,3}$'  # IPv4 address
    $privipRegex = '^(127\.\d{1,3}\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})$'  # Private IP address
    $hashRegex = '^[a-fA-F0-9]{32,64}$'   # Hash (MD5, SHA-256, etc.)

    If ($ioc -match $privipRegex) {
        Return "private_ip"
    } elseif ($ioc -match $ipRegex) {
        Return "ip"
    } elseif ($ioc -match $hashRegex) {
        Return "hash"
    } elseif ($ioc -match $urlRegex) {
        # Distinguish between domain and URL
        If ($ioc -match $domainRegex -and -not $ioc.Contains("/")) {
            Return "domain"
        } else {
            Return "url"
        }
    } else {
        Return "unknown"
    }
}

# <----Display typing animation---->
Function Show-Animated-Text {
    Param (
        [string]$text,
        [int]$delay = 0.5,  # Default delay of 0 milliseconds for fastest animation
        [switch]$NoAnimation  # Switch to skip the animation
    )

    if ($NoAnimation) {
        Write-Host $text
    } else {
        foreach ($char in $text.ToCharArray()) {
            if ($Host.UI.RawUI.KeyAvailable) {
                $Host.UI.RawUI.FlushInputBuffer()
                Write-Host $text.Substring($text.IndexOf($char))
                return
            }
            Write-Host -NoNewline $char
            Start-Sleep -Milliseconds $delay
        }
        Write-Host ""
    }
}

# <----Edit configured values---->
Function Edit-Configuration {
    Param (
        [ref]$browser,
        [ref]$iocLimit
    )

    Do {
        Clear-Host
        Write-Host "Current IOC limit is $($iocLimit.Value)."
        Write-Host "Current default browser is $($browser.Value)."
        Write-Host ""
        Write-Host "To change IOC limit, press 1."
        Write-Host "To change browser, press 2."
        Write-Host "Choice to use/not use URLScan API, press 3."
        Write-Host "Press q to quit."
        Write-Host ""
        $choice = Read-Host "Enter your choice"
        Write-Host ""

        Switch ($choice) {
            "1" {
                $newIocLimit = Read-Host "Enter the new IOC limit"
                Write-Host ""
                if ($newIocLimit -match '^\d+$') {
                    $iocLimit.Value = [int]$newIocLimit
                    $config.ioclim = $iocLimit.Value
                    $config | ConvertTo-Json | Set-Content $configPath
                    Write-Host "IOC limit changed to $newIocLimit." -ForegroundColor Green
                } else {
                    Write-Host "Invalid input. Please enter a numeric value." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "2" {
                Write-Host "Some browsers: chrome, msedge, firefox, iexplore, opera, brave"
                $newBrowser = Read-Host "Enter the new default browser"
                if ($supportedBrowsers -contains $newBrowser) {
                   $browser.Value = $newBrowser
                   $config.defbrow = $browser.Value
                   $config | ConvertTo-Json | Set-Content $configPath
                   Write-Host "Default browser changed to $newBrowser." -ForegroundColor Green
                } else {
                   Write-Host "Invalid browser name. Please enter one of the supported browsers." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "3" {
                if ($useurlscan -eq "N") {
                    Write-Host "You are currently not using URLScan API. You can change the choice below."
                    Write-Host ""
                } elseif ($useurlscan -eq "Y") {
                    Write-Host "You are currently using URLScan API. You can change the choice below."
                    Write-Host ""
                }
                $newUsage = Read-Host "Do you want to use URLScan API? Select Y only if you have an API key (Y/N)"
                if ($newUsage -match '^[YyNn]$') {
                    $urlscanusage = $newUsage
                    $config.useurlscan = $urlscanusage
                    $config | ConvertTo-Json | Set-Content $configPath
                    Write-Host "URLScan API usage status changed to $newUsage. Changes will apply after you restart the script." -ForegroundColor Green
                } else {
                    Write-Host "Invalid input. Please enter Y/N value." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "Q" {
                Clear-Host
                return
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } While ($true)
}

# <----IOC Type handling function---->
Function Lookup-Handler {
    Param (
        [string]$type,
        [array]$iocs
    )

    $allUrlscanTasks = @()

    foreach ($ioc in $iocs) {
        $urls = $null
        $uscanurls = $null
        $uscanuuid = $null

        if ($type -eq "private_ip") {
            Write-Host "--------------------------------------------------"
            Write-Host "$ioc is a private IP :(" -ForegroundColor Yellow
            Write-Host "--------------------------------------------------"
            continue
        }

        if ($type -eq "domain") {
            # ------------------Domain Lookup------------------
            $urls = @(
                "$($osintUrls.vt)/$ioc",
                "$($osintUrls.urlscan)/$ioc",
                "$($osintUrls.norton)/$ioc",
                "$($osintUrls.whois)/$ioc",
                "$($osintUrls.talos)=$ioc",
                "$($osintUrls.ibm)/url/$ioc",
                "$($osintUrls.abip)/$ioc"
            )
        } elseif ($type -eq "ip") {
            # --------------------IP Lookup--------------------
            $urls = @(
                "$($osintUrls.vt)/$ioc",
                "$($osintUrls.urlscan)/$ioc",
                "$($osintUrls.whois)/$ioc",
                "$($osintUrls.talos)=$ioc",
                "$($osintUrls.ibm)/url/$ioc",
                "$($osintUrls.abip)/$ioc",
                "$($osintUrls.shodan)=$ioc"
            )
        } elseif ($type -eq "url") {
            # -------------------URL Lookup--------------------
            $url = $ioc
            if ($useurlscan -eq "Y") {
                $json = powershell -ExecutionPolicy Bypass -File $urlscanpath -url $url -configPath $configPath
                $result = $json | ConvertFrom-Json
                $uscanuuid = $result.scanuuid
                $uscanoutput = $result.oisoutput
                $uscanss = $result.ssurl
                $usstatmsg = $result.statusmessage
                $userror = $result.error
                $userrordesc = $result.errordesc
            }

            # Remove http:// or https://
            if ($url -match '^(https?://)') {
                $urlnohttp = $url.Substring($matches[1].Length)
            } else {
                $urlnohttp = $url
            }

            # For VirusTotal, always add "https://" if not already present
            if ($url -match '^(https?://)') {
                $urlhttp = $url  # No change if already has http:// or https://
            } else {
                $urlhttp = "https://$url"  # Add https:// if missing
            }

            $encodedOriginal = Encode-URL -url $ioc
            $encodedNohttp = Encode-URL -url $urlnohttp
            $encodedHttp = Encode-URL -url $urlhttp

            # Extract domain from URL
            if ($url -match '^(https?://)?([^/]+)') {
                $domain = $matches[2]
            } else {
                $domain = $url -replace '/.*$', ''
            }

            # Construct URLs for different services
            $urls = @(
                "$($osintUrls.vt)/$($encodedHttp.Double)",  # VirusTotal with https://
                "$($osintUrls.norton)/$($encodedOriginal.Double)",
                "$($osintUrls.talos)=$($encodedOriginal.Single)",
                "$($osintUrls.abip)/$domain",
                "$($osintUrls.whois)/$domain",
                "$($osintUrls.ibm)/url/$domain"
            )

            if ($useurlscan -eq "Y") {
            $uscanurls = @($uscanoutput, $uscanss)
            }

        } elseif ($type -eq "hash") {
            # -------------------Hash Lookup-------------------
            $urls = @(
                "$($osintUrls.vt)/$ioc",
                "$($osintUrls.otx)=$ioc",
                "$($osintUrls.kasper)/$ioc/results?tab=lookup",
                "$($osintUrls.ibm)/malware/$ioc"
            )
        }

        # Open result URLs in the browser and display them in the terminal
        if ($urls) {
            Start-Process $browser -ArgumentList ("-new-window", ($urls -join " "))
            Write-Host "IOC ($type): $ioc" -ForegroundColor Green
            Write-Host "--------------------------------------------------"
            $urls | ForEach-Object { Write-Host $_ }
            Write-Host "--------------------------------------------------"
        }

        # Print URLscan results and collect for later polling
        if ($type -eq "url" -and $useurlscan -eq "Y" -and $usstatmsg -eq "Submission successful") {
            Write-Host "URLscan results for: $ioc" -ForegroundColor Green
            Write-Host "--------------------------------------------------"
            $uscanurls | ForEach-Object { Write-Host $_ }
            Write-Host "--------------------------------------------------"
            Write-Host ""
            Write-Host "Waiting for results from URLscan API..." -ForegroundColor Yellow

            # Collect tasks for polling after all IOCs
            for ($i = 0; $i -lt $uscanurls.Count; $i++) {
                if ($uscanuuid -is [array]) {
                    $uuidValue = $uscanuuid[$i]
                } else {
                    $uuidValue = $uscanuuid
                }
                $allUrlscanTasks += [PSCustomObject]@{
                    Url  = $uscanurls[$i]
                    Uuid = $uuidValue
                }
            }
        } elseif ($type -eq "url" -and $useurlscan -eq "Y" -and $usstatmsg -ne "Submission successful") {
            Write-Host "URLscan results for: $ioc" -ForegroundColor Green
            Write-Host "--------------------------------------------------"
            Write-Host "URLScan was not able to scan this IOC. You can try submitting manually." -ForegroundColor Red
            Write-Host "--------------------------------------------------"  
        }
    }

    # Poll and open URLscan results after all IOCs are processed
    foreach ($task in $allUrlscanTasks) {
        $scanReady = $false
        $maxTries = 15
        $try = 0
        while (-not $scanReady -and $try -lt $maxTries) {
            Start-Sleep -Seconds 2
            $try++
            try {
                $scanResult = Invoke-RestMethod -Uri "https://urlscan.io/api/v1/result/$($task.Uuid)/"
                if ($scanResult.task -and $scanResult.task.status -eq "done") {
                    $scanReady = $true
                } elseif ($scanResult.page) {
                    $scanReady = $true
                }
            } catch {}
        }
        if ($scanReady) {
            Start-Process $browser -ArgumentList $task.Url
        } else {
            Write-Host "URLScan result for this IOC is not available yet, open this link after a while: $($task.Url)" -ForegroundColor Red
        }
    }
}

# --------------------Main Loop--------------------

# <----Setting config file path---->
$parentDir = Join-Path $env:USERPROFILE '\Desktop\ois'

# Helper function to search for a file in parentDir, ois* dirs, and their subdirs
function Find-FilePath {
    param(
        [string]$parentDir,
        [string]$fileName
    )
    # 1. Check parentDir directly
    $candidate = Join-Path $parentDir $fileName
    if (Test-Path $candidate) { return $candidate }

    # 2. Check all ois* dirs in parentDir
    $oisDirs = Get-ChildItem -Path $parentDir -Directory | Where-Object { $_.Name -like 'ois*' }
    foreach ($dir in $oisDirs) {
        $candidate = Join-Path $dir.FullName $fileName
        if (Test-Path $candidate) { return $candidate }
    }

    # 3. Check all subdirectories of ois* dirs
    foreach ($dir in $oisDirs) {
        $subdirs = Get-ChildItem -Path $dir.FullName -Directory
        foreach ($subdir in $subdirs) {
            $candidate = Join-Path $subdir.FullName $fileName
            if (Test-Path $candidate) { return $candidate }
        }
    }
    return $null
}

$configPath = Find-FilePath -parentDir $parentDir -fileName 'config.json'
$urlscanpath = Find-FilePath -parentDir $parentDir -fileName 'urlscan.ps1'

if (-not $configPath) {
    throw "No config.json found in $parentDir, any ois* directory, or their subdirectories"
}
if (-not $urlscanpath) {
    throw "No urlscan.ps1 found in $parentDir, any ois* directory, or their subdirectories"
}

$useurlscan = Get-UseUrlscanPreference -configPath $configPath

# <----Browser, IOC limit editing---->
$config = Get-Content $configPath | ConvertFrom-Json
$browser = if ($config.defbrow) { $config.defbrow } else { "msedge" }
$iocLimit = if ($config.ioclim) { $config.ioclim } else { 4 }
$uscanusage = if ($config.useurlscan) { $config.useurlscan } else { "" }

$supportedBrowsers = @("chrome", "msedge", "firefox", "safari", "opera", "brave")

Do {
    # Input IOC from the user (mix of domains, IPs, URLs, hashes)
    Write-Host ""
    $iocInput = Read-Host "Enter maximum $iocLimit IOCs (i-info, e-edit)"
    Write-Host ""

    # Check if the user input is "e" (case-insensitive)
    if ($iocInput -match '^(?i)e$') {
        Edit-Configuration -browser ([ref]$browser) -iocLimit ([ref]$iocLimit)
        Continue
    }

    # Check if the user input is "i" to show information
    if ($iocInput -match '^(?i)i$') {

Write-Host @"
    _____            __
   /#####\          /##|           __                           
  /##__ ##|  ____  |__/           |##|                         
 | ##  \ #| /####|  __ ________ __|##|__                         
 | ##  | #|/##/___ | #| ##__###|_ ####_/                          
 | ##  | #|  #####|| #| #|  \##| | ##|                            
 | ##  | #|\____##|| #| #|  | #| | ##|__                        
 |  ######/#######|| #| #|  | #| | ####/                        
  \______/|_______/|__|__/  |__/  \___/                            
 |_####_/  _____     ______                                                    
   | #|   /#####\   /######|                                       
   | #|  |##___##| /##_____/                                       
   | #|  |##   |#|| #|                                            
  /####\ | ######||  ######|                                       
 |______| \______/ \_______/                                       
   /#####\                                                        
  /##__###|  _______  ______  _______  _______  _______  ________                                         
 |##|  \__/ /######| /######|/#######|/#######|/##__## ||##___ ##| 
 |##\____  /##_____/|____|##| ##__###| ##__###|##|__|#/ |##|  \__/ 
  \____##\| ##       /#__###| ##  \##| ##  \##|###___/  |##|      
  _____\##| ##      /#|__|##| ##  |##| ##  |##|##|_____ |##|      
 |########|  ######| #######| ##  |##| ##  |##|########\|##|      
  \______/ \_______/\_______|__/  |__|__/  |__/\_______||__/      
"@ -ForegroundColor Cyan

Write-Host ""
Show-Animated-Text -text "By Suchit Reddi"
Write-Host ""

Write-Host "Overview: " -ForegroundColor Green
Show-Animated-Text -text "1) Analysts can give their IOCs (Domain, IP, URL, Hash). The IOC type will be auto-validated by the script. Defanged IOCs are also processed."
Show-Animated-Text -text "2) Maximum of 4 IOCs are recommended to limit excessive resource consumption. If more than four are given, a confirmation to proceed will be displayed."
Show-Animated-Text -text "3) The delimiters that can be used between two IOCs are: Space ( ), OR operator ( OR )( or ), and Comma (,)."
Show-Animated-Text -text "4) The links for results will be displayed in terminal for analysts to copy paste as references."
Show-Animated-Text -text "5) After the process is done, the script asks again for IOCs until terminated manually."
Show-Animated-Text -text "6) The config.json file and urlscan.ps1 file can be placed anywhere in C:\Users\YOUR USERNAME HERE\Desktop\ois or C:\Users\YOUR USERNAME HERE\Desktop\ois\ois*."
Show-Animated-Text -text "7) If you have URLScan account, you can use the API to get a live screenshot for the URL. You will be prompted to choose if you want to use it or not in the beginning. If you want to change the choice later, you can edit it from e."

Write-Host ""

#Write-Host "Known Issues: " -ForegroundColor Red
#Show-Animated-Text -text "--> Threat Connect should be logged in before using this tool, or else you will be redirected to the dashboard instead of the search result. Please click the link displayed in terminal to open it."
        Continue
    }

    If (-not $iocInput) {
        Write-Host "Enter valid IOCs. With great IOCs come great results!" -ForegroundColor Red
        Continue
    }

    # Split on commas, spaces, or "OR" (case insensitive), trim whitespace, and filter out "OR and comma" as valid IOCs.
    $iocs = $iocInput -split '\s*(,|\s+|(?i)\bOR\b)\s*' |
    Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^(,|(?i)OR)$" } |
    ForEach-Object {
        $_.Trim() `
        -replace 'hxxps', 'https' `
        -replace 'hxxp', 'http' `
        -replace '\[\:\/\/\]', '://' `
        -replace '\[\.\]', '.'
    }

    # Ensure valid IOCs are present
    If (-not $iocs) {
        Write-Host "No valid IOCs found. With great IOCs come great results!" -ForegroundColor Red
        Continue
    }

    # Check if the count exceeds the limit
    If ($iocs.Count -gt $iocLimit) {
        Write-Host "You have entered $($iocs.Count) IOCs, which exceeds the limit of $iocLimit." -ForegroundColor Yellow
        $confirm = Read-Host "Press N to cancel, or any other key to continue"
        If ($confirm -ieq "n") { Continue }
    }

    # Defang the IOCs
    $defangediocs = $iocs | ForEach-Object {
    $_ -replace 'https', 'hxxps' `
       -replace 'http', 'hxxp' `
       -replace '://', '[://]' `
       -replace '\.', '[.]'
    }

    # Separate the IOCs by type
    $ipIocs = @()
    $privipIocs = @()
    $domainIocs = @()
    $urlIocs = @()
    $hashIocs = @()

    # Classify each IOC
    foreach ($ioc in $iocs) {
        $ioc = $ioc.Trim()
        $classification = Classify-IOC -ioc $ioc

        switch ($classification) {
            "domain" { $domainIocs += $ioc }
            "url" { $urlIocs += $ioc }
            "ip" { $ipIocs += $ioc }
            "private_ip" { $privipIocs += $ioc }
            "hash" { $hashIocs += $ioc }
            default { Write-Host "Invalid IOC: $ioc" -ForegroundColor Red }
        }
    }

    # Lookup the IOCs by type
    If ($privipIocs) { Lookup-Handler -type "private_ip" -iocs $privipIocs }
    If ($ipIocs) { Lookup-Handler -type "ip" -iocs $ipIocs }
    If ($hashIocs) { Lookup-Handler -type "hash" -iocs $hashIocs }
    If ($domainIocs) { Lookup-Handler -type "domain" -iocs $domainIocs }
    If ($urlIocs) { Lookup-Handler -type "url" -iocs $urlIocs }

} While ($true)