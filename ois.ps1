Write-Host @"
   /#####\          /##            __                           
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
Write-Host "By 5herl0ck"

# -------------------Script Start-----------------------------------
# <----Browser, IOC Limit---->
$browser = "msedge"
$iocLimit = 4
$maxLength = 1023

# <----Define OSINT URLs---->
$osintUrls = @{
    # <----All round---->
    "vt" = "https://www.virustotal.com/gui/search"
    "ibm" = "https://exchange.xforce.ibmcloud.com"
    "talos" = "https://talosintelligence.com/reputation_center/lookup?search"
    "kasper" = "https://opentip.kaspersky.com"
    "otx" = "https://otx.alienvault.com/browse/global/pulses?q"
    
    # <----Domain, URL---->
    "norton" = "https://sitereview.bluecoat.com/#/lookup-result"
    
    # <----Domain, IP---->
    "abip" = "https://www.abuseipdb.com/check"
    "whois" = "https://www.whois.com/whois"
    "urlscan" = "https://urlscan.io/domain"
    "shodan" = "https://www.shodan.io/search?query"
    
    # <====Deprecated====>
    # "ggl" = "https://transparencyreport.google.com/safe-browsing/search?url"
    # "talos_h" = "https://talosintelligence.com/talos_file_reputation?s"
    # "urlvoid" = "https://urlvoid.com/scan"
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

# <----Functions to Validate IOC Types---->

# Check if a string is a valid IP address
Function Is-ValidIP {
    Param ([string]$ip)
    return $ip -match '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
}

# Check if a string is a valid domain
Function Is-ValidDomain {
    Param ([string]$domain)
    return $domain -match '^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
}

# Check if a string is a valid URL
Function Is-ValidURL {
    Param ([string]$url)
    return $url -match '^(https?|http?|ftp)://[^\s/$.?#].[^\s]*$'
}

# Check if a string is a valid hash (SHA256)
Function Is-ValidHash {
    Param ([string]$hash)
    return $hash -match '^[a-fA-F0-9]{64}$'
}

# <----Lookup IOC Handler Function---->
Function Lookup-Handler {
    Param (
        [string]$type,
        [array]$iocs
    )
    foreach ($ioc in $iocs) {
        if ($type -eq "domain") {
			# ------------------Domain Lookup------------------
            $urls = @(
                "$($osintUrls.vt)/$ioc",
                "$($osintUrls.norton)/$ioc",
                "$($osintUrls.urlscan)/$ioc",
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

            # Remove http:// or https:// for Norton (ensure domain-only)
            if ($url -match '^(https?://)') {
                $urlNorton = $url.Substring($matches[1].Length)  # Remove 'http://' or 'https://'
            } else {
                $urlNorton = $url
            }

            # For VirusTotal, always add "https://" if not already present
            if ($url -match '^(https?://)') {
                $urlVirusTotal = $url  # No change if already has http:// or https://
            } else {
                $urlVirusTotal = "https://$url"  # Add https:// if missing
            }

            # Encode both the original URL and the Norton URL
            $encodedOriginal = Encode-URL -url $ioc
            $encodedNorton = Encode-URL -url $urlNorton
            $encodedVirusTotal = Encode-URL -url $urlVirusTotal  # Ensure the modified URL is encoded for VT

            # Construct URLs for different services
            $urls = @(
                "$($osintUrls.vt)/$($encodedVirusTotal.Double)",  # VirusTotal with https://
                "$($osintUrls.norton)/$($encodedNorton.Single)",   # Norton without https:// or http://
                "$($osintUrls.ibm)/url/$($encodedOriginal.Single)",
                "$($osintUrls.talos)=$($encodedOriginal.Single)"
            )
        } elseif ($type -eq "hash") {
			# -------------------Hash Lookup-------------------
            $urls = @(
                "$($osintUrls.vt)/$ioc",
                "$($osintUrls.otx)=$ioc",
                "$($osintUrls.kasper)/$ioc/results?tab=lookup",
                "$($osintUrls.ibm)/malware/$ioc"
            )
        }

        # Open URLs in the browser and display them in the terminal
        Start-Process $browser -ArgumentList ("-new-window", ($urls -join " "))
        Write-Host "IOC: $ioc"
        Write-Host "--------------------------------------------------"
        $urls | ForEach-Object { Write-Host $_ }
        Write-Host "--------------------------------------------------"
    }
}

# --------------------Main Loop--------------------
Do {
    # Input IOC from the user (mix of domains, IPs, URLs, hashes)
	Write-Host ""
    $iocInput = Read-Host "Enter IOCs (max $iocLimit IOCs)"
	Write-Host ""

    If (-not $iocInput) {
        Write-Host "Enter valid IOCs. With great IOCs come great results!" -ForegroundColor Yellow
        Continue
    }

    # Split on commas, spaces, or "OR" (case insensitive), trim whitespace, and filter out "OR and comma" as valid IOCs.
    $iocs = $iocInput -split '\s*(,|\s+|(?i)\bOR\b)\s*' | Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^(,|(?i)OR)$" }

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

    # Separate the IOCs by type
    $ipIocs = @()
    $domainIocs = @()
    $urlIocs = @()
    $hashIocs = @()

    # Classify each IOC
    foreach ($ioc in $iocs) {
        $ioc = $ioc.Trim()

        if (Is-ValidIP $ioc) {
            $ipIocs += $ioc
        } elseif (Is-ValidDomain $ioc) {
            $domainIocs += $ioc
        } elseif (Is-ValidURL $ioc) {
            $urlIocs += $ioc
        } elseif (Is-ValidHash $ioc) {
            $hashIocs += $ioc
        } else {
            Write-Host "Invalid IOC: $ioc" -ForegroundColor Red
        }
    }

    # Lookup the IOCs by type
    If ($hashIocs) { Lookup-Handler -type "hash" -iocs $hashIocs }
    If ($ipIocs) { Lookup-Handler -type "ip" -iocs $ipIocs }
    If ($domainIocs) { Lookup-Handler -type "domain" -iocs $domainIocs }
    If ($urlIocs) { Lookup-Handler -type "url" -iocs $urlIocs }

} While ($true)
