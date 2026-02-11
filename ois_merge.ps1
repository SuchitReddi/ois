# Opens given Domain/IP/url/hash in reputed OSINT sites.
# Author - Suchit Reddi

# Helper function to search for a file in parentDir, ois* dirs, and their subdirs
function Find-FilePath {
    param(
        [string]$parentDir,
        [string]$fileName
    )
	
    if ([string]::IsNullOrWhiteSpace($parentDir)) { return $null }
	
    # 1. Check parentDir directly
    $candidate = Join-Path -Path $parentDir -ChildPath $fileName
    if (Test-Path $candidate) { return $candidate }

    # 2. Check all OIS* dirs in parentDir
    $oisDirs = Get-ChildItem -Path $parentDir -Directory | Where-Object { $_.Name -like 'ois*' }
    foreach ($dir in $oisDirs) {
        $candidate = Join-Path $dir.FullName $fileName
        if (Test-Path $candidate) { return $candidate }
    }

    # 3. Check all subdirectories of OIS* dirs
    foreach ($dir in $oisDirs) {
        $subdirs = Get-ChildItem -Path $dir.FullName -Directory
        foreach ($subdir in $subdirs) {
            $candidate = Join-Path $subdir.FullName $fileName
            if (Test-Path $candidate) { return $candidate }
        }
    }
    return $null
}

$parentDir = (Get-Location).ProviderPath
$exePath = Find-FilePath -parentDir $parentDir -fileName 'ois.exe'
if ($exePath) { 
    #Write-Host "Debug: EXE file location: $exePath"
    $verInfo = (Get-Item $exePath).VersionInfo
    $fileDesc = $verInfo.FileDescription
    $fileVer = $verInfo.FileVersion
    $prodVer = $verInfo.ProductVersion 
}

function Show-Logo {
Write-Host @"
        _____           __
       /#####\         /##\              __                           
      /##__ ##|   ____ |__|             |##|                         
     | ##  \ #|  /####| __  ________  __|##|__                         
     | ##  | #| /##/__ | #|| ##__###||_ ####_/                          
     | ##  | #||######|| #|| #|  \##|  | ##|                            
     | ##  | #| \____#|| #|| #|  | #|  | ##|__                       
     |  #####//#######|| #|| #|  | #|  | ####/                       
      \_____/ |______/ |__||__/  |__/   \___/     
"@ -ForegroundColor Cyan
Write-Host @"
     ________                          
     |_####_/  _____     ______                                       
       | #|   /#####\   /######|                                       
       | #|  |## __##| /##____/                                       
       | #|  |##|  |#|| #|                                            
      /####\ | ######||  ######|                                       
     |______| \_____/  \______/                                             
"@ -ForegroundColor DarkCyan
Write-Host @"
        _____                                    
       /#####\                                                        
      /##__###|  _______  ______   _______   _______   _______  ________
     |##|  \__/ /######| /######| /#######| /#######| /##__## ||##___ ##| 
     |##\____  /##_____/ |____|#|| ##__###|| ##__###||##|__|#/ |##|  \__/ 
      \____##\| ##        /#__##|| ##  \##|| ##  \##||###___/  |##|      
      _____\##| ##       /#|__|#|| ##  |##|| ##  |##||##|_____ |##|      
     |########|  ######|| ######|| ##  |##|| ##  |##||########\|##|      
      \______/ \_______/\_______||__/  |__||__/  |__/ \_______||__/      
"@ -ForegroundColor Blue
Write-Host "$fileDesc " -NoNewLine
Write-Host "v$fileVer " -ForegroundColor Cyan -NoNewLine
Write-Host "by " -NoNewLine
Write-Host "Suchit" -ForegroundColor Red
}

# ------------------ Helper: Load/Save Config safely ------------------
function Load-Config {
    param([string]$path)
    if (-not $path -or -not (Test-Path $path)) { return [PSCustomObject]@{} }
    try {
        $raw = Get-Content -Path $path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return [PSCustomObject]@{} }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $obj) { return [PSCustomObject]@{} }
        return $obj
    } catch {
        Write-Host "Warning: failed to read/parse config.json at $path. Recreating minimal config." -ForegroundColor Yellow
        return [PSCustomObject]@{}
    }
}

function Save-Config {
    param([object]$cfg, [string]$path)
    if (-not $cfg) { $cfg = [PSCustomObject]@{} }
    try {
        $cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
    } catch {
        throw "Failed to save config to $path : $($_.Exception.Message)"
    }
}
# ---------------------------------------------------------------------

# <----Edit configured values---->
Function Edit-Configuration {
    Param (
        [ref]$browser,
        [ref]$iocLimit
    )

    Do {
        Clear-Host
        Write-ColoredLine "1) Press 1 to change " "IOC limit" ". Current limit: $($iocLimit.Value)" Blue
        Write-ColoredLine "2) Press 2 to choose to " "open/not open results in browser." "" Blue
        Write-ColoredLine "3) Press 3 to " "change browser" ". Current browser: $($browser.Value)" Blue
        Write-ColoredLine "4) Press 4 to choose to " "use/not use URLScan API" "." Blue
        Write-ColoredLine "5) Press 5 to choose to " "use/not use Virus Total API" "." Blue
        Write-ColoredLine "`nPress " "b" " to go back." Red
        $choice = Read-Host "`nTime to choose"
        Write-Host ""

        Switch ($choice) {
            "1" {
                # Changing IOC limit
                $newIocLimit = Read-Host "Enter the new IOC limit"
                Write-Host ""
                if ($newIocLimit -match '^\d+$') {
                    $iocLimit.Value = [int]$newIocLimit
                    $config.ioclim = $iocLimit.Value
                    $config | ConvertTo-Json | Set-Content $configPath
                    Write-ColoredLine "IOC limit changed to " "$newIocLimit" "" Yellow
                } else {
                    Write-Host "Invalid input. Please enter a numeric value." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "2" {
                # Using browser or not
                if ($usebrow -eq "N") {
                    Write-Host "You are currently not opening results in browser. You can change the choice below."
                    Write-Host ""
                } elseif ($usebrow -eq "Y") {
                    Write-Host "You are currently opening results in browser. You can change the choice below."
                    Write-Host ""
                }
                $newusebrowser = Read-Host "Do you want to open the result links directly in the browser? (Y/N)"
                if ($newusebrowser -match '^[YyNn]$') {
                    $usebrowser = $newusebrowser
                    $config.usebrow = $usebrowser
                    $config | ConvertTo-Json | Set-Content $configPath
                    Write-ColoredLine "Use browser status changed to " "$newusebrowser" ". Changes will apply as soon as you go out of editing." Green
                } else {
                    Write-Host "Invalid input. Please enter Y/N value." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "3" {
                # Changing default browser
                Write-Host "Some browsers: chrome, msedge, firefox, iexplore, opera, brave"
                $newBrowser = Read-Host "Enter the new default browser"
                if ($supportedBrowsers -contains $newBrowser) {
                   $browser.Value = $newBrowser
                   $config.defbrow = $browser.Value
                   $config | ConvertTo-Json | Set-Content $configPath
                   Write-ColoredLine "Default browser changed to " "$newBrowser" "" Green
                } else {
                   Write-Host "Invalid browser name. Please enter one of the supported browsers." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "4" {
                # Using urlscan api
                if ($useurlscan -eq "N") {
                    Write-Host "You are currently not using URLScan API. You can change the choice below."
                    Write-Host ""
                } elseif ($useurlscan -eq "Y") {
                    Write-Host "You are currently using URLScan API. You can change the choice below."
                    Write-Host ""
                }
				Write-Host -NoNewline "Red" -ForegroundColor Red
				Write-Host -NoNewline " pill or "
				Write-Host -NoNewline "Blue" -ForegroundColor Blue
				Write-Host " pill, Neo?"
                $newUsage = Read-Host "Take the red pill only if you have an API key (Y/N)"
                if ($newUsage -match '^[YyNn]$') {
                    $urlscanusage = $newUsage
                    $config.useurlscan = $urlscanusage
                    $config | ConvertTo-Json | Set-Content $configPath
                    Write-ColoredLine "URLScan API usage status changed to " "$newUsage" ". Changes will apply as soon as you go out of editing." Yellow
                } else {
                    Write-Host "Invalid input. Please enter Y/N." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "5" {
                # Using vt api
                if ($usevtapi -eq "N") {
                    Write-Host "You are currently not using Virus Total API. You can change the choice below."
                    Write-Host ""
                } elseif ($usevtapi -eq "Y") {
                    Write-Host "You are currently using Virus Total API. You can change the choice below."
                    Write-Host ""
                }
				Write-Host -NoNewline "Red" -ForegroundColor Red
				Write-Host -NoNewline " pill or "
				Write-Host -NoNewline "Blue" -ForegroundColor Blue
				Write-Host " pill, Neo?"
                $newUsagevt = Read-Host "Take the red pill only if you have an API key (Y/N)"
                if ($newUsagevt -match '^[YyNn]$') {
                    $vtapiusage = $newUsagevt
                    $config.usevtapi = $vtapiusage
                    $config | ConvertTo-Json | Set-Content $configPath
                    Write-ColoredLine "Virus Total API usage status changed to " "$newUsagevt" ". Changes will apply as soon as you go out of editing." Yellow
                } else {
                    Write-Host "Invalid input. Please enter Y/N value." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "B" {
				Write-Host "Configuration updated. Changes are applied immediately." -ForegroundColor Green
				Start-Sleep -Seconds 2
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
    #$domainRegex = '^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$'  # Simple domain
    $domainRegex = '^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$' #Stricter with DNS label rules

    #$urlRegex = '^((https?|http?|ftp?):\/\/)?([^\s@\/]+@)?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|({{{{\[[0-9a-fA-F:]+\]}}}}|[0-9a-fA-F:]+))(:\d+)?(\/.*)?(\?.*)?(#[^\s]*)?$'  # URL with optional protocol and path
    $urlRegex = '^(?:(?:https?|ftps?):\/\/)?(?:[^\s\/@]+@)?(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|\[(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]+\])(?::(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]))?(?:\/[^\s?#]*)*(?:\?[^\s#]*)?(?:#[^\s]*)?$' # IP tightened and port constrained. Avoids partial matches

    #$ipRegex = '^(\d{1,3}\.){3}\d{1,3}$'  # Simple IPv4 address
    $ipRegex = '^((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$' # Restricted octet to 0-255

    #$privipRegex = '^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})$'  # Simple Private IP address
    $privipRegex = '^(?:(?:127|10)\.((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){2}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|172\.(?:1[6-9]|2\d|3[0-1])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))$' # Octet restriction

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

# <--------Color for only part of line------->
function Write-ColoredLine {
    param(
        [string]$prefix,
        [string]$colorText,
        [string]$suffix,
        [ValidateSet('Black','DarkBlue','DarkGreen','DarkCyan','DarkRed','DarkMagenta','DarkYellow','Gray','DarkGray','Blue','Green','Cyan','Red','Magenta','Yellow','White')]
        [ConsoleColor]$color = "Yellow"
    )
    Write-Host $prefix -NoNewline
    Write-Host $colorText -ForegroundColor $color -NoNewline
    Write-Host $suffix
}

# =========================
# Inline URLScan function (based on urlscan.ps1)
# Returns PSCustomObject with same fields that the original child script returned as JSON
# =========================
function Invoke-Urlscan {
	param(
		[string]$url,
		[string]$configPath
	)

	if (-not $configPath) {
		throw "Config file not found."
	}

	# Robustly load config (read entire file as string)
	try {
		$raw = Get-Content -Path $configPath -Raw -ErrorAction Stop
		$config = $raw | ConvertFrom-Json -ErrorAction Stop
	} catch {
		$config = $null
	}

	if (-not $config) { $config = [PSCustomObject]@{} }

	$apikey = $null
	if ($config -and $config.useurlscan -eq "Y" -and $config.PSObject.Properties.Name -contains 'urlscanapikey') {
		try {
			$getsecapikey = $config.urlscanapikey | ConvertTo-SecureString
			$apikey = [System.Net.NetworkCredential]::new("", $getsecapikey).Password
		} catch {
			Write-Host "WARNING: Failed to decrypt URLScan API key in config file." -ForegroundColor Red
			$apikey = $null
		}
	}

	# If we still don't have an API key, prompt temporarily (do not save from child script)
	if (-not $apikey -and $config.useurlscan -eq "Y") {
		Write-Host "No URLScan API key found or decryption failed!" -ForegroundColor Red
		$apikey = Read-Host -AsSecureString "Enter your URLScan API Key (temporary)" 
		$apikey = [System.Net.NetworkCredential]::new("", $apikey).Password
	}

        # Search for existing scans for this URL
        $escapedUrl = ($url -replace '([\+\-\=\&\|\>\<\!\(\)\{\}\[\]\^"~\*\?:\\/])', '\$1')
        $searchQuery = "page.url:*$escapedUrl*"
        if ($apikey) { $searchResults = Invoke-RestMethod -Uri "https://urlscan.io/api/v1/search?datasource=scans&q=$searchQuery&size=100" -Headers @{ "api-key" = "$apikey" }}
        $existingResult = $null
        if ($searchResults.results) {
        $existingResult = $searchResults.results | Where-Object { $_.page.status -gt 0 -or $_.page.status } | Select-Object -First 1
        }
        
        $pagedata = $null
        $urlsctitle = $null
        $urlscasn = $null
        $urlscasnname = $null
        $urlscstatus = $null
        $urlscip = $null
        $urlsccountry = $null
        $urlscserver = $null
        $urlscmime = $null

        $pagedata = $existingResult.page
        $urlsctitle = $pagedata.title
        $urlscasn = $pagedata.asn
        $urlscasnname = $pagedata.asnname
        $urlscstatus = $pagedata.status
        $urlscip = $pagedata.ip
        $urlsccountry = $pagedata.country
        $urlscserver = $pagedata.server
        $urlscmime = $pagedata.mimeType

	$theapikey = @{
		"api-key" = "$apikey"
	}
	$theBody = @{
		"url" = "$url"
		"visibility" = "private"
	} | ConvertTo-Json

	try {
		# Posting to URLscan API Key and URL
		$sendtoapi = Invoke-RestMethod -Method Post -Uri "https://urlscan.io/api/v1/scan/" -Headers $theapikey -Body $theBody -ContentType application/json

		# Getting just the section of data that is relevant... Only need $sendtoapi.api, but the UUID is nice to have as well
		$scanuuid = $sendtoapi.uuid
                $uscanapi = $sendtoapi.api
		$oisoutput = $sendtoapi.result
		$ssurl = "https://urlscan.io/screenshots/$scanuuid.png"
		$statmsg = $sendtoapi.message #Only giving submission successful if successful, but no result otherwise

                #Start-Sleep -Seconds 20
                #$uscanres = Invoke-RestMethod -Method Get -Uri "$uscanapi"
                #Write-Host "Page url from result value is $($uscanres)"

                return [PSCustomObject]@{
                        scanuuid      = $scanuuid
                        oisoutput     = $oisoutput
                        ssurl         = $ssurl
                        statusmessage = $statmsg
                        urlsctitle    = $urlsctitle
                        urlscasn      = $urlscasn
                        urlscasnname  = $urlscasnname
                        urlscstatus   = $urlscstatus
                        urlscip       = $urlscip
                        urlsccountry  = $urlsccountry
                        urlscserver   = $urlscserver
                        urlscmime     = $urlscmime
                }
	} catch {
		# Directly use exception message and details, no Write-Host
		$message = $_.Exception.Message
		$description = $_.Exception.ToString()
		return [PSCustomObject]@{
			scanuuid = $null
			oisoutput = $null
			ssurl = $null
			error = $message
			errordesc = $description
			statusmessage = $statmsg
		}
	}
}

# =========================
# Inline Virus Total function (based on vt.ps1)
# Returns PSCustomObject with same fields that the original child script returned as JSON
# =========================
function Invoke-VT {
	param(
		[string]$vturl,
		[string]$vtdomain,
		[string]$vtip,
		[string]$vtfilehash,
		[string]$configPath
	)

	if (-not $configPath) {
	    throw "Config file not found."
	}
	$raw = $null
	$config = $null
	# Robustly load config (read entire file as string)
	try {
	    $raw = Get-Content -Path $configPath -Raw -ErrorAction Stop
	    $config = $raw | ConvertFrom-Json -ErrorAction Stop
	} catch {
	    $config = $null
	}

	if (-not $config) { $config = [PSCustomObject]@{} }

	$apikey = $null
	if ($config -and $config.PSObject -and $config.PSObject.Properties.Name -contains 'virustotalapikey') {
		try {
		    $getsecapikey = $config.virustotalapikey | ConvertTo-SecureString
		    $apikey = [System.Net.NetworkCredential]::new("", $getsecapikey).Password
		} catch {
		    Write-Host "WARNING: Failed to decrypt Virus Total API key in config file." -ForegroundColor Red
		    $apikey = $null
		}
	}

	# If we still don't have an API key, prompt temporarily (do not save from child script)
	if (-not $apikey) {
		Write-Host "No Virus Total API key found or decryption failed!" -ForegroundColor Red
		$tmp = Read-Host -AsSecureString "Enter your Virus Total API Key (temporary)"
		$apikey = [System.Net.NetworkCredential]::new("", $tmp).Password
	}

	$lastanalysistimeepoch = $null

        $tz = [System.TimeZoneInfo]::Local
        $tzid = $tz.Id
        $tzoffset = $tz.BaseUtcOffset
        $tzh = $tzoffset.Hours
        $tzm = $tzoffset.Minutes

	# Convert Epoch time from API to human readable
	function Get-TimeAgo($epoch) {
		$dt = [System.DateTimeOffset]::FromUnixTimeSeconds($epoch). ToLocalTime(). DateTime
		$now = Get-Date 
		$span = $now - $dt

		if ($span.TotalDays -gt 365) {
			return "{0} years ago" -f [math]::Floor($span.TotalDays / 365)
		} elseif ($span.TotalDays -gt 30) {
			return "{0} months ago" -f [math]::Floor($span.TotalDays / 30)
		} elseif ($span.TotalDays -gt 1) {
			return "{0} days ago" -f [math]::Floor($span.TotalDays)
		} elseif ($span.TotalHours -gt 1) {
			return "{0} hours ago" -f [math]::Floor($span.TotalHours)
		} elseif ($span.TotalMinutes -gt 1) {
			return "{0} minutes ago" -f [math]::Floor($span.TotalMinutes)
		} elseif ($span.TotalSeconds -gt 1) {
			return "{0} seconds ago" -f [math]::Floor($span.TotalSeconds)
		} else {
			return "just now"
		}
	}

	# Convert Bytes to human readable
	function File-Size {
		param([long]$bytes)
		if ($bytes -ge 1GB) {
			return "{0:N2} GB" -f ($bytes / 1GB)
		} elseif ($bytes -ge 1MB) {
			return "{0:N2} MB" -f ($bytes / 1MB)
		} elseif ($bytes -ge 1KB) {
			return "{0:N2} KB" -f ($bytes / 1KB)
		} else {
			return "$bytes bytes"
		}
	}

	function Get-VTPolling {
		param(
			[string]$uri
		)
		$maxTries = 30
		$try = 0
		$scanReady = $false
		$json = $null
                $yearsSinceEpoch = (Get-Date).Year - 1970
                $invalidTimeAgo  = "{0} years ago" -f $yearsSinceEpoch

		while (-not $scanReady -and $try -lt $maxTries) {
			Start-Sleep -Seconds 1
			$try++
			try {
		            $headers=@{}
			    $headers.Add("accept", "application/json")
			    $headers.Add("x-apikey", $apikey)
			    $scanResult = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
			    $lastanalysistimeepoch = $scanResult.data.attributes.last_analysis_date
			    $timeago = Get-TimeAgo $lastanalysistimeepoch

			    #Write-Host ("Try " + $try + ": last_analysis_date=" + $lastanalysistimeepoch + " | timeago=" + $timeago)

			    if ($lastanalysistimeepoch -and $lastanalysistimeepoch -ne 0 -and $timeago -ne $invalidTimeAgo) {
			 	$scanReady = $true
			    }
			} catch {
			    $stream = $_. Exception.Response.GetResponseStream()
			    if ($null -eq $stream) { break }
			    $body = (New-Object System.IO.StreamReader($stream)). ReadToEnd()
			    try { $json = $body | ConvertFrom-Json } catch { $json = $null }
			    # I don't know why, but unlike the url, this works only when I removed the -not in front of the if condition or left it untouched and changed break to continue.
			    if ($json -and $json.error.code -eq "NotFoundError") { break }
			}
		}

		if ($scanReady) {
			return $scanResult
		} else {
			Write-Host "VirusTotal report is not available even after $maxTries attempts." -ForegroundColor Red
			return $null
		}
	}
	
	$headers=@{ "accept"="application/json"; "x-apikey"=$apikey }
    $response = $null
	if ($vturl) {
		# <!---------URL---------!>
		# Headers for the URL rescan API call
		$headers.Add("content-type", "application/x-www-form-urlencoded")
		$urlbody = "url=$vturl"
		# Posting to Virus Total Scan URL API
		$responsePost = Invoke-RestMethod -Uri 'https://www.virustotal.com/api/v3/urls' -Method POST -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $urlbody

		#Extracting the analysis ID for retreiving results. It is different for URLs as we need to strip the head and tail.
		$id = $responsePost.data.id
		$analysisid = $id -replace '^[^-]+-([^-]+)-.*$', '$1'
		$analysisurl = "https://www.virustotal.com/api/v3/urls/$analysisid"

		# Getting from Get a URL/file analysis API
		$response = Get-VTPolling -Uri $analysisurl
	} elseif ($vtdomain) {
		# <!---------Domain---------!>
		$uri = "https://www.virustotal.com/api/v3/domains/$vtdomain"
		$responsePost = Invoke-RestMethod -Uri $uri/analyse -Method POST -Headers $headers

		# After sending the domain for rescan, let's get the domain report
		$response = Get-VTPolling -uri $uri
	} elseif ($vtip) {
		# <!---------IP---------!>
		$uri = "https://www.virustotal.com/api/v3/ip_addresses/$vtip"
		$responsePost = Invoke-RestMethod -Uri $uri/analyse -Method POST -Headers $headers

		# Getting from Get a URL/file analysis API
		#$response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
		$response = Get-VTPolling -uri $uri
	} elseif ($vtfilehash) {
		# <!---------Hash---------!>
		$uri = "https://www.virustotal.com/api/v3/files/$vtfilehash"
		$responsePost = Invoke-RestMethod -Uri $uri/analyse -Method POST -Headers $headers

		# Headers for the File hash API call.
		$response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
		# Polling is not feasible for hashes as it takes too long.
		#$response = Get-VTPolling -uri $uri
	}

	# Removing the section "extensions" because it has Dll and dll which is causing case-insensitivity issues if response type is string. Ex hash: 45bce435c83ee84771c52d626448631e757bc34e347849e2b61fd032a42c28e3
	if ($response -and $response.GetType(). FullName -eq 'System.String') {
		# Removing the "bunlde_info.extensions" block before parsing due to duplicate case keys (Dll/dll issue)
		$response = $response -replace '"extensions"\s*:\s*\{[^\}]*\},', ''
		$response = $response | ConvertFrom-Json
	}

	$total = $null
	$malscore = $null
	$vtscore = $null

	if ($response.data.attributes.PSObject.Properties.Name -contains "last_analysis_stats") {
		# Assigning values for malicious, suspicious, undetected and harmless stats for domain, url, and hash.
		$mal = $response.data.attributes.last_analysis_stats.malicious
		$sus = $response.data.attributes.last_analysis_stats.suspicious
		$und = $response.data.attributes.last_analysis_stats.undetected
		$har = $response.data.attributes.last_analysis_stats.harmless
		$tim = $response.data.attributes.last_analysis_stats.timeout 
		$total = $mal+$sus+$und+$har+$tim
		$malscore = $mal
		$vtscore = "$malscore/$total"
	}

	$size = $null
	$tags = $null
	$uncompsize = $null
	$timeago = $null
	$filesnum = $null
	$hasexe = $null
	$respcode = $null
	$regdateiso = $null
	$updateiso = $null
	$expdateiso = $null

	# This below code dictates what values we retreive for each IOC type
	if ($vtfilehash) {
		# Basic exiftool fields
		$proname = $response.data.attributes.exiftool.ProductName
		$names = $response.data.attributes.names
		$tagresult = $response.data.attributes.tags
		if ($tagresult -and $tagresult.Count -gt 0) { 
			$tags = $tagresult 
		}
		$intname = $response.data.attributes.exiftool.InternalName
		$fildesc = $response.data.attributes.exiftool.FileDescription
		$filtype = $response.data.attributes.type_extension

		# Digital signature details
		$sigver = $null
		$signer = $null
		if ($response.data.attributes.signature_info.verified) {
			$sigver = $response.data.attributes.signature_info.verified
			$signer = $response.data.attributes.signature_info.signers
		}

		# File size details
		$sizeinbytes = $response.data.attributes.size
		$size = File-Size $sizeinbytes

		# Getting last analysed time
		$lastanalysistimeepoch = $response.data.attributes.last_analysis_date
		$lasttime = (Get-Date -Date "1970-01-01 00:00:00Z"). AddSeconds($lastanalysistimeepoch)
		$lasttimeout = $lasttime.ToString("dd MMMM yyyy HH:mm:ss") + " " + $tzid + " (UTC " + $tzh + ":" + $tzm + ")"
		$timeago = Get-TimeAgo $lastanalysistimeepoch

		# In case of zip file, getting bundle info
		$bundledfiles = $response.data.attributes.bundle_info
		if ($bundledfiles) {
			$filesnum = $bundledfiles.num_children
			$uncompsizeinbytes = $bundledfiles.uncompressed_size
			$uncompsize = File-Size $uncompsizeinbytes
			$hasexe = $bundledfiles.file_types.'Portable Executable'
		}
	} elseif ($vturl) {
		# Getting last analysed time
		$lastanalysistimeepoch = $response.data.attributes.last_analysis_date
		$timeago = Get-TimeAgo $lastanalysistimeepoch
		$lasttime = (Get-Date -Date "1970-01-01 00:00:00Z"). AddSeconds($lastanalysistimeepoch)
		$lasttimeout = $lasttime.ToString("dd MMMM yyyy HH:mm:ss") + " " + $tzid + " (UTC " + $tzh + ":" + $tzm + ")"

		# Getting http response code
		$respcode = $response.data.attributes.last_http_response_code
	} elseif ($vtdomain -or $vtip) {
		# Getting last analysed time
		$lastanalysistimeepoch = $response.data.attributes.last_analysis_date
		$timeago = Get-TimeAgo $lastanalysistimeepoch
		$lasttime = (Get-Date -Date "1970-01-01 00:00:00Z"). AddSeconds($lastanalysistimeepoch)
		$lasttimeout = $lasttime.ToString("dd MMMM yyyy HH:mm:ss") + " " + $tzid + " (UTC " + $tzh + ":" + $tzm + ")"

		$registrar = $response.data.attributes.registrar

		# Registration, Update, and Expiration details using RDAP fields
		$rdap = $response.data.attributes.rdap
		$regdateiso = ($rdap.events | Where-Object { $_.event_action -eq "registration" }).event_date
		$updateiso = ($rdap.events | Where-Object { $_.event_action -eq "last changed" }).event_date
                $rdapname = $rdap.name
                if ($response.data.attributes.country) {
                    $rdapcn = $response.data.attributes.country
                } elseif ($rdap.country) {
                    $rdapcn = $rdap.country
                }
                $asn = $response.data.attributes.asn
                $asowner = $response.data.attributes.as_owner

		# Converting to readable and epoch dates. Cnvert the readable dates to strings so that they won't get changed into epoch when converted into json.
		if ($regdateiso) {
			$regdate = [datetime]::Parse($regdateiso)
			$regdateout = $regdate.ToString("dd MMMM yyyy HH:mm:ss") + " " + $tzid + " (UTC " + $tzh + ":" + $tzm + ")"
			$regdateepoch = [int][double]([datetimeoffset]$regdate). ToUnixTimeSeconds()
			$regtimeago = Get-TimeAgo $regdateepoch
		}

		if ($updateiso) {
			$update = [datetime]::Parse($updateiso)
			$updateout = $update.ToString("dd MMMM yyyy HH:mm:ss") + " " + $tzid + " (UTC " + $tzh + ":" + $tzm + ")"
			$updateepoch = [int][double]([datetimeoffset]$update). ToUnixTimeSeconds()
			$uptimeago = Get-TimeAgo $updateepoch
		}

		# IPs don't have expiration date, so doing it only for domain
		if ($vtdomain) { 
			$expdateiso = ($response.data.attributes.rdap.events | Where-Object { $_.event_action -eq "expiration" }).event_date
			if ($expdateiso) {
				$expdate = [datetime]::Parse($expdateiso)
				$expdateout = $expdate.ToString("dd MMMM yyyy HH:mm:ss") + " " + $tzid + " (UTC " + $tzh + ":" + $tzm + ")"
			}
		}
	} else {
		# Getting last analysed time
		$lastanalysistimeepoch = $response.data.attributes.date
		$timeago = Get-TimeAgo $lastanalysistimeepoch
		$lasttime = (Get-Date -Date "1970-01-01 00:00:00Z"). AddSeconds($lastanalysistimeepoch)
		$lasttimeout = $lasttime.ToString("dd MMMM yyyy HH:mm:ss") + " " + $tzid + " (UTC " + $tzh + ":" + $tzm + ")"
	}

	try {
		return [PSCustomObject]@{
			total = $total
			malscore = $malscore
			vtscore = $vtscore
			proname = $proname
			rdapname = $rdapname
			rdapcn = $rdapcn
			asn = $asn
			asowner = $asowner
			names = $names
			tags = $tags
			intname = $intname
			fildesc = $fildesc
			filtype = $filtype
			sigver = $sigver
			signer = $signer
			size = $size
			uncompsize = $uncompsize
			timeago = $timeago
			lasttimeout = $lasttimeout
			filesnum = $filesnum
			hasexe = $hasexe
			respcode = $respcode
			registrar = $registrar
			regdateout = $regdateout
			updateout = $updateout
			expdateout = $expdateout
			regtimeago = $regtimeago
			uptimeago = $uptimeago
		}
	} catch {
		# Directly use exception message and details, no Write-Host
		$message = $_.Exception.Message
		$description = $_.Exception.ToString()

		return [PSCustomObject]@{
			total = $null
			malscore = $null
			vtscore = $null
			proname = $null
			rdapname = $null
			rdapcn = $null
			asn = $null
			asowner = $null
			names = $null
			tags = $null
			intname = $null
			fildesc = $null
			filtype = $null
			sigver = $null
			signer = $null
			size = $null
			uncompsize = $null
			timeago = $null
			lasttimeout = $null
			filesnum = $null
			hasexe = $null
			respcode = $null
			registrar = $null
			regdateout = $null
			updateout = $null
			expdateout = $null
			regtimeago = $null
			uptimeago = $null
			error = $message
			errordesc = $description
		}
	}
}
# =========================
# Inline VirusTotal function ends here
# =========================

# =========================
# Inline IPQuery function starts here
# =========================
function Invoke-IPQuery {
	param(
		[string]$ip
	)

	try {
		$ipqapi = Invoke-RestMethod -Method Get -Uri "https://api.ipquery.io/$($ip)?format=json"

		# Getting just the section of data that is relevant... Only need $sendtoapi.api, but the UUID is nice to have as well
		$asnipq = $ipqapi.isp.asn
		$orgipq = $ipqapi.isp.org
		$ispipq = $ipqapi.isp.isp
		$couipq = $ipqapi.location.country
		$stateipq = $ipqapi.location.state
		$cityipq = $ipqapi.location.city
		$riskipq = $ipqapi.risk
		$ismobile = $riskipq.is_mobile
		$isvpn = $riskipq.is_vpn
		$istor = $riskipq.is_tor
		$isproxy = $riskipq.is_proxy
		$isdatacenter = $riskipq.is_datacenter

		return [PSCustomObject]@{
			asnipq = $asnipq
			orgipq = $orgipq
			ispipq = $ispipq
			couipq = $couipq
			stateipq = $stateipq
			cityipq = $cityipq
			riskipq = $riskipq
			ismobile = $ismobile
			isvpn = $isvpn
			istor = $istor
			isproxy = $isproxy
			isdatacenter = $isdatacenter
		}
	} catch {
		# Directly use exception message and details, no Write-Host
		$message = $_.Exception.Message
		$description = $_.Exception.ToString()
		return [PSCustomObject]@{
			asnipq = $null
			orgipq = $null
			ispipq = $null
			couipq = $null
			stateipq = $null
			cityipq = $null
			riskipq = $null
			ismobile = $null
			isvpn = $null
			istor = $null
			isproxy = $null
			isdatacenter = $null
			error = $message
			errordesc = $description
			statusmessage = $statmsg
		}
	}
}
# =========================
# Inline IPQuery function ends here
# =========================

# =========================
# Now the main script logic (based on your ois.ps1) but calling the above functions
# =========================
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
    "mxtoolbox" = "https://mxtoolbox.com/SuperTool.aspx?action=blacklist"
}

# Ask user if they want to use urlscan or not
function Get-UseUrlscanPreference {
    param([string]$configPath)
    $config = $null
	try {
		$raw = Get-Content -Path $configPath -Raw -ErrorAction Stop
		$config = $raw | ConvertFrom-Json -ErrorAction Stop
	} catch {
		$config = $null
	}

    if (-not ($config.PSObject -and $config.PSObject.Properties.Name -contains 'useurlscan')) {
        if (-not $config) { $config = [PSCustomObject]@{} }
        $config | Add-Member -MemberType NoteProperty -Name 'useurlscan' -Value ""
        Save-Config -cfg $config -path $configPath
    }

    if ([string]::IsNullOrWhiteSpace($config.useurlscan) -and $configPath) {
        do {
            Write-Host "This script allows you to use URLScan API to get better URL search results."
            Write-ColoredLine "If you don't have an account, create one at " "https://urlscan.io/user/signup" "" Cyan
            Write-ColoredLine "If you already have an account, get the API key here " "https://urlscan.io/user/profile/" "" Cyan
            Write-Host "Click on the New API key button to create an API key."
            Write-Host "If you want to change the choice later, go to the edit menu"
            $yorn = Read-Host "`nDo you want to use URLScan API? Select Y only if you have an API key (Y/N)"
			Write-Host ""
        } while ($yorn -notmatch '^[YyNn]$')
        $config.useurlscan = $yorn.ToUpper()
        Save-Config -cfg $config -path $configPath
    }
    return $config.useurlscan
}

# Ask user if they want to use virus total api or not
function Get-UseVTApiPreference {
    param([string]$configPath)
    $config = $null
	try {
		$raw = Get-Content -Path $configPath -Raw -ErrorAction Stop
		$config = $raw | ConvertFrom-Json -ErrorAction Stop
	} catch {
		$config = $null
	}

    if (-not ($config.PSObject -and $config.PSObject.Properties.Name -contains 'usevtapi')) {
        if (-not $config) { $config = [PSCustomObject]@{} }
        $config | Add-Member -MemberType NoteProperty -Name 'usevtapi' -Value ""
        Save-Config -cfg $config -path $configPath
    }

    if ([string]::IsNullOrWhiteSpace($config.usevtapi) -and $configPath) {
        do {
            Write-Host "`nThis script allows you to use Virus Total API to submit and pull results."
            Write-ColoredLine "If you don't have an account, create one at " "https://www.virustotal.com/gui/join-us" "" Cyan
            Write-Host "If you already have an account, get the API key from the profile icon on the top right corner"
            Write-Host "If you want to change the choice later, go to the edit menu"
            $yornvt = Read-Host "`nDo you want to use Virus Total API? Select Y only if you have an API key (Y/N)"
			Write-Host ""
        } while ($yornvt -notmatch '^[YyNn]$')
        $config.usevtapi = $yornvt.ToUpper()
        Save-Config -cfg $config -path $configPath
    }
    return $config.usevtapi
}

# Ask user if they want to open result links in browser or not
function Get-UseBrowser {
    param([string]$configPath)
    $config = $null
	try {
		$raw = Get-Content -Path $configPath -Raw -ErrorAction Stop
		$config = $raw | ConvertFrom-Json -ErrorAction Stop
	} catch {
		$config = $null
	}

    if (-not ($config.PSObject -and $config.PSObject.Properties.Name -contains 'usebrow')) {
        if (-not $config) { $config = [PSCustomObject]@{} }
        $config | Add-Member -MemberType NoteProperty -Name 'usebrow' -Value ""
        Save-Config -cfg $config -path $configPath
    }

    if ([string]::IsNullOrWhiteSpace($config.usebrow) -and $configPath) {
        do {
            Write-Host "`nThis script allows you to open the reference links automatically in the browser. Each IOC results open in a new window."
            $yornusebrow = Read-Host "Do you want to open the result links directly in the browser? (Y/N)"
        } while ($yornusebrow -notmatch '^[YyNn]$')
        $config.usebrow = $yornusebrow.ToUpper()
        Save-Config -cfg $config -path $configPath
		Write-Host "`nSaved preferences to config file" -ForegroundColor Green
		Start-Sleep -Seconds 2
		Clear-Host
    }
    return $config.usebrow
}

# <----IOC Type handling function---->
Function Lookup-Handler {
    Param (
        [string]$type,
        [array]$iocs
    )

    $allUrlscanTasks = @()

    foreach ($ioc in $iocs) {
        Write-ColoredLine "" "`nIOC ($type): " "$ioc" Blue
        <# Getting IP info from ipquery #>
        if ($type -eq "ip") {
            $resultipq = Invoke-IPQuery -ip $ioc
        }

        if ($useurlscan -eq "Y" -and $type -eq "url" -or $type -eq "domain") {
            $usresult = Invoke-Urlscan -url $ioc -configPath $configPath

            $uscanuuid     = $usresult.scanuuid
            $uscanoutput   = $usresult.oisoutput
            $uscanss       = $usresult.ssurl
            $usstatmsg     = $usresult.statusmessage
            $urlsctitle    = $usresult.urlsctitle
            $urlscasn      = $usresult.urlscasn
            $urlscasnname  = $usresult.urlscasnname
            $urlscstatus   = $usresult.urlscstatus
            $urlscip       = $usresult.urlscip
            $urlsccountry  = $usresult.urlsccountry
            $urlscserver   = $usresult.urlscserver
            $urlscmime     = $usresult.urlscmime
        }

        <# Getting VT details for all IOC types if VT API is being used #>
        if ($usevtapi -eq "Y" -or $resultipq.asnipq -or $usresult) {
            $resultvt = $null
            if ($usevtapi -eq "Y") {
                switch ($type) {
                    "ip"    { $resultvt = Invoke-VT -vtip $ioc -configPath $configPath 2>$null }
                    "hash"  { $resultvt = Invoke-VT -vtfilehash $ioc -configPath $configPath 2>$null }
                    "domain"{ $resultvt = Invoke-VT -vtdomain $ioc -configPath $configPath 2>$null }
                    "url"   { $resultvt = Invoke-VT -vturl $ioc -configPath $configPath 2>$null }
                    "private_ip" { Write-Host "Not sending to Virus Total as this is a Private IP" }
                    default { Write-Host "Virus Total says Unknown type: $type"; return }
                }
        }
			
            if ($resultvt -or $resultipq -or $usresult) {
                try {
                    $yearsSinceEpoch = (Get-Date).Year - 1970
                    $invalidTimeAgo  = "{0} years ago" -f $yearsSinceEpoch

                    if ($type -eq "hash" -and $resultvt.timeago -eq $invalidTimeAgo) {
                        Write-Host "This hash has no results in Virus Total!" -ForegroundColor Red
                    }

                    # Verdict will be malicious if malscore is greater than 0
                    if ($resultvt.malscore -gt 0 -and $resultvt.total) {
                        Write-ColoredLine "Virus Total verdict is " "malicious ($($resultvt.vtscore))" "" Red
                    } elseif ($resultvt.malscore -eq 0 -and $resultvt.total) {
                        Write-ColoredLine "Virus Total verdict is " "clean ($($resultvt.vtscore))" "" Green
                    } elseif ($type -ne "hash" -and -not $resultvt.total -and $usevtapi -eq "Y") {
                        Write-Host "Could not get verdict. Waiting time is too long..." -ForegroundColor Yellow
                    }

                    if ($resultvt.timeago -and $resultvt.timeago -ne $invalidTimeAgo)  { Write-Host "Last Analysis: $($resultvt.timeago) on $($resultvt.lasttimeout)" -ForegroundColor DarkYellow }
                    # Result tags if any
                    if ($resultvt.tags -and $resultvt.tags.Count -gt 0) {
			Write-Host ("Tags: " + ($resultvt.tags[0..([Math]::Min(9, $resultvt.tags.Count - 1))] -join ', ')) -ForegroundColor Cyan
		    }

                    # These values will only be seen for file hashes
                    if ($resultvt.names -and $resultvt.names.Count -gt 0) {
			Write-Host ("Names found for this hash: " + ($resultvt.names[0..([Math]::Min(6, $resultvt.names.Count - 1))] -join ', ')) -ForegroundColor DarkCyan
		    }

                    if ($resultvt.proname)  { Write-ColoredLine "" "Product Name: " "$($resultvt.proname)" Yellow }
                    if ($resultvt.intname)  { Write-ColoredLine "" "Internal Name: " "$($resultvt.intname)" Yellow }
                    if ($resultvt.fildesc)  { Write-ColoredLine "" "File Description: " "$($resultvt.fildesc)" Yellow } 

                    # Checking if the file is signed
                    if ($resultvt.filtype -and $resultvt.sigver) {
                        Write-ColoredLine "File signed by: " "$($resultvt.signer)" "" Green
                    } elseif ($resultvt.filtype -and $resultvt.sigver -eq $null) {
                        Write-ColoredLine "File signed by: " "Not Signed!" "" Red
                    }

                    if ($resultvt.filtype) { Write-ColoredLine "" "File Type: " "$($resultvt.filtype)" Yellow }

                    if ($urlscasn) { Write-ColoredLine "" "ASN (URLScan): " "$urlscasn" DarkCyan }
                    if ($urlscasnname) { Write-ColoredLine "" "ASN Name (URLScan): " "$urlscasnname" DarkCyan }  

                    if ($urlsctitle) { Write-ColoredLine "" "Page Title: " "$urlsctitle" Yellow }
                    if ($urlscmime) { Write-ColoredLine "" "Mime Type: " "$urlscmime" Yellow }
                    if ($urlscip) { Write-ColoredLine "Hosting IP: " "$urlscip" "" Green }
                    if ($urlscserver) { Write-ColoredLine "" "Hosting Server: " "$urlscserver" Yellow }

                    $respcode = $resultvt.respcode
                    if (-not $respcode) { $respcode = $urlscstatus }

                    if ($respcode) {
                        if ($respcode -ge 200 -and $respcode -lt 300) {
                            Write-ColoredLine "HTTP Response Code: " "$($respcode)" "" Green # Success (2xx)
                        } elseif ($respcode -ge 300 -and $respcode -lt 400)  {
                            Write-ColoredLine "HTTP Response Code: " "$($respcode)" "" Yellow # Redirect (3xx)
                        } elseif ($respcode -ge 400 -and $respcode -lt 600)  {
                            Write-ColoredLine "HTTP Response Code: " "$($respcode)" "" Red # Client Error (4xx) or Server Error (5xx)
                        } else {
                            Write-ColoredLine "" "HTTP Response Code: " "$($respcode)" Yellow
                        }
                    }                  
		
                    #IP related ASN and owner info			
                    if ($resultipq.asnipq) { Write-ColoredLine "" "ASN (IPQuery): " "$($resultipq.asnipq)" DarkCyan }
					
                    if ($resultipq.orgipq -or $resultipq.ispipq) {
                        if ($resultipq.orgipq -eq $resultipq.ispipq) { 
                            Write-ColoredLine "" "AS Org/ISP: " "$($resultipq.orgipq)" DarkCyan 
                        } elseif ($resultipq.orgipq) {
                            Write-ColoredLine "" "AS Org: " "$($resultipq.orgipq)" DarkCyan
                        } elseif ($resultipq.ispipq) {
                            Write-ColoredLine "" "AS ISP: " "$($resultipq.ispipq)" DarkCyan
                        }
                    }
		    $vtasn = "AS$($resultvt.asn)"			
                    if ($resultipq.asnipq -and ($vtasn -ne $resultipq.asnipq))  { Write-ColoredLine "" "ASN (Virus Total): " "$vtasn" DarkCyan }
                    if (($resultvt.asowner -ne $resultipq.orgipq) -and ($resultvt.asowner -ne $resultipq.ispipq)) { Write-ColoredLine "" "ASN Owner (Virus Total): " "$($resultvt.asowner)" DarkCyan }
                    if ($resultvt.registrar)  { Write-ColoredLine "" "Registrar: " "$($resultvt.registrar)" Yellow }
                    if ($resultvt.rdapname)  { Write-ColoredLine "" "Name: " "$($resultvt.rdapname)" Yellow }
					
                    if ($resultipq.cityipq -and $resultipq.stateipq -ne $resultipq.cityipq) { Write-ColoredLine "" "City: " "$($resultipq.cityipq)" Blue }
		    if ($resultipq.stateipq) { Write-ColoredLine "" "State: " "$($resultipq.stateipq)" Blue }
		    if ($resultipq.couipq) { Write-ColoredLine "" "Country: " "$($resultipq.couipq)" Blue }
					
                    if (-not $resultipq.couipq -and $resultvt.rdapcn)  { Write-ColoredLine "" "Country: " "$($resultvt.rdapcn)" Blue }
                    
                    if ($urlsccountry) { Write-ColoredLine "" "Country: " "$urlsccountry" Blue }
					
                    if ($resultipq.ismobile) { Write-ColoredLine "" "Is Mobile: " "$($resultipq.ismobile)" DarkRed }
                    if ($resultipq.isvpn) { Write-ColoredLine "" "Is VPN: " "$($resultipq.isvpn)" DarkRed }
                    if ($resultipq.istor) { Write-ColoredLine "" "Is Tor: " "$($resultipq.istor)" DarkRed }
                    if ($resultipq.isproxy) { Write-ColoredLine "" "Is Proxy: " "$($resultipq.isproxy)" DarkRed }
                    if ($resultipq.isdatacenter) { Write-ColoredLine "" "Is Datacenter: " "$($resultipq.isdatacenter)" DarkRed }
					
                    if ($resultvt.regdateout)  { Write-ColoredLine "" "Registered on: " "$($resultvt.regtimeago) on $($resultvt.regdateout)" Yellow }
                    if ($resultvt.updateout)  { Write-ColoredLine "" "Updated on: " "$($resultvt.uptimeago) on $($resultvt.updateout)" Yellow }
                    if ($resultvt.expdateout)  { Write-ColoredLine "" "Expiring on: " "$($resultvt.expdateout)" Red }
                    if ($resultvt.size -and $resultvt.timeago -ne $invalidTimeAgo)  { Write-ColoredLine "" "File Size: " "$($resultvt.size)" Yellow }
                    if ($resultvt.uncompsize)  { Write-Host "There are $($resultvt.filesnum) files. Uncompressed size is $($resultvt.uncompsize)" }
                    if ($resultvt.hasexe -and $resultvt.hasexe -gt 0)  { Write-ColoredLine "" "Warning! " "Contains $($resultvt.hasexe) executables!" Red }
                }
                catch {
		    Write-Host "Error parsing VT result. Maybe this IOC was never submitted." -ForegroundColor Red
		    Write-Host "Open the link from references or try again after sometime to get api results." -ForegroundColor DarkRed
                }
            } else {
                Write-Host "No VT result for $ioc"
            }
        }

        if ($type -eq "private_ip") {
            Write-Host "<----------------------------------------------------------------->"
            Write-Host "$ioc is a private IP :(" -ForegroundColor Yellow
            Write-Host "<----------------------------------------------------------------->"
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
                "$($osintUrls.mxtoolbox)%3a$ioc",
                "$($osintUrls.talos)=$ioc",
                "$($osintUrls.ibm)/url/$ioc",
                "$($osintUrls.abip)/$ioc",
                "$($osintUrls.shodan)=$ioc"
            )
        } elseif ($type -eq "url") {
            # -------------------URL Lookup--------------------
            $url = $ioc
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
            if ($usebrow -eq "Y") {Start-Process $browser -ArgumentList ("-new-window", ($urls -join " "))}
            Write-ColoredLine "<------------------------" "Reference links" "-------------------------->" Cyan
            $urls | ForEach-Object { Write-Host $_ }
            Write-Host "<----------------------------------------------------------------->"
        }

        # Print URLscan results and collect for later polling
        if ($type -eq "url" -and $useurlscan -eq "Y" -and $usstatmsg -eq "Submission successful") {
            Write-ColoredLine "<--------------------------" "URLscan results" "------------------------>" Green
            $uscanurls | ForEach-Object { Write-Host $_ }
            Write-Host "<----------------------------------------------------------------->"

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
            Write-ColoredLine "<--------------------------" "URLscan results" "------------------------>" Red
            Write-Host "URLScan was not able to scan this IOC. You can try submitting manually." -ForegroundColor Red
            Write-Host "<----------------------------------------------------------------->"  
        }
    }

    # Poll and open URLscan results after all IOCs are processed
    if ($usebrow -eq "Y") {
        foreach ($task in $allUrlscanTasks) {
            $scanReady = $false
            $maxTries = 20
            $try = 0
            while (-not $scanReady -and $try -lt $maxTries) {
                Start-Sleep -Seconds 1
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
                Write-Host "URLScan result for this IOC is not available yet. Open the above link after a while..." -ForegroundColor Red
            }
        }
    }
}

Show-Logo

Write-Host "`n'i' to know more about the tool 
'e' to edit configuration" -ForegroundColor DarkGreen

Write-Host "'c' to clear the console
'q' to quit" -ForegroundColor DarkRed

# Setup config path
$parentDir = (Get-Location).ProviderPath
$configPath = Find-FilePath -parentDir $parentDir -fileName 'config.json'
if ($configPath) { Write-Host "`nConfig file location: $configPath" }
#Write-Host "DEBUG: parentDir='$parentDir'  configPath='$configPath'"

Write-Host "`nWelcome, Sherlock. The game is on!" -ForegroundColor Magenta

# Creating config.json if it isn't found in present working directory. Need to enhance location thing later.
if (-not $configPath) {
    $configPath = Join-Path -Path (Get-Location) -ChildPath 'config.json'
    $defaultConfig = @{
        ioclim            = 4
        usebrow           = ""
        defbrow           = "chrome"
        useurlscan        = ""
        urlscanapikey     = ""
        usevtapi          = ""
        virustotalapikey  = ""
    }
    $defaultConfig | ConvertTo-Json -Depth 4 | Set-Content -Path $configPath -Encoding UTF8
    Write-Host "`nconfig.json was not found. Created default config file at: $configPath" -ForegroundColor Red
    Write-ColoredLine "" "IMP: " "Please update your API keys and other settings before continuing by entering e." Red
    Write-Host ""
}

# =========================
# Interactive main loop (kept behaviorally the same)
# =========================
Do {

    # Get choices from user/config
    $useurlscan = Get-UseUrlscanPreference -configPath $configPath
    # ----- RELOAD CONFIG SO SCRIPT-LEVEL $config IS CURRENT -----
    $config = Load-Config -path $configPath

    if ($useurlscan -eq "Y" -and -not $config.urlscanapikey) {
        Write-Host "No URLScan API key found!" -ForegroundColor Red
        $urlapikey = Read-Host "Enter your URLScan API Key (Changes will apply from the next IOC submission)"
        $dosecapikey = ConvertTo-SecureString $urlapikey -AsPlainText -Force
        if ($config -and $config.PSObject -and $config.PSObject.Properties.Name -contains 'urlscanapikey') {
        $config.urlscanapikey = $dosecapikey | ConvertFrom-SecureString
        } else {
            if ($null -eq $config -or $config.GetType().Name -ne 'PSCustomObject') {
                # create an empty object but DO NOT overwrite valid config
                $config = [PSCustomObject]@{}
            }
            $config | Add-Member -MemberType NoteProperty -Name 'urlscanapikey' -Value ($dosecapikey | ConvertFrom-SecureString)
        }
        Save-Config -cfg $config -path $configPath
    }

    $usevtapi = Get-UseVTApiPreference -configPath $configPath
    # ----- RELOAD CONFIG SO SCRIPT-LEVEL $config IS UPDATED -----
    $config = Load-Config -path $configPath

    # Saving encrypted VT api key in config file
    if ($usevtapi -eq "Y" -and -not $config.virustotalapikey) {
        Write-Host "No Virus Total API key found!" -ForegroundColor Red
        $vtapikey = Read-Host "Enter your Virus Total API Key (Changes will apply from the next IOC submission)"
        $dosecapikey = ConvertTo-SecureString $vtapikey -AsPlainText -Force
        if ($config -and $config.PSObject -and $config.PSObject.Properties.Name -contains 'virustotalapikey') {
            $config.virustotalapikey = $dosecapikey | ConvertFrom-SecureString
        } else {
            if ($null -eq $config -or $config.GetType().Name -ne 'PSCustomObject') {
                # create an empty object but DO NOT overwrite valid config
                $config = [PSCustomObject]@{}
            }
            $config | Add-Member -MemberType NoteProperty -Name 'virustotalapikey' -Value ($dosecapikey | ConvertFrom-SecureString)
        }
        Save-Config -cfg $config -path $configPath
    }

    $usebrow = Get-UseBrowser -configPath $configPath
    # ----- RELOAD CONFIG SO SCRIPT-LEVEL $config IS UPDATED -----
    $config = Load-Config -path $configPath

    # <----Browser, IOC limit editing---->
    $config = $null
    try {
        $raw = Get-Content -Path $configPath -Raw -ErrorAction Stop
        $config = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $config = $null
    }
    $usebrowser   = if ($config.usebrow)      { $config.usebrow }      else { "" }
    $browser      = if ($config.defbrow)      { $config.defbrow }      else { "msedge" }
    $iocLimit     = if ($config.ioclim)       { $config.ioclim }       else { 4 }
    $useurlscan   = if ($config.useurlscan)   { $config.useurlscan }   else { "" }
    $usevtapi     = if ($config.usevtapi)     { $config.usevtapi }     else { "" }

    $supportedBrowsers = @("chrome", "msedge", "firefox", "safari", "opera", "brave")

    # Input IOC from the user (mix of domains, IPs, URLs, hashes)
    $iocInput = Read-Host "`nEnter IOCs"
    # Check if the user input is "e" (case-insensitive)
	if ($iocInput -match '^(?i)e$') {
		Edit-Configuration -browser ([ref]$browser) -iocLimit ([ref]$iocLimit)

		# ---------------- Reload config immediately after editing ----------------
		$config = Load-Config -path $configPath

		# Refresh all runtime variables based on updated config.json
		$usebrowser   = if ($config.usebrow)      { $config.usebrow }      else { "" }
		$browser      = if ($config.defbrow)      { $config.defbrow }      else { "msedge" }
		$iocLimit     = if ($config.ioclim)       { $config.ioclim }       else { 4 }
		$useurlscan   = if ($config.useurlscan)   { $config.useurlscan }   else { "" }
		$usevtapi     = if ($config.usevtapi)     { $config.usevtapi }     else { "" }
		
		Continue
	}

    # Check if the user input is "c" to clear screen
    if ($iocInput -match '^(?i)c$') {
        Write-Host "`nNow You See Me..." -ForegroundColor Green
        Start-Sleep -Seconds 2
        Clear-Host
        Write-Host "`nNow You Won't!" -ForegroundColor Red
        Write-Host ""
        Write-Host ""
        Start-Sleep -Seconds 2
        Clear-Host
        Continue
    }

    # Quit the script if "q" is pressed
    if ($iocInput -match '^(?i)q$') {
        Show-Logo
        Write-Host "`nFly, you fools!" -ForegroundColor DarkYellow
        Write-Host ""
	Start-Sleep -Seconds 2
        break
    }

    # Check if the user input is "i" to show information
    if ($iocInput -match '^(?i)i$') {
        Show-Logo

        Write-Host ""

        Write-Host "Overview: " -ForegroundColor Green
        Show-Animated-Text -text "1) Analysts can submit multiple IOCs (Domain, IP, URL, Hash) at once. IOC type will be auto-validated. Defanged IOCs can also be given."
        Show-Animated-Text -text "2) Maximum of 4 IOCs are recommended to limit excessive resource consumption if you opt for opening results in browser."
        Show-Animated-Text -text "3) The delimiters that can be used between two IOCs are: Space ( ), OR operator ( OR )( or ), and Comma (,)."
        Show-Animated-Text -text "4) The links for results will be displayed in terminal for analysts to copy paste as references."
        Show-Animated-Text -text "5) The executable can be run from anywhere, the config file created needs to be in the same directory."
        Show-Animated-Text -text "6) If you submit Virus Total API Key, you can get many details directly in console. IOCs will be submitted to VT for reanalyzing when the script is run."
        Show-Animated-Text -text "7) If you have URLScan account, you can use the API to get a live screenshot for the URL. You will be prompted to choose if you want to use it or not in the beginning. You can change it from the edit menu by entering e as input."

        Write-Host "`nKnown Issues: " -ForegroundColor Red
        Show-Animated-Text -text "--> When user selects clear screen, it doesn't clear the whole history which can be seen by scrolling up. But it does clear up the window."
        Show-Animated-Text -text "--> Terminal output results can be formatted neatly."
        Continue
    }

    If (-not $iocInput) {
        Write-Host "Enter valid IOCs" -ForegroundColor Red
        Continue
    }

    # Split on commas, spaces, or "OR" (case insensitive), trim whitespace, and filter out "OR and comma" as valid IOCs.
    $iocs = $iocInput -split '(?:\s*,\s*|\s+\bOR\b\s+|\s+)' |
    Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^(,|(?i)OR)$" -and $_.Length -ge 3 } |
    ForEach-Object {
        $_.Trim() `
        -replace 'hxxps', 'https' `
        -replace 'hxxp', 'http' `
        -replace '\[\:\/\/\]', '://' `
        -replace '\[\.\]', '.'
    }

    # Ensure valid IOCs are present
    If (-not $iocs) {
        Write-Host "No valid IOCs found" -ForegroundColor Red
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
    If ($domainIocs) { Lookup-Handler -type "domain" -iocs $domainIocs }
    If ($hashIocs) { Lookup-Handler -type "hash" -iocs $hashIocs }
    If ($urlIocs) { Lookup-Handler -type "url" -iocs $urlIocs }

} While ($true)