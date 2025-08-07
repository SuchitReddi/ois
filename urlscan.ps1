param(
    [string]$url,
    [string]$configPath
)

# Asking for url if no input is given by ois.ps1. Should not happen normally as ois.ps1 won't execute further without valid IOC.
if (-not $url) {
    $url = Read-Host "Input url"
}

if (-not $configPath) {
    throw "Config file not found."
}
$config = Get-Content $configPath | ConvertFrom-Json

if ($config.urlscanapikey -and $config.urlscanapikey -is [string] -and $config.urlscanapikey.Trim().Length -gt 0) {
    try {
        $getsecapikey = $config.urlscanapikey | ConvertTo-SecureString
        $apikey = [System.Net.NetworkCredential]::new("", $getsecapikey).Password
    } catch {
        Write-Host "Failed to decrypt API key in config file." -ForegroundColor Yellow
    }
}

if (-not $apikey) {
    Write-Host "No URLScan API key found!" -ForegroundColor Red
    $apikey = Read-Host "Enter your URLScan API Key (Changes will apply from the next IOC submission)"
    $dosecapikey = ConvertTo-SecureString $apikey -AsPlainText -Force
    if ($config.PSObject.Properties['urlscanapikey']) {
        $config.urlscanapikey = $dosecapikey | ConvertFrom-SecureString
    } else {
        $config | Add-Member -MemberType NoteProperty -Name 'urlscanapikey' -Value ($dosecapikey | ConvertFrom-SecureString)
    }
    $config | ConvertTo-Json | Set-Content $configPath
}

# Use the decrypted $apikey for the API call
$theapikey = @{
    "API-Key" = "$apikey"
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
    $oisoutput = $sendtoapi.result
    $ssurl = "https://urlscan.io/screenshots/$scanuuid.png"
    $statmsg = $sendtoapi.message #Only giving submission successful if successful, but no result otherwise

# Don't add anything other than variables in blocks you will convert to json. If they are not valid, you will get a error.
    @{
        scanuuid = $scanuuid
        oisoutput = $oisoutput
        ssurl = $ssurl
        statusmessage = $statmsg
    } | ConvertTo-Json

} catch {
    # Directly use exception message and details, no Write-Host
    $message = $_.Exception.Message
    $description = $_.Exception.ToString()

    @{
        scanuuid = $null
        oisoutput = $null
        ssurl = $null
        error = $message
        errordesc = $description
        statusmessage = $statmsg
    } | ConvertTo-Json
}