@echo off

REM OIS - OSINT IOC Scanner
REM Author: Suchit Reddi
REM Opens given IP/url/domain/hash in commonly used lookup sites.

echo   /$$$$$$          /$$           /$$                            
echo  /$$__  $$        ^|__/          ^| $$                            
echo ^| $$  \ $$ /$$$$$$$/$$/$$$$$$$ /$$$$$$                          
echo ^| $$  ^| $$/$$_____^| $^| $$__  $^|_  $$_/                          
echo ^| $$  ^| $^|  $$$$$$^| $^| $$  \ $$ ^| $$                            
echo ^| $$  ^| $$\____  $^| $^| $$  ^| $$ ^| $$ /$$                        
echo ^|  $$$$$$//$$$$$$$^| $^| $$  ^| $$ ^|  $$$$/                        
echo  \______/^|_______/^|__^|__/  ^|__/  \___/                          
echo  /$$$$$$                                                        
echo ^|_  $$_/                                                        
echo   ^| $$   /$$$$$$  /$$$$$$$                                      
echo   ^| $$  /$$__  $$/$$_____/                                      
echo   ^| $$ ^| $$  \ $^| $$                                           
echo  /$$$$$^|  $$$$$$^|  $$$$$$$                                      
echo ^|______/\______/ \_______/                                      
echo   /$$$$$$                                                       
echo  /$$__  $$                                                      
echo ^| $$  \__/ /$$$$$$$ /$$$$$$ /$$$$$$$ /$$$$$$$  /$$$$$$  /$$$$$$ 
echo ^|  $$$$$$ /$$_____/^|____  $^| $$__  $^| $$__  $$/$$__  $$/$$__  $$
echo  \____  $^| $$       /$$$$$$^| $$  \ $^| $$  \ $^| $$$$$$$^| $$  \__/
echo  /$$  \ $^| $$      /$$__  $^| $$  ^| $^| $$  ^| $^| $$_____^| $$      
echo ^|  $$$$$$^|  $$$$$$^|  $$$$$$^| $$  ^| $^| $$  ^| $^|  $$$$$$^| $$      
echo  \______/ \_______/\_______^|__/  ^|__^|__/  ^|__/\_______^|__/     

echo By Suchit Reddi
echo.
REM -------------------Script Start-----------------------------------------------

REM <----All round Lookup---->
set vt=https://www.virustotal.com/gui/search
set ibm=https://exchange.xforce.ibmcloud.com
set talos=https://talosintelligence.com/reputation_center/lookup?search
set talos_h=https://talosintelligence.com/talos_file_reputation?s
set kasper=https://opentip.kaspersky.com
set otx=https://otx.alienvault.com/browse/global/pulses?q

REM <----Domain, IP, URL---->
set shodan=https://www.shodan.io/search?query

REM <----Domain, URL---->
set norton=https://sitereview.bluecoat.com/#/lookup-result
set ggl=https://transparencyreport.google.com/safe-browsing/search?url

REM <----Domain, IP---->
set abip=https://www.abuseipdb.com/check
set whois=https://www.whois.com/whois
set urlscan=https://urlscan.io/domain

REM <----Just Domain---->
set urlvoid=https://urlvoid.com/scan

:start
setlocal enabledelayedexpansion

echo [1] Domain
echo [2] IP
echo [3] URL
echo [4] Hash
set /p lookup="Select respective number: "

if "%lookup%"=="1" (
    call :lookup_handler domain
) else if "%lookup%"=="2" (
    call :lookup_handler ip
) else if "%lookup%"=="3" (
    call :lookup_handler url
) else if "%lookup%"=="4" (
    call :lookup_handler hash
) else (
    echo Invalid number! Select from 1 to 4... && echo. && goto start
)
goto start

:lookup_handler
REM Argument %1 will be used to distinguish between domain, ip, url, or hash
set type=%1
set /p ioc="Enter IOCs (max 3): "
echo. 

REM Replace commas, OR, or with spaces to normalize the input
set ioc=%ioc:,= % && set ioc=%ioc: OR = % && set ioc=%ioc: or = %
set count=0

REM Loop through each IOC in the user input
FOR %%i IN (%ioc%) DO (
    REM Increment the counter
    set /A count+=1

    if !count! leq 3 (
        if !type!==domain (
            REM ------------------Domain Lookup------------------------------------
            set "domains=!vt!/%%i !otx!=%%i !kasper!/%%i/?tab=lookup !urlscan!/%%i !norton!/%%i !ggl!=%%i !whois!/%%i !talos!=%%i !ibm!/url/%%i !abip!/%%i !urlvoid!/%%i !shodan!=%%i"

            start msedge -new-window !domains!

            REM Display the URLs for the user to copy
            echo IOC: %%i
            echo ------------------------------------------------------------------
            echo %vt%/%%i && echo %otx%=%%i && echo %kasper%/%%i/?tab=lookup && echo %urlscan%/%%i && echo %norton%/%%i && echo %ggl%=%%i && echo %whois%/%%i && echo %talos%=%%i && echo %ibm%/url/%%i && echo %abip%/%%i && echo %urlvoid%/%%i && echo %shodan%=%%i
            echo ------------------------------------------------------------------
            echo.
        ) else if !type!==ip (
            REM ----------------------IP Lookup------------------------------------
            set "ips=!vt!/%%i !otx!=%%i !kasper!/%%i/?tab=lookup !urlscan!/%%i !norton!/%%i !ggl!=%%i !whois!/%%i !talos!=%%i !ibm!/url/%%i !abip!/%%i !shodan!=%%i"

            start msedge -new-window !ips!

            echo IOC: %%i
            echo ------------------------------------------------------------------
            echo %vt%/%%i && echo %otx%=%%i && echo %kasper%/%%i/?tab=lookup && echo %urlscan%/%%i && echo %norton%/%%i && echo %ggl%=%%i && echo %whois%/%%i && echo %talos%=%%i && echo %ibm%/url/%%i && echo %abip%/%%i && echo %shodan%=%%i
            echo ------------------------------------------------------------------
            echo.
        ) else if !type!==url (
            REM ----------------------URL Lookup-----------------------------------
            call :EncodeURL %%i
            set "urls=%vt%/!enc_url_2! %otx%=!enc_url! %kasper%/!enc_url!/?tab=lookup %norton%/!enc_url_2! %ggl%=!enc_url! %ibm%/url/!enc_url! %shodan%=!enc_url! %talos%=!enc_url!"

            start msedge -new-window !urls!

            echo IOC: %%i
            echo ------------------------------------------------------------------
            echo %vt%/!enc_url_2! && echo %otx%=!enc_url! && echo %kasper%/!enc_url!/?tab=lookup && echo %norton%/!enc_url_2! && echo %ggl%=!enc_url! && echo %ibm%/url/!enc_url! && echo %shodan%=!enc_url! && echo %talos%=!enc_url!
            echo ------------------------------------------------------------------
            echo.
        ) else if !type!==hash (
            REM ----------------------Hash Lookup-----------------------------------
            set "hashes=!vt!/%%i !otx!=%%i !kasper!/%%i/results?tab=lookup !ibm!/malware/%%i !talos_h!=%%i"

            start msedge -new-window !hashes!

            echo IOC: %%i
            echo ------------------------------------------------------------------
            echo %vt%/%%i && echo %otx%=%%i && echo %kasper%/%%i/results?tab=lookup && echo %ibm%/malware/%%i && echo %talos_h%=%%i
            echo ------------------------------------------------------------------
            echo.
        )
    ) else (
        echo Sky is the limit... but 3 is the limit for now && echo.
    )
)
goto start
REM -------------------Script End---------------------------------------

REM -------------------URL Encoding Function----------------------------
:EncodeURL
setlocal enabledelayedexpansion
set "url=%~1"
set "enc_url="
set "enc_url_2="

REM Loop through the URL characters for single encoding
for /L %%j in (0,1,255) do (
    set "chr=!url:~%%j,1!"
    if "!chr!"=="" goto :breakLoop

    REM Encode special characters
    if "!chr!"==":" (
        set "enc_url=!enc_url!%%3A"
    ) else if "!chr!"=="/" (
        set "enc_url=!enc_url!%%2F"
    ) else if "!chr!"=="&" (
        set "enc_url=!enc_url!%%26"
    ) else if "!chr!"=="+" (
        set "enc_url=!enc_url!%%2B"
    ) else if "!chr!"==" " (
        set "enc_url=!enc_url!%%20"
    ) else if "!chr!"=="#" (
        set "enc_url=!enc_url!%%23"
    ) else if "!chr!"=="?" (
        set "enc_url=!enc_url!%%3F"
    ) else if "!chr!"=="=" (
        set "enc_url=!enc_url!%%3D"
    ) else if "!chr!"=="@" (
        set "enc_url=!enc_url!%%40"
    ) else if "!chr!"=="$" (
        set "enc_url=!enc_url!%%24"
    ) else if "!chr!"=="%" (
        set "enc_url=!enc_url!%%25"
    ) else (
        set "enc_url=!enc_url!!chr!"
    )
)

:breakLoop
REM Double encode by replacing % with %25 in enc_url
set "enc_url_2=!enc_url:%%=%%25!"
endlocal & set "enc_url=%enc_url%" & set "enc_url_2=%enc_url_2%"
goto :eof