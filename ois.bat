@echo off
REM This tool opens given IOC (Domain/IP/url/hash) in reputed OSINT sites.

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

echo By 5herl0ck
echo.

REM -------------------Script Start-----------------------------------

REM Assign OSINT links to variables.

REM <----Browser, IOC Limit---->
set browser=msedge
set ioc_limit=4
set max_length=1023

REM <----All round---->
set vt=https://www.virustotal.com/gui/search
set ibm=https://exchange.xforce.ibmcloud.com
set talos=https://talosintelligence.com/reputation_center/lookup?search
set kasper=https://opentip.kaspersky.com
set otx=https://otx.alienvault.com/browse/global/pulses?q

REM <----Domain, IP, URL---->
set shodan=https://www.shodan.io/search?query

REM <----Domain, URL---->
set norton=https://sitereview.bluecoat.com/#/lookup-result

REM <----Domain, IP---->
set abip=https://www.abuseipdb.com/check
set whois=https://www.whois.com/whois
set urlscan=https://urlscan.io/domain

REM <----Just Domain---->
set urlvoid=https://urlvoid.com/scan

REM <====Deprecated====>
REM set ggl=https://transparencyreport.google.com/safe-browsing/search?url
REM set talos_h=https://talosintelligence.com/talos_file_reputation?s

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
    echo Invalid number^^! Select from available options... && echo.
)
goto start

:lookup_handler
REM Argument %1 will be used to distinguish between domain, ip, url, or hash
set type=%1
set ioc=
set count=0
set /p ioc="Enter IOCs (max !ioc_limit! IOCs): "
echo. 

REM Check if the IOC input is empty
if "%ioc%"=="" (
    echo Enter valid IOCs. With great IOCs come great results^^! && echo. && set lookup= && goto start
)

REM Calculate the length of the IOC input
set ioc_length=0
for /l %%A in (0,1,1024) do (
    if "!ioc:~%%A,1!"=="" (
        set ioc_length=%%A
        goto :length_checked
    )
)
:length_checked

if %ioc_length% geq %max_length% (
    echo. && echo.
    echo The input exceeds the cmd's maximum string length of 1024 characters. Please separate them if there are multiple IOCs.
    echo.
    endlocal && set ioc= && set lookup= && set count= && goto start
)

REM Replace commas, OR, or with spaces to normalize the input
set ioc=%ioc:,= % && set ioc=%ioc: OR = % && set ioc=%ioc: or = %
set total_iocs=0
REM Count the number of IOCs
FOR %%i IN (%ioc%) DO (
    set /A total_iocs+=1
)

REM Check if the total IOCs exceed the limit
if !total_iocs! gtr !ioc_limit! (
    echo You have entered !total_iocs! IOCs, which exceeds the current limit of !ioc_limit!.
    set /p sure="Press N to cancel, or any key to continue: "
	echo.
    if /I "!sure!"=="n" (
        endlocal && set ioc= && set lookup= && goto start
    )
)

REM Loop through each IOC in the user input
FOR %%i IN (%ioc%) DO (
    REM Increment the counter
    set /A count+=1

    if !count! leq !ioc_limit! (
        if !type!==domain (
            REM ------------------Domain Lookup------------------------------------
            set "domains=!vt!/%%i !norton!/%%i !urlscan!/%%i !whois!/%%i !talos!=%%i !ibm!/url/%%i !abip!/%%i !shodan!=%%i !urlvoid!/%%i"
            start !browser! -new-window !domains!
            REM Display the URLs for the user to copy
            echo IOC: %%i
            echo ------------------------------------------------------------------
            echo %vt%/%%i && echo %norton%/%%i && echo %urlscan%/%%i && echo %whois%/%%i && echo %talos%=%%i && echo %ibm%/url/%%i && echo %abip%/%%i && echo %shodan%=%%i && echo %urlvoid%/%%i
            echo ------------------------------------------------------------------
			echo Useful sites not included in the script:
			echo https://urlscan.io
            echo https://viewdns.info
            echo.
        ) else if !type!==ip (
            REM ----------------------IP Lookup------------------------------------
            set "ips=!vt!/%%i !urlscan!/%%i !whois!/%%i !talos!=%%i !ibm!/url/%%i !abip!/%%i !shodan!=%%i"
            start !browser! -new-window !ips!
            echo IOC: %%i
            echo ------------------------------------------------------------------
            REM for %%A in (!ips!) do echo %%A
            echo %vt%/%%i && echo %urlscan%/%%i && echo %whois%/%%i && echo %talos%=%%i && echo %ibm%/url/%%i && echo %abip%/%%i && echo %shodan%=%%i
            echo ------------------------------------------------------------------
            echo Useful sites not included in the script:
            echo https://viewdns.info
            echo.
        ) else if !type!==url (
            REM ----------------------URL Lookup-----------------------------------
            call :EncodeURL "%%i"
            set "urls=%vt%/!enc_url_2! %norton%/!enc_url_2! %ibm%/url/!enc_url! %talos%=!enc_url!"
            start !browser! -new-window !urls!
            echo IOC: %%i
            echo ------------------------------------------------------------------
            echo %vt%/!enc_url_2! && echo %norton%/!enc_url_2! && echo %ibm%/url/!enc_url! && echo %talos%=!enc_url!
            echo ------------------------------------------------------------------
			echo Useful sites not included in the script:
			echo https://urlscan.io
            echo.
        ) else if !type!==hash (
            REM ----------------------Hash Lookup-----------------------------------
            set "hashes=!vt!/%%i !otx!=%%i !kasper!/%%i/results?tab=lookup !ibm!/malware/%%i"
            start !browser! -new-window !hashes!
            echo IOC: %%i
            echo ------------------------------------------------------------------
            echo %vt%/%%i && echo %otx%=%%i && echo %kasper%/%%i/results?tab=lookup && echo %ibm%/malware/%%i
            echo ------------------------------------------------------------------
            echo.
        )
    ) else (
		echo Sky is the limit... but !ioc_limit! is the limit for now && echo.
    )
)

endlocal && set ioc= && set lookup= && set type=
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