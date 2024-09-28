@echo off

REM OIS - OSINT IOC Scanner
REM Author: Suchit Reddi
REM Opens given IP/url/domain in commonly used lookup sites.

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

REM -------------------Script Start-----------------------------------------------

:start

REM <----All round Lookup---->
set ibm=https://exchange.xforce.ibmcloud.com
set talos=https://talosintelligence.com/reputation_center/lookup?search
set shodan=https://www.shodan.io/search?query

REM <----Domain & IP Lookup---->
set vt=https://www.virustotal.com/gui/search
set whois=https://www.whois.com/whois

REM <----Just Domain Lookup---->
set norton=https://sitereview.bluecoat.com/#/lookup-result
set urlvoid=https://urlvoid.com/scan
set ggl=https://transparencyreport.google.com/safe-browsing/search?url
set urlscan=https://urlscan.com/domain

REM <----Just IP Lookup---->
set abip=https://www.abuseipdb.com/check

echo.
echo Type of Lookup:
echo [1] Domain
echo [2] IP
echo [3] URL
set /p lookup="Select respective number: "

if "%lookup%"=="1" (
    call :domain
) else if "%lookup%"=="2" (
    call :ip
) else if "%lookup%"=="3" (
    call :url
) else (
    echo Invalid number! Select from 1, 2, 3... && echo. && goto start
)

REM ------------------Domain Lookup-----------------------------------------------
:domain
echo.
set /p dom="Enter domain (ex:- suchitreddi.github.io): "

start msedge -new-window "%vt%/%dom%" "%urlscan%/%dom%" "%norton%/%dom%" "%ggl%=%dom%" "%whois%/%dom%" "%talos%=%dom%" "%ibm%/url/%dom%" "%urlvoid%/%dom%" "%shodan%=%dom%"
echo. && echo Select and copy links using Ctrl+Shift+V && echo.

echo ------------------------------------------------------------------
echo.
echo %vt%/%dom%  && echo %urlscan%/%dom%  && echo %norton%/%dom%  && echo %ggl%=%dom%  && echo %whois%/%dom%  && echo %talos%=%dom%  && echo %ibm%/url/%dom%  && echo %urlvoid%/%dom%  && echo %shodan%=%dom%

echo.
echo ------------------------------------------------------------------
echo.
goto end

REM ----------------------IP Lookup-----------------------------------------------
:ip
echo.
set /p ip_addr="Enter IP address (ex:- 8.8.8.8): "

start msedge -new-window "%vt%/%ip_addr%" "%talos%=%ip_addr%" "%ibm%/ip/%ip_addr%" "%whois%/%ip_addr%" "%abip%/%ip_addr%" "%shodan%=%ip_addr%"
echo. && echo Select and copy links using Ctrl+Shift+V && echo.

echo ------------------------------------------------------------------
echo.
echo %vt%/%ip_addr% && echo %whois%/%ip_addr% && echo %ibm%/url/%ip_addr%  && echo %shodan%=%ip_addr% && echo %talos%=%ip_addr% && echo %abip%/%ip_addr%

echo.
echo ------------------------------------------------------------------
echo.
goto end

REM ----------------------URL Lookup-----------------------------------------------
:url
echo.
set /p url_addr="Enter URL (ex:- https://suchitreddi.github.io/Work/scripts.html): "
call :EncodeURL "%url_addr%"

start msedge -new-window "%vt%/%enc_url_2%" "%ggl%=%enc_url%" "%ibm%/url/%enc_url%" "%shodan%=%enc_url%" "%talos%=%enc_url%"
echo. && echo Select and copy links using Ctrl+Shift+V && echo.

echo ------------------------------------------------------------------
echo.
echo %vt%/%enc_url_2% && echo %ggl%=%enc_url% && echo %ibm%/url/%enc_url%  && echo %shodan%=%enc_url% && echo %talos%=%enc_url%

echo.
echo ------------------------------------------------------------------
echo.
goto end

REM -------------------URL Encoding Function--------------------------------------
:EncodeURL
setlocal EnableDelayedExpansion
set "url=%~1"
set "enc_url="
set "enc_url_2="

REM Loop through the URL characters for single encoding
for /L %%i in (0,1,255) do (
    set "chr=!url:~%%i,1!"
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
REM Perform the second pass (double encoding)
REM Double encode by replacing % with %25 in enc_url
set "enc_url_2=!enc_url:%%=%%25!"

endlocal & set "enc_url=%enc_url%" & set "enc_url_2=%enc_url_2%"
goto :eof

:end
set /p another="Do you want to search for another IOC? (y/n) "
echo.
if /i %another%==y (
    goto start
) else if /i %another%==n (
    echo Happy Hunting! Press any key to exit... && pause>nul && exit
) else (
    echo Invalid option! Select y or n... && echo. && goto end
)
REM -------------------Script End---------------------------------------