@echo off

REM OIS - OSINT IOC Scanner
REM Author: Suchit Reddi
REM Opens given IP/url/domain in commonly used lookup sites.

echo " .--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--. "
echo "/ .. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \"
echo "\ \/\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ \/ /"
echo " \/ /`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'\/ / "
echo " / /\    /$$$$$$          /$$           /$$                              / /\ "
echo "/ /\ \  /$$__  $$        |__/          | $$                             / /\ \"
echo "\ \/ / | $$  \ $$ /$$$$$$$/$$/$$$$$$$ /$$$$$$                           \ \/ /"
echo " \/ /  | $$  | $$/$$_____| $| $$__  $|_  $$_/                            \/ / "
echo " / /\  | $$  | $|  $$$$$$| $| $$  \ $$ | $$                              / /\ "
echo "/ /\ \ | $$  | $$\____  $| $| $$  | $$ | $$ /$$                         / /\ \"
echo "\ \/ / |  $$$$$$//$$$$$$$| $| $$  | $$ |  $$$$/                         \ \/ /"
echo " \/ /   \______/|_______/|__|__/  |__/  \___/                            \/ / "
echo " / /\   /$$$$$$                                                          / /\ "
echo "/ /\ \ |_  $$_/                                                         / /\ \"
echo "\ \/ /   | $$   /$$$$$$  /$$$$$$$                                       \ \/ /"
echo " \/ /    | $$  /$$__  $$/$$_____/                                        \/ / "
echo " / /\    | $$ | $$  \ $| $$                                              / /\ "
echo "/ /\ \   | $$ | $$  | $| $$                                             / /\ \"
echo "\ \/ /  /$$$$$|  $$$$$$|  $$$$$$$                                       \ \/ /"
echo " \/ /  |______/\______/ \_______/                                        \/ / "
echo " / /\    /$$$$$$                                                         / /\ "
echo "/ /\ \  /$$__  $$                                                       / /\ \"
echo "\ \/ / | $$  \__/ /$$$$$$$ /$$$$$$ /$$$$$$$ /$$$$$$$  /$$$$$$  /$$$$$$  \ \/ /"
echo " \/ /  |  $$$$$$ /$$_____/|____  $| $$__  $| $$__  $$/$$__  $$/$$__  $$  \/ / "
echo " / /\   \____  $| $$       /$$$$$$| $$  \ $| $$  \ $| $$$$$$$| $$  \__/  / /\ "
echo "/ /\ \  /$$  \ $| $$      /$$__  $| $$  | $| $$  | $| $$_____| $$       / /\ \"
echo "\ \/ / |  $$$$$$|  $$$$$$|  $$$$$$| $$  | $| $$  | $|  $$$$$$| $$       \ \/ /"
echo " \/ /   \______/ \_______/\_______|__/  |__|__/  |__/\_______|__/        \/ / "
echo " / /\.--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--./ /\ "
echo "/ /\ \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \/\ \"
echo "\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `' /"
echo " `--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--' "
echo OIS - OSINT IOC Scanner
echo By Suchit Reddi

REM -------------------Script Start-----------------------------------------------

:start

REM <----All round Lookup---->
set ibm="https://exchange.xforce.ibmcloud.com"

REM <----Domain & IP Lookup---->
set vt="https://www.virustotal.com/gui/search"
set talos="https://talosintelligence.com/reputation_center/lookup?search"
set whois="https://www.whois.com/whois"

REM <----Just Domain Lookup---->
set norton="https://sitereview.bluecoat.com/#/lookup-result"
set urlvoid="https://urlvoid.com/scan"

REM <----Just IP Lookup---->
set abip="https://www.abuseipdb.com/check"

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
    echo Invalid number! Select from 1, 2, 3... && goto start
)

REM ------------------Domain Lookup-----------------------------------------------
:domain
echo.
set /p dom="Enter domain (ex:- suchitreddi.github.io): "

start msedge -new-window "%vt%/%dom%" "%norton%/%dom%" "%whois%/%dom%" "%talos%=%dom%" "%ibm%/url/%dom%" "%urlvoid%/%dom%"

echo.
echo Done!
echo.
echo -----------------------------------------------------------------------------
echo.
goto end


REM ----------------------IP Lookup-----------------------------------------------
:ip
echo.
set /p ip_addr="Enter IP address (ex:- 8.8.8.8): "

start msedge -new-window "%vt%/%ip_addr%" "%talos%=%ip_addr%" "%ibm%/ip/%ip_addr%" "%whois%/%ip_addr%" "%abip%/%ip_addr%"

echo.
echo Done!
echo.
echo -----------------------------------------------------------------------------
echo.
goto end


REM ----------------------URL Lookup-----------------------------------------------
:url
echo.
set /p url_addr="Enter URL (ex:- https://suchitreddi.github.io/Work/scripts.html): "
call :EncodeURL "%url_addr%"

start msedge -new-window "%vt%/%enc_url_2%" "%ibm%/url/%enc_url%"

echo.
echo Done!
echo.
echo -----------------------------------------------------------------------------
echo.
goto end

REM -------------------URL Encoding Function--------------------------------------
:EncodeURL
setlocal EnableDelayedExpansion
set "url=%~1"
set "enc_url="
set "enc_url_2="

for /L %%i in (0,1,255) do (
    set "chr=!url:~%%i,1!"
    if "!chr!"=="" goto :breakLoop
    if "!chr!"==":" (
        set "enc_url=!enc_url!%%3A"
        set "enc_url_2=!enc_url_2!%%253A"
    ) else if "!chr!"=="/" (
        set "enc_url=!enc_url!%%2F"
        set "enc_url_2=!enc_url_2!%%252F"
    ) else (
        set "enc_url=!enc_url!!chr!"
        set "enc_url_2=!enc_url_2!!chr!"
    )
)

:breakLoop
endlocal & set "enc_url=%enc_url%" & set "enc_url_2=%enc_url_2%"
goto :eof

:end
set /p another="Do you want to search for another IOC? (y/n) "
echo.
if /i %another%==y (goto start)
if /i %another%==n (echo Happy Hunting! Press any key to exit... && pause>nul && exit)

REM -------------------Script End-------------------------------------------------
