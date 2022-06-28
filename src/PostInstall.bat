@echo off
>nul chcp 65001
title Post Installation Script for gooseISO - he3als

:start
:: Credit to server.bat for the logo
echo  [38;5;220m                           ___ ____   ___  [0m
echo  [38;5;220m __ _  ___   ___  ___  ___^|_ _/ ___^| / _ \  [0m[38;5;220m  _[0m
echo  [38;5;220m/ _` ^|/ _ \ / _ \/ __^|/ _ \^| ^|\___ \^| ^| ^| ^| [0m[38;5;208m^>[38[38;5;220m^([97m.[0m[38;5;220m^)__[0m
echo [38;5;220m^| (_^| ^| (_) ^| (_) \__ \  __/^| ^| ___) ^| ^|_^| ^| [0m[38;5;220m ^(___/[0m 
echo  [38;5;220m\__, ^|\___/ \___/^|___/\___^|___^|____/ \___/ [0m
echo  [38;5;220m^|___/            [0m
echo]
echo [38;5;220mThis is the post installation script for gooseISO, a fork of Atlas.[0m
echo [38;5;220m────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[0m
echo The post install script is about to start.
echo If needed, change your language and regional settings right now.
pause
echo]
echo You also should ensure that tamper protection is disabled, although it already should be.
echo Waiting 2 seconds and then opening the Security app...
timeout /t 2 /nobreak > nul
start "" "windowsdefender:"
pause
goto postinstall

:postinstall
echo Please wait, this may take a moment.
echo Do not close this window or the other window!
set success=
C:\Windows\GooseModules\nsudo.exe -U:T -P:E -Wait C:\Windows\GooseModules\goose-config.bat /postinstall
:: Read from success.txt
set /p success=<C:\Users\Public\success.txt
:: Check if script finished
if %success% equ true (
	goto success
	) else (
	:: If not, restart script
	echo.
	goto failure
)

:failure
echo POST INSTALL SCRIPT CLOSED!
echo The script was 
echo Launching script again...
echo.
goto start

:success
del /f /q "C:\Users\Public\success.txt"
shutdown /r /f /t 10 /c "Required reboot to apply changes to Windows"
DEL "%~f0"
exit