@echo off
>nul chcp 65001
title Re-applying Tweaks for gooseISO - he3als

:start
:: Credit to server.bat for the logo
echo  [38;5;220m                           ___ ____   ___  [0m
echo  [38;5;220m __ _  ___   ___  ___  ___^|_ _/ ___^| / _ \  [0m[38;5;220m  _[0m
echo  [38;5;220m/ _` ^|/ _ \ / _ \/ __^|/ _ \^| ^|\___ \^| ^| ^| ^| [0m[38;5;208m^>[38[38;5;220m^([97m.[0m[38;5;220m^)__[0m
echo [38;5;220m^| (_^| ^| (_) ^| (_) \__ \  __/^| ^| ___) ^| ^|_^| ^| [0m[38;5;220m ^(___/[0m 
echo  [38;5;220m\__, ^|\___/ \___/^|___/\___^|___^|____/ \___/ [0m
echo  [38;5;220m^|___/            [0m
echo]
echo [38;5;220mThis script re-applies all the post-install tweaks in case of a Windows Update or other changes.[0m
echo [38;5;220m────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[0m
echo It is highly recommended to have no pending updates and Windows Defender disabled.
echo Your computer will be restarted after this.
pause
echo]
goto postinstall

:postinstall
echo Please wait, this may take a moment.
echo Do not close this window or the other window!
set success=
C:\Windows\GooseModules\nsudo.exe -U:T -P:E -Wait C:\Windows\GooseModules\goose-config.bat /thetweaks
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
exit