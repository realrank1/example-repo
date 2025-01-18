@echo off
cls
powercfg -change standby-timeout-ac 0
cls
powercfg -change monitor-timeout-ac 0
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
cls
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9001000000000000" /f
cls
netsh interface tcp set global autotuninglevel=disabled

cls

exit