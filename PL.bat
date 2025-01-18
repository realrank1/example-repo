@echo off
netsh interface set interface "Ethernet" disable
cls
netsh interface set interface "Wifi" disable
cls
timeout /t 2 /nobreak
cls
netsh interface set interface "Ethernet" enable
cls
netsh interface set interface "Wifi" enable
cls
exit