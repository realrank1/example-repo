@echo off
cls
netsh int ip reset
cls
netsh winsock reset
cls
ipconfig /release
cls
ipconfig /renew
cls
taskkill /f /im "F Drop internet.exe"
cls
cd %systemroot%\system32
call :IsAdmin
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "*SpeedDuplex" /t REG_SZ /d "0" /f
cls
exit
cls
