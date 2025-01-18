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
exit
cls
