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
exit
cls