@Echo Off
Title 10MB
cd %systemroot%\system32
call :IsAdmin

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "*SpeedDuplex" /t REG_SZ /d "1" /f
Exit