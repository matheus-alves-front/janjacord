@echo off
REM Abre uma SEGUNDA conta do JanjaCord no mesmo PC (teste de 2 contas).
REM Uso:  scripts\run-conta2.bat
cd /d "%~dp0..\apps\desktop"
set JC_USERDATA_DIR=%TEMP%\janjacord-conta2
call node_modules\.bin\electron.cmd .
