@echo off
REM Abre o JanjaCord (conta principal / máquina A).
REM Uso:  scripts\run.bat
cd /d "%~dp0..\apps\desktop"
call node_modules\.bin\electron.cmd .
