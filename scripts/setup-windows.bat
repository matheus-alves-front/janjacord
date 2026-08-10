@echo off
REM ============================================================
REM  JanjaCord — setup automático para Windows
REM  Roda tudo: Node (se faltar), pnpm, VS Build Tools (se o
REM  módulo nativo precisar), install, build e abre o app.
REM  Uso: duplo clique ou:  scripts\setup-windows.bat
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0.."

echo ============================================
echo   JanjaCord — setup Windows (automático)
echo ============================================

REM ---------- 1. Node ----------
where node >nul 2>&1
if errorlevel 1 (
  echo [1/5] Node nao encontrado — instalando via winget (LTS)...
  winget install -e --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements >nul 2>&1
  if errorlevel 1 (
    echo  Falha ao instalar Node. Baixe em https://nodejs.org e rode de novo.
    pause
    exit /b 1
  )
  echo  Node instalado — REABRA este prompt (para atualizar o PATH) e rode de novo.
  pause
  exit /b 1
)
for /f "delims=" %%v in ('node --version') do set NODEVER=%%v
echo [1/5] Node OK: %NODEVER%

REM ---------- 2. pnpm ----------
where pnpm >nul 2>&1
if errorlevel 1 (
  echo [2/5] Instalando pnpm...
  call npm install -g pnpm@10 >nul 2>&1
  if errorlevel 1 (
    echo  Falha ao instalar pnpm.
    pause
    exit /b 1
  )
)
for /f "delims=" %%p in ('pnpm --version') do set PNPMVER=%%p
echo [2/5] pnpm OK: %PNPMVER%

REM ---------- 3. VS Build Tools (só se o módulo nativo falhar depois) ----------
echo [3/5] Verificando compilador C++ (VS Build Tools)...
set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
set HASVS=0
if exist "%VSWHERE%" (
  "%VSWHERE%" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 >nul 2>&1
  if not errorlevel 1 set HASVS=1
)
if "%HASVS%"=="0" (
  echo  VS Build Tools ausente — instalando (pode demorar alguns minutos)...
  winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-source-agreements --accept-package-agreements --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" >nul 2>&1
  if errorlevel 1 (
    echo  Nao consegui instalar automaticamente. Se o build falhar, instale manualmente:
    echo  https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
    echo  (carga: Desktop development with C++)
  )
)

REM ---------- 4. pnpm install ----------
echo [4/5] pnpm install (pode demorar)...
call pnpm install --no-frozen-lockfile
if errorlevel 1 (
  echo  Falha no install. Tentando rebuild dos modulos nativos...
  call pnpm rebuild better-sqlite3-multiple-ciphers node-datachannel esbuild
  call pnpm install --no-frozen-lockfile
  if errorlevel 1 (
    echo  Ainda falhou. Me mande o conteudo do log gerado em:  install.log
    call pnpm install --no-frozen-lockfile > install.log 2>&1
    pause
    exit /b 1
  )
)

REM ---------- 5. build ----------
echo [5/5] pnpm build (compilando)...
call pnpm build
if errorlevel 1 (
  echo  Falha no build. Me mande o log.
  call pnpm build > build.log 2>&1
  pause
  exit /b 1
)

echo ============================================
echo   PRONTO! Abrindo o JanjaCord...
echo ============================================
cd apps\desktop
call node_modules\.bin\electron.cmd .
pause
