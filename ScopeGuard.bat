@echo off
setlocal
cd /d "%~dp0"

set "SG_PYTHON=py -3"
%SG_PYTHON% --version >nul 2>&1
if errorlevel 1 (
    echo ScopeGuard requires Python 3.11 or newer.
    echo Install Python from https://www.python.org/downloads/ and try again.
    pause
    exit /b 2
)
%SG_PYTHON% -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >nul 2>&1
if errorlevel 1 (
    echo ScopeGuard requires Python 3.11 or newer.
    pause
    exit /b 2
)

if not exist ".venv\Scripts\python.exe" (
    echo Setting up ScopeGuard on first launch...
    %SG_PYTHON% -m venv .venv
    if errorlevel 1 goto setup_failed
)

if not exist ".venv\.scopeguard-installed" (
    echo Installing ScopeGuard and its dependencies...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -e "%~dp0"
    if errorlevel 1 goto setup_failed
    type nul > ".venv\.scopeguard-installed"
)

".venv\Scripts\scopeguard.exe" %*
exit /b %errorlevel%

:setup_failed
echo ScopeGuard setup failed. Check your internet connection and Python installation, then run this file again.
pause
exit /b 2
