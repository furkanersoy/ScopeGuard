@echo off
setlocal
cd /d "%~dp0"

rem Prefer the Python launcher, then fall back to python on PATH.
set "SG_PYTHON=py -3"
%SG_PYTHON% -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >nul 2>&1
if errorlevel 1 set "SG_PYTHON=python"
%SG_PYTHON% -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >nul 2>&1
if errorlevel 1 goto python_required

if not exist ".venv\Scripts\python.exe" (
    echo Setting up ScopeGuard on first launch...
    %SG_PYTHON% -m venv .venv
    if errorlevel 1 goto setup_failed
)

for /f "delims=" %%H in ('".venv\Scripts\python.exe" -c "import hashlib; from pathlib import Path; print(hashlib.sha256(Path(\'pyproject.toml\').read_bytes()).hexdigest())"') do set "SG_PROJECT_HASH=%%H"
if not defined SG_PROJECT_HASH goto setup_failed
set "SG_INSTALLED_HASH="
if exist ".venv\.scopeguard-installed" set /p SG_INSTALLED_HASH=<".venv\.scopeguard-installed"
if not "%SG_PROJECT_HASH%"=="%SG_INSTALLED_HASH%" (
    echo Installing or updating ScopeGuard and its dependencies...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -e .
    if errorlevel 1 goto setup_failed
    > ".venv\.scopeguard-installed" echo %SG_PROJECT_HASH%
)

".venv\Scripts\scopeguard.exe" %*
exit /b %errorlevel%

:python_required
echo ScopeGuard requires Python 3.11 or newer, available as "py -3" or "python".
echo Install Python from https://www.python.org/downloads/ and try again.
pause
exit /b 2

:setup_failed
echo ScopeGuard setup failed. Check your internet connection and Python installation, then run this file again.
pause
exit /b 2
