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

".venv\Scripts\python.exe" -c "import hashlib; from pathlib import Path; print(hashlib.sha256(Path('pyproject.toml').read_bytes()).hexdigest())" > ".venv\.scopeguard-current"
if errorlevel 1 goto setup_failed
fc /b ".venv\.scopeguard-installed" ".venv\.scopeguard-current" >nul 2>&1
if errorlevel 1 (
    echo Installing or updating ScopeGuard and its dependencies...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -e .
    if errorlevel 1 goto setup_failed
    move /y ".venv\.scopeguard-current" ".venv\.scopeguard-installed" >nul
) else (
    del /q ".venv\.scopeguard-current" >nul 2>&1
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
