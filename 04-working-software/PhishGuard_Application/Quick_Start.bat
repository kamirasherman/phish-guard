@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Phishing Awareness Trainer - Quick Start

set "APP_HOST=127.0.0.1"
set "APP_PORT="
set "APP_URL="

cls
echo ========================================================
echo          Phishing Awareness Trainer Quick Start
echo ========================================================
echo.

rem The complete project must be extracted from the ZIP first.
if not exist "app.py" goto missing_files
if not exist "schema.sql" goto missing_files
if not exist "requirements.txt" goto missing_files

rem Locate a Python installation.
where py >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=py"
    goto python_found
)
where python >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=python"
    goto python_found
)

echo ERROR: Python was not found.
echo Install Python 3.11 or later from python.org and select
echo        "Add python.exe to PATH" during installation.
echo.
pause
exit /b 1

:python_found
if not exist ".venv\Scripts\python.exe" (
    echo Creating the local Python environment...
    %PYTHON_CMD% -m venv ".venv"
    if errorlevel 1 goto venv_error
)

set "VENV_PY=%CD%\.venv\Scripts\python.exe"

rem Select an unused local port so an older copy cannot intercept the browser.
for /f %%P in ('powershell.exe -NoProfile -Command "$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); $listener.Start(); $port=$listener.LocalEndpoint.Port; $listener.Stop(); Write-Output $port"') do set "APP_PORT=%%P"
if not defined APP_PORT (
    echo ERROR: Could not select a free local port.
    pause
    exit /b 1
)
set "APP_URL=http://%APP_HOST%:%APP_PORT%"

rem Install the project requirements when Flask is unavailable.
"%VENV_PY%" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installing application requirements...
    "%VENV_PY%" -m pip install -r "requirements.txt"
    if errorlevel 1 goto install_error
)

rem Install the Windows-compatible production server if needed.
"%VENV_PY%" -c "import waitress" >nul 2>&1
if errorlevel 1 (
    echo Installing the Waitress application server...
    "%VENV_PY%" -m pip install "waitress>=3.0,<4"
    if errorlevel 1 goto install_error
)

rem Keep a stable session secret for this extracted copy.
if not exist "instance" mkdir "instance"
if not exist "instance\quickstart_secret.txt" (
    "%VENV_PY%" -c "import secrets, pathlib; pathlib.Path(r'instance\quickstart_secret.txt').write_text(secrets.token_hex(32), encoding='utf-8')"
)
set /p SECRET_KEY=<"instance\quickstart_secret.txt"

rem Safe local demonstration defaults. The desktop launcher always uses the
rem selected free local port so generated training links match this instance.
if not defined ADMIN_USERNAME set "ADMIN_USERNAME=admin"
if not defined ADMIN_PASSWORD set "ADMIN_PASSWORD=training-demo-only"
set "BASE_URL=%APP_URL%"
if not defined COOKIE_SECURE set "COOKIE_SECURE=false"
if not defined ENABLE_SMTP set "ENABLE_SMTP=false"
if not defined SMTP_PROVIDER set "SMTP_PROVIDER=google_workspace"
if not defined SMTP_HOST set "SMTP_HOST=smtp.gmail.com"
if not defined SMTP_PORT set "SMTP_PORT=587"
if not defined SMTP_ENCRYPTION set "SMTP_ENCRYPTION=starttls"

rem Preview mode begins with all-domain recipient entry. After an Administrator
rem saves a specific client-domain allowlist, that file persists across restarts.
set "FORCE_ALLOW_ALL_DOMAINS=false"
set "BUILD_LABEL=Landing Integrated + RBAC + Audit + SMTP + Default Training Domain + Uncapped Video Upload + PB-21 + Training Quiz + Persistent Dispatch + HTTPS 2026.09.05"

rem Open the application after the local server has had time to start.
start "" powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process '%APP_URL%'"

echo.
echo Application address: %APP_URL%
echo Administrator username: %ADMIN_USERNAME%
echo Administrator password: %ADMIN_PASSWORD%
echo Build: Landing Integrated + RBAC + Audit + SMTP + Default Training Domain + Uncapped Video Upload + PB-21 + Training Quiz + Persistent Dispatch + HTTPS 2026.09.05
echo SMTP setup: sign in, then choose SMTP settings
echo Audit log: instance\audit.log
echo Use only addresses you are authorized to test.
echo.
echo Keep this window open while using the application.
echo Press CTRL+C to stop the server.
echo ========================================================
echo.

"%VENV_PY%" -m waitress --listen=%APP_HOST%:%APP_PORT% --max-request-body-size=9223372036854775807 app:app
set "SERVER_EXIT=%ERRORLEVEL%"

echo.
if not "%SERVER_EXIT%"=="0" (
    echo The server stopped with exit code %SERVER_EXIT%.
    echo A common cause is another application already using port %APP_PORT%.
    pause
)
exit /b %SERVER_EXIT%

:missing_files
echo ERROR: Required application files were not found.
echo.
echo Extract the entire ZIP before running Quick_Start.bat.
echo Do not launch the batch file or app.py from inside the ZIP.
echo The folder must contain app.py, schema.sql, and requirements.txt.
echo.
pause
exit /b 1

:venv_error
echo.
echo ERROR: The Python virtual environment could not be created.
echo Verify that Python is installed correctly, then try again.
echo.
pause
exit /b 1

:install_error
echo.
echo ERROR: Required Python packages could not be installed.
echo Check your internet connection and try again.
echo.
pause
exit /b 1
