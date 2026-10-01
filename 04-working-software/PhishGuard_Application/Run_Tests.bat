@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title PhishGuard - Test Suite

echo ========================================================
echo               PhishGuard Test Suite
echo ========================================================
echo.

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

echo ERROR: Python 3.11 or later was not found.
if not defined PHISHGUARD_TEST_RUNNER pause
exit /b 1

:python_found
if not exist ".venv\Scripts\python.exe" (
    echo Creating local test environment...
    %PYTHON_CMD% -m venv ".venv"
    if errorlevel 1 goto failed
)
set "VENV_PY=%CD%\.venv\Scripts\python.exe"

rem Never let test collection initialize or resume the active application instance.
set "PHISHGUARD_TEST_MODE=true"
set "BACKGROUND_DISPATCH_ENABLED=false"
set "ENABLE_SMTP=false"
set "PRODUCTION_MODE=false"
set "TRUST_PROXY=false"
if not defined PHISHGUARD_TEST_RUNNER (
    set "PHISHGUARD_DIRECT_TEST_ROOT=%TEMP%\PhishGuardTests-%RANDOM%-%RANDOM%"
    mkdir "%PHISHGUARD_DIRECT_TEST_ROOT%" >nul 2>&1
    set "DATABASE=%PHISHGUARD_DIRECT_TEST_ROOT%\runner.sqlite"
    set "OUTBOX_DIR=%PHISHGUARD_DIRECT_TEST_ROOT%\outbox"
    set "MEDIA_DIR=%PHISHGUARD_DIRECT_TEST_ROOT%\media"
    set "DOMAIN_ALLOWLIST_FILE=%PHISHGUARD_DIRECT_TEST_ROOT%\allowed_domains.txt"
    set "AUDIT_LOG_FILE=%PHISHGUARD_DIRECT_TEST_ROOT%\audit.log"
    set "SMTP_SETTINGS_FILE=%PHISHGUARD_DIRECT_TEST_ROOT%\smtp_settings.json"
    set "BASE_URL=http://localhost"
    set "COOKIE_SECURE=false"
    set "FORCE_ALLOW_ALL_DOMAINS=false"
)

"%VENV_PY%" -c "import flask, pytest" >nul 2>&1
if errorlevel 1 (
    echo Installing test requirements...
    "%VENV_PY%" -m pip install -r requirements.txt
    if errorlevel 1 goto failed
)

echo Running tests...
"%VENV_PY%" -m pytest -q
set "RESULT=%ERRORLEVEL%"
if defined PHISHGUARD_DIRECT_TEST_ROOT rmdir /s /q "%PHISHGUARD_DIRECT_TEST_ROOT%" >nul 2>&1
echo.
if "%RESULT%"=="0" (
    echo PASS: All automated tests completed successfully.
) else (
    echo FAIL: One or more tests failed. Exit code %RESULT%.
)
echo.
if not defined PHISHGUARD_TEST_RUNNER pause
exit /b %RESULT%

:failed
echo.
echo ERROR: Test environment setup failed.
echo Check Python and Internet connectivity, then try again.
if not defined PHISHGUARD_TEST_RUNNER pause
exit /b 1
