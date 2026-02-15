@echo off
echo 🗑️  Uninstalling Claude Code Security Reviewer Local Environment...

:: 1. Remove Virtual Environment
if exist "venv" (
    echo 🔴 Removing venv...
    rmdir /s /q venv
) else (
    echo ⚪ venv not found.
)

:: 2. Cleanup __pycache__
echo 🧹 Cleaning up cache...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d"
if exist ".pytest_cache" rmdir /s /q ".pytest_cache"

echo.
echo ✅ Uninstallation Complete.
echo The 'venv' and temporary cache files have been removed.
echo To re-install, run 'install.bat'.
pause
