@echo off
echo [*] Starting Claude Code Security Reviewer Installation (Windows)...

:: 1. Check if running in current directory
if exist "server.py" (
    echo [.] Found server.py in current directory. Skipping clone...
) else (
    :: Clone repository if not ensuring
    if not exist "claude-security-reviewer-v2" (
        echo [+] Cloning repository...
        git clone https://github.com/zakky8/claude-security-reviewer-v2.git
        cd claude-security-reviewer-v2
    ) else (
        cd claude-security-reviewer-v2
    )
)

:: 2. Setup Virtual Environment
if not exist "venv" (
    echo [+] Creating virtual environment...
    python -m venv venv
)

:: 3. Install dependencies
echo [*] Installing dependencies...
call venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo [OK] Installation Complete!
echo --------------------------------------------------
echo To start the Web Dashboard:
echo    venv\Scripts\activate ^&^& python server.py
echo.
echo To use as an Agentic Subsystem (API):
echo    start /B python server.py
echo --------------------------------------------------
pause
