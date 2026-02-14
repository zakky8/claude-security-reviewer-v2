@echo off
echo 🚀 Starting Claude Code Security Reviewer Installation (Windows)...

:: 1. Clone repository
if not exist "claude-code-security-review-v2" (
    echo 📂 Cloning repository...
    git clone https://github.com/anthropics/claude-code-security-review.git
    cd claude-code-security-review
) else (
    cd claude-code-security-review
)

:: 2. Setup Virtual Environment
if not exist "venv" (
    echo 🐍 Creating virtual environment...
    python -m venv venv
)

:: 3. Install dependencies
echo 📦 Installing dependencies...
call venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r claudecode\requirements.txt

echo.
echo ✅ Installation Complete!
echo --------------------------------------------------
echo To start the Web Dashboard:
echo    venv\Scripts\activate ^&^& python server.py
echo.
echo To use as an Agentic Subsystem (API):
echo    start /B python server.py
echo --------------------------------------------------
pause
