#!/bin/bash
# Claude Code Security Reviewer v2.0 - One-Click Installer
# Supports: Linux, macOS, and Windows (Git Bash/WSL)

echo "🚀 Starting Claude Code Security Reviewer Installation..."

# 1. Check if running in current directory
if [ -f "server.py" ]; then
    echo "📂 Found server.py in current directory. Skipping clone..."
else
    # Clone the repository
    if [ ! -d "claude-code-security-review-v2" ]; then
        echo "📂 Cloning repository..."
        git clone https://github.com/anthropics/claude-code-security-review.git
        cd claude-code-security-review || exit
    else
        echo "📂 Repository already exists, jumping in..."
        cd claude-code-security-review || exit
    fi
fi

# 2. Setup Virtual Environment
if [ ! -d "venv" ]; then
    echo "🐍 Creating virtual environment..."
    python3 -m venv venv || python -m venv venv
fi

# 3. Activate and Install
echo "📦 Installing dependencies (this may take a minute)..."
source venv/bin/activate || source venv/Scripts/activate
pip install --upgrade pip
pip install -r claudecode/requirements.txt

echo ""
echo "✅ Installation Complete!"
echo "--------------------------------------------------"
echo "To start the Web Dashboard:"
echo "   source venv/bin/activate && python server.py"
echo ""
echo "To use as an Agentic Subsystem (API):"
echo "   nohup python server.py > server.log 2>&1 &"
echo "--------------------------------------------------"
