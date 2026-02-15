#!/bin/bash
echo "🗑️  Uninstalling Claude Code Security Reviewer Local Environment..."

# 1. Remove Virtual Environment
if [ -d "venv" ]; then
    echo "🔴 Removing venv..."
    rm -rf venv
else
    echo "⚪ venv not found."
fi

# 2. Cleanup __pycache__
echo "🧹 Cleaning up cache..."
find . -type d -name "__pycache__" -exec rm -rf {} +
rm -rf .pytest_cache

echo ""
echo "✅ Uninstallation Complete."
echo "The 'venv' and temporary cache files have been removed."
echo "To re-install, run './install.sh'."
