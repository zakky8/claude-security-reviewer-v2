# Claude Security Reviewer Installer for Windows
$ErrorActionPreference = 'Stop'

Write-Host "`n🚀 Claude Security Reviewer v3.0 - Installer" -ForegroundColor Blue
Write-Host "--------------------------------------------"

$installDir = "C:\claude-security"
if (!(Test-Path $installDir)) {
    Write-Host "📂 Creating installation directory: $installDir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $installDir | Out-Null
}

Set-Location $installDir

Write-Host "📂 Cloning latest version..." -ForegroundColor Cyan
if (Test-Path ".git") {
    git pull
} else {
    git clone https://github.com/zakky8/claude-code-security-reviewer-v2.git .
}

Write-Host "🐍 Setting up Virtual Environment..." -ForegroundColor Cyan
if (!(Test-Path "venv")) {
    python -m venv venv
}

Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
& ".\venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\venv\Scripts\pip.exe" install -r requirements.txt

Write-Host "`n✅ SUCCESS: Claude Security Reviewer is installed!" -ForegroundColor Green
Write-Host "--------------------------------------------"
Write-Host "To start the Web Dashboard anytime, run:" -ForegroundColor Yellow
Write-Host "cd $installDir; .\venv\Scripts\python.exe server.py" -ForegroundColor White
Write-Host "--------------------------------------------`n"

# Optional: Add to PATH or create a simple shortcut command
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    Write-Host "💡 Note: You can add '$installDir' to your PATH to run 'claude-security' anywhere." -ForegroundColor Gray
}

# Start it now?
$run = Read-Host "Would you like to start the server now? (y/n)"
if ($run -eq 'y') {
    & ".\venv\Scripts\python.exe" server.py
}
