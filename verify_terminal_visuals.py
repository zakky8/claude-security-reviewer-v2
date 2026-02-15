#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Standard package-level import
from claudecode import ModernReporter  # type: ignore

def verify_visuals():
    os.environ['FORCE_COLOR'] = 'true'
    
    # 1. Splash
    ModernReporter.print_splash()
    
    # 2. Statuses
    ModernReporter.print_status("CONFIG", "Target: zakky8/claude-code-security-review-v2 #42")
    ModernReporter.print_status("SYSTEM", "Guarding your code...", "\033[94m")
    ModernReporter.print_status("SOURCE", "Fetching PR metadata and diff...", "\033[92m")
    ModernReporter.print_status("ENGINE", "Running Hybrid Security Scan...", "\033[96m")
    
    # 3. Findings
    mock_findings = [
        {
            "severity": "CRITICAL",
            "file": "src/auth/login.py",
            "category": "sql_injection",
            "description": "Unsanitized user input in query"
        },
        {
            "severity": "HIGH",
            "file": "src/config/settings.py",
            "category": "hardcoded_secrets",
            "description": "AWS_SECRET_KEY found in plain text"
        },
        {
            "severity": "MEDIUM",
            "file": "src/utils/crypto.py",
            "category": "weak_crypto",
            "description": "Using MD5 for password hashing"
        }
    ]
    
    ModernReporter.print_findings_table(mock_findings)
    ModernReporter.print_verdict(mock_findings)

if __name__ == "__main__":
    verify_visuals()
