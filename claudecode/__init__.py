"""
ClaudeCode - AI-Powered PR Security Audit Tool

A standalone security audit tool that uses Claude Code for comprehensive
security analysis of GitHub pull requests.
"""

__version__ = "1.0.0"
__author__ = "Anthropic Security Team"

# Import main components for easier access
from .github_action_audit import (  # type: ignore
    GitHubActionClient,
    ClaudeCliRunner,
    LLMClientRunner,
    ModernReporter,
    main
)

__all__ = [
    "GitHubActionClient",
    "ClaudeCliRunner",
    "LLMClientRunner",
    "ModernReporter",
    "main"
]
