from setuptools import setup, find_packages

setup(
    name="claude-code-security-review",
    version="2.0.0",
    description="AI-powered security review tool using Claude/LLMs",
    author="Anthropic Security Team",
    packages=find_packages(),
    install_requires=[
        "requests",
        "anthropic",
        "openai",
        "tenacity",
    ],
    entry_points={
        "console_scripts": [
            "claude-security-review=claudecode.github_action_audit:main",
        ],
    },
)
