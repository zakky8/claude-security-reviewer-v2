"""
Secrets detection module for identifying hardcoded credentials in code.
Performs a fast regex-based pre-scan before sending files to Claude.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from claudecode.schema import CodeLocation, SecurityFinding, Severity, VulnerabilityCategory


class SecretsScanner:
    """Fast regex-based scanner for detecting hardcoded secrets."""

    # Regex patterns for different types of secrets
    PATTERNS = {
        "aws_access_key": (
            r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "AWS Access Key ID",
        ),
        "aws_secret_key": (r"aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "AWS Secret Access Key"),
        "github_token": (r"gh[pousr]_[A-Za-z0-9_]{36,255}", "GitHub Personal Access Token"),
        "github_fine_grained": (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "GitHub Fine-Grained Token"),
        "stripe_api_key": (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live API Key"),
        "stripe_restricted": (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key"),
        "gcp_service_account": (r'"type":\s*"service_account"', "GCP Service Account JSON"),
        "private_key_rsa": (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
        "private_key_ec": (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key"),
        "private_key_openssh": (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key"),
        "jwt_token": (r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "JWT Token"),
        "slack_token": (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}", "Slack Token"),
        "slack_webhook": (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "Slack Webhook"),
        "mailgun_api_key": (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key"),
        "twilio_api_key": (r"SK[0-9a-fA-F]{32}", "Twilio API Key"),
        "sendgrid_api_key": (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key"),
        "heroku_api_key": (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "Heroku API Key"),
        "facebook_access_token": (r"EAACEdEose0cBA[0-9A-Za-z]+", "Facebook Access Token"),
        "google_api_key": (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
        "google_oauth": (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID"),
        "password_in_url": (
            r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}[\"'\s]",
            "Password in Connection String",
        ),
        "generic_api_key": (r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "Generic API Key"),
        "generic_secret": (r"(?i)secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "Generic Secret"),
        "high_entropy_string": (
            r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]",
            "High Entropy String (possible secret)",
        ),
    }

    # Patterns to ignore (common false positives)
    IGNORE_PATTERNS = [
        r"^[A-Z_]+$",  # Environment variable names
        r"^test",  # Test values
        r"^example",  # Example values
        r"^dummy",  # Dummy values
        r"^placeholder",  # Placeholder values
        r"^your",  # Template placeholders
        r"^TODO",  # TODO comments
        r"^FIXME",  # FIXME comments
    ]

    def __init__(self) -> None:
        """Initialize the secrets scanner with compiled regex patterns."""
        self.compiled_patterns: Dict[str, Tuple[re.Pattern[str], str]] = {
            name: (re.compile(pattern), desc) for name, (pattern, desc) in self.PATTERNS.items()
        }

    def scan_file(self, file_path: str, content: str) -> List[SecurityFinding]:
        """
        Scan a file for hardcoded secrets.

        Args:
            file_path: Path to the file being scanned
            content: File content to scan

        Returns:
            List of security findings for detected secrets
        """
        findings: List[SecurityFinding] = []
        lines = content.split("\n")

        for pattern_name, (pattern, description) in self.compiled_patterns.items():
            for line_num, line in enumerate(lines, start=1):
                # Skip comments in common languages
                if self._is_comment_line(line):
                    continue

                matches = pattern.finditer(line)
                for match in matches:
                    matched_text = match.group(0)

                    # Skip if it matches ignore patterns
                    if self._should_ignore(matched_text):
                        continue

                    # Redact the secret value (show only first 4 and last 4 chars)
                    redacted = self._redact_secret(matched_text)

                    finding_id = self._generate_finding_id(file_path, line_num, pattern_name)

                    finding = SecurityFinding(
                        id=finding_id,
                        title=f"Hardcoded {description} Detected",
                        description=f"Found what appears to be a hardcoded {description.lower()} in the code. "
                        f"Hardcoded secrets should never be committed to version control. "
                        f"Detected value (redacted): {redacted}",
                        severity=Severity.CRITICAL,
                        category=VulnerabilityCategory.SECRETS,
                        cwe_id="CWE-798",
                        owasp_id="A07:2021",
                        location=CodeLocation(
                            file_path=file_path,
                            start_line=line_num,
                            end_line=line_num,
                            snippet=self._get_snippet(lines, line_num),
                        ),
                        remediation=f"Remove the hardcoded {description.lower()} and use environment variables or a "
                        f"secrets management system instead. If this secret has been committed, "
                        f"rotate it immediately as it should be considered compromised.",
                        references=[
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                            "https://cwe.mitre.org/data/definitions/798.html",
                        ],
                        confidence=self._calculate_confidence(pattern_name, matched_text),
                        is_new=True,
                    )

                    findings.append(finding)

        return findings

    def scan_diff(self, diff_content: str) -> List[SecurityFinding]:
        """
        Scan a diff for secrets in added lines only.

        Args:
            diff_content: Git diff content

        Returns:
            List of security findings for detected secrets
        """
        findings: List[SecurityFinding] = []
        current_file: Optional[str] = None
        line_num = 0

        for line in diff_content.split("\n"):
            # Track which file we're in
            if line.startswith("diff --git"):
                # Extract filename
                match = re.search(r"b/(.+)$", line)
                if match:
                    current_file = match.group(1)
                line_num = 0
            elif line.startswith("@@"):
                # Extract line number from hunk header
                match = re.search(r"\+(\d+)", line)
                if match:
                    line_num = int(match.group(1))
            elif line.startswith("+") and not line.startswith("+++") and current_file:
                # This is an added line
                added_content = line[1:]  # Remove the '+' prefix

                # Scan this line for secrets
                file_findings = self.scan_file(current_file, added_content)

                # Update line numbers
                for finding in file_findings:
                    finding.location.start_line = line_num
                    finding.location.end_line = line_num
                    findings.append(finding)

                line_num += 1
            elif not line.startswith("-") and current_file:
                # Context or unchanged line
                line_num += 1

        return findings

    def _is_comment_line(self, line: str) -> bool:
        """Check if a line is a comment in common languages."""
        stripped = line.strip()
        return (
            stripped.startswith("#")  # Python, Ruby, Shell
            or stripped.startswith("//")  # Java, JavaScript, C++, Go
            or stripped.startswith("/*")  # Multi-line comment start
            or stripped.startswith("*")  # Multi-line comment middle
            or stripped.startswith("*/")  # Multi-line comment end
            or stripped.startswith("<!--")  # HTML/XML comment
        )

    def _should_ignore(self, text: str) -> bool:
        """Check if text matches any ignore patterns."""
        for pattern in self.IGNORE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _redact_secret(self, secret: str) -> str:
        """Redact a secret, showing only first and last 4 characters."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def _get_snippet(self, lines: List[str], line_num: int, context: int = 1) -> str:
        """Get a code snippet with context lines."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = lines[start:end]
        return "\n".join(snippet_lines)

    def _generate_finding_id(self, file_path: str, line_num: int, pattern_name: str) -> str:
        """Generate a stable unique ID for a finding."""
        content = f"{file_path}:{line_num}:{pattern_name}"
        hash_digest = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"SEC-SECRET-{hash_digest.upper()}"

    def _calculate_confidence(self, pattern_name: str, matched_text: str) -> float:
        """Calculate confidence score based on pattern type and characteristics."""
        # Base confidence by pattern type
        high_confidence_patterns = {
            "aws_access_key",
            "github_token",
            "stripe_api_key",
            "private_key_rsa",
            "private_key_ec",
        }

        if pattern_name in high_confidence_patterns:
            base_confidence = 0.95
        elif pattern_name.startswith("generic_") or pattern_name == "high_entropy_string":
            base_confidence = 0.6
        else:
            base_confidence = 0.85

        # Adjust based on entropy
        if len(matched_text) > 50:
            base_confidence = min(1.0, base_confidence + 0.05)

        return base_confidence
