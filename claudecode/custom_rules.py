"""
Custom rule engine for user-defined security patterns.
Allows projects to define custom security rules in YAML format.
"""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from claudecode.schema import CodeLocation, SecurityFinding, Severity, VulnerabilityCategory


class CustomRulesEngine:
    """Engine for applying custom user-defined security rules."""

    DEFAULT_RULES_PATH = ".github/security-rules.yml"

    def __init__(self, rules_file: Optional[str] = None) -> None:
        """
        Initialize custom rules engine.

        Args:
            rules_file: Path to custom rules YAML file (defaults to .github/security-rules.yml)
        """
        self.rules_file = rules_file or self.DEFAULT_RULES_PATH
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self) -> None:
        """Load custom rules from YAML file."""
        rules_path = Path(self.rules_file)

        if not rules_path.exists():
            # No custom rules file, that's okay
            return

        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "rules" not in data:
                return

            for rule in data["rules"]:
                self._validate_rule(rule)
                # Compile regex pattern for performance
                rule["compiled_pattern"] = re.compile(rule["pattern"])
                self.rules.append(rule)

        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in custom rules file: {e}")
        except Exception as e:
            raise ValueError(f"Error loading custom rules: {e}")

    def _validate_rule(self, rule: Dict[str, Any]) -> None:
        """
        Validate that a rule has all required fields.

        Args:
            rule: Rule dictionary to validate

        Raises:
            ValueError: If rule is invalid
        """
        required_fields = ["id", "description", "pattern", "severity", "remediation"]

        for field in required_fields:
            if field not in rule:
                raise ValueError(f"Custom rule missing required field: {field}")

        # Validate severity
        severity_str = rule["severity"].upper()
        if severity_str not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            raise ValueError(f"Invalid severity in rule {rule['id']}: {rule['severity']}")

        # Validate pattern is a valid regex
        try:
            re.compile(rule["pattern"])
        except re.error as e:
            raise ValueError(f"Invalid regex pattern in rule {rule['id']}: {e}")

    def scan_file(self, file_path: str, content: str) -> List[SecurityFinding]:
        """
        Scan a file against custom rules.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            List of security findings matching custom rules
        """
        if not self.rules:
            return []

        findings: List[SecurityFinding] = []

        for rule in self.rules:
            # Check if file matches the glob pattern
            if not self._file_matches_glob(file_path, rule.get("file_glob", "*")):
                continue

            # Scan file content
            rule_findings = self._apply_rule(rule, file_path, content)
            findings.extend(rule_findings)

        return findings

    def _file_matches_glob(self, file_path: str, glob_pattern: str) -> bool:
        """
        Check if file matches a glob pattern.

        Args:
            file_path: File path to check
            glob_pattern: Glob pattern (can be comma-separated list)

        Returns:
            True if file matches any pattern
        """
        patterns = [p.strip() for p in glob_pattern.split(",")]

        for pattern in patterns:
            # Simple glob matching - * matches anything
            if pattern == "*":
                return True

            # Convert glob to regex
            regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")

            if re.search(regex_pattern + "$", file_path):
                return True

        return False

    def _apply_rule(
        self, rule: Dict[str, Any], file_path: str, content: str
    ) -> List[SecurityFinding]:
        """
        Apply a single rule to file content.

        Args:
            rule: Rule to apply
            file_path: Path to the file
            content: File content

        Returns:
            List of findings for this rule
        """
        findings: List[SecurityFinding] = []
        lines = content.split("\n")

        pattern = rule["compiled_pattern"]

        for line_num, line in enumerate(lines, start=1):
            matches = pattern.finditer(line)

            for match in matches:
                finding_id = self._generate_finding_id(file_path, line_num, rule["id"])

                # Determine category from rule or use default
                category = self._get_category(rule)

                finding = SecurityFinding(
                    id=finding_id,
                    title=rule.get("title", rule["description"]),
                    description=rule["description"],
                    severity=Severity[rule["severity"].upper()],
                    category=category,
                    cwe_id=rule.get("cwe_id"),
                    owasp_id=rule.get("owasp_id"),
                    location=CodeLocation(
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        snippet=line.strip(),
                    ),
                    remediation=rule["remediation"],
                    references=rule.get("references", []),
                    confidence=rule.get("confidence", 0.8),
                    is_new=True,
                )

                findings.append(finding)

        return findings

    def _get_category(self, rule: Dict[str, Any]) -> VulnerabilityCategory:
        """
        Determine vulnerability category from rule.

        Args:
            rule: Rule dictionary

        Returns:
            VulnerabilityCategory enum value
        """
        category_str = rule.get("category", "").upper().replace(" ", "_")

        # Try to match to known categories
        for cat in VulnerabilityCategory:
            if cat.name == category_str:
                return cat

        # Default category based on severity
        if rule["severity"].upper() in ["CRITICAL", "HIGH"]:
            return VulnerabilityCategory.CODE_EXECUTION
        else:
            return VulnerabilityCategory.CONFIG

    def _generate_finding_id(self, file_path: str, line_num: int, rule_id: str) -> str:
        """Generate a stable unique ID for a finding."""
        content = f"{file_path}:{line_num}:{rule_id}"
        hash_digest = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"SEC-CUSTOM-{hash_digest.upper()}"

    def get_rules_summary(self) -> Dict[str, Any]:
        """
        Get summary of loaded custom rules.

        Returns:
            Dictionary with rules statistics
        """
        if not self.rules:
            return {"loaded": False, "count": 0}

        severity_counts = {}
        for rule in self.rules:
            severity = rule["severity"].upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "loaded": True,
            "count": len(self.rules),
            "file": self.rules_file,
            "severity_distribution": severity_counts,
        }
