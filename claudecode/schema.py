"""
Structured schema definitions for security findings using Pydantic v2.
This module defines the data models for security scan results, findings, and SARIF conversion.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Security finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityCategory(str, Enum):
    """Categories of security vulnerabilities."""

    INJECTION = "Injection"
    AUTHENTICATION = "Authentication & Authorization"
    DATA_EXPOSURE = "Data Exposure"
    CRYPTOGRAPHY = "Cryptographic Issues"
    INPUT_VALIDATION = "Input Validation"
    BUSINESS_LOGIC = "Business Logic"
    CONFIG = "Configuration Security"
    SUPPLY_CHAIN = "Supply Chain"
    CODE_EXECUTION = "Code Execution"
    XSS = "Cross-Site Scripting"
    SSRF = "Server-Side Request Forgery"
    DESERIALIZATION = "Insecure Deserialization"
    PATH_TRAVERSAL = "Path Traversal"
    SECRETS = "Hardcoded Secrets"


class CodeLocation(BaseModel):
    """Location of code with a security finding."""

    file_path: str = Field(description="Path to the file containing the issue")
    start_line: int = Field(description="Starting line number", ge=1)
    end_line: int = Field(description="Ending line number", ge=1)
    snippet: Optional[str] = Field(None, description="Code snippet showing the issue")

    @field_validator("end_line")
    @classmethod
    def end_line_after_start(cls, v: int, info: Any) -> int:
        """Validate that end_line >= start_line."""
        if "start_line" in info.data and v < info.data["start_line"]:
            raise ValueError("end_line must be >= start_line")
        return v


class SecurityFinding(BaseModel):
    """A single security finding from the scan."""

    id: str = Field(description="Unique stable finding ID, e.g. SEC-001")
    title: str = Field(description="Brief title describing the finding")
    description: str = Field(description="Detailed description of the security issue")
    severity: Severity = Field(description="Severity level of the finding")
    category: VulnerabilityCategory = Field(description="Category of vulnerability")
    cwe_id: Optional[str] = Field(None, description="CWE-XXX identifier")
    owasp_id: Optional[str] = Field(None, description="OWASP Top 10 reference, e.g. A03:2021")
    location: CodeLocation = Field(description="Location of the vulnerable code")
    remediation: str = Field(description="Guidance on how to fix the issue")
    references: List[str] = Field(default_factory=list, description="External reference URLs")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    is_new: bool = Field(True, description="True if introduced in this diff, False if pre-existing")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return self.model_dump()


class ScanResults(BaseModel):
    """Complete results from a security scan."""

    scan_id: str = Field(description="Unique identifier for this scan")
    repository: str = Field(description="Repository name in format owner/repo")
    pr_number: Optional[int] = Field(None, description="Pull request number if applicable")
    commit_sha: str = Field(description="Commit SHA that was scanned")
    scan_timestamp: str = Field(description="ISO 8601 timestamp of scan")
    findings: List[SecurityFinding] = Field(default_factory=list, description="All security findings")
    files_scanned: int = Field(description="Number of files scanned", ge=0)
    model_used: str = Field(description="Claude model used for the scan")
    scan_duration_seconds: float = Field(description="Total scan duration", ge=0.0)
    summary: str = Field(description="Human-readable summary of scan results")

    @classmethod
    def create(
        cls,
        repository: str,
        commit_sha: str,
        findings: List[SecurityFinding],
        files_scanned: int,
        model_used: str,
        scan_duration_seconds: float,
        pr_number: Optional[int] = None,
    ) -> "ScanResults":
        """Factory method to create scan results with auto-generated values."""
        import uuid

        return cls(
            scan_id=str(uuid.uuid4()),
            repository=repository,
            pr_number=pr_number,
            commit_sha=commit_sha,
            scan_timestamp=datetime.utcnow().isoformat() + "Z",
            findings=findings,
            files_scanned=files_scanned,
            model_used=model_used,
            scan_duration_seconds=scan_duration_seconds,
            summary=cls._generate_summary(findings),
        )

    @staticmethod
    def _generate_summary(findings: List[SecurityFinding]) -> str:
        """Generate a human-readable summary of findings."""
        if not findings:
            return "No security issues found."

        severity_counts = {
            "CRITICAL": len([f for f in findings if f.severity == Severity.CRITICAL]),
            "HIGH": len([f for f in findings if f.severity == Severity.HIGH]),
            "MEDIUM": len([f for f in findings if f.severity == Severity.MEDIUM]),
            "LOW": len([f for f in findings if f.severity == Severity.LOW]),
            "INFO": len([f for f in findings if f.severity == Severity.INFO]),
        }

        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts[sev]
            if count > 0:
                parts.append(f"{count} {sev}")

        return f"Found {len(findings)} security {'issue' if len(findings) == 1 else 'issues'}: {', '.join(parts)}"

    def to_sarif(self) -> Dict[str, Any]:
        """Convert scan results to SARIF 2.1.0 format for GitHub Code Scanning."""
        rules = {}
        results = []

        for finding in self.findings:
            rule_id = finding.id
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": finding.remediation, "markdown": finding.remediation},
                    "properties": {
                        "tags": [finding.category.value],
                        "precision": self._confidence_to_precision(finding.confidence),
                    },
                }

                if finding.cwe_id:
                    rules[rule_id]["properties"]["cwe"] = [finding.cwe_id]
                if finding.owasp_id:
                    rules[rule_id]["properties"]["owasp"] = finding.owasp_id

            result = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.location.file_path},
                            "region": {
                                "startLine": finding.location.start_line,
                                "endLine": finding.location.end_line,
                            },
                        }
                    }
                ],
            }

            if finding.location.snippet:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": finding.location.snippet
                }

            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Claude Code Security Review",
                            "version": "2.0",
                            "informationUri": "https://github.com/anthropics/claude-code-security-review",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "scanId": self.scan_id,
                        "repository": self.repository,
                        "commitSha": self.commit_sha,
                        "scanTimestamp": self.scan_timestamp,
                        "modelUsed": self.model_used,
                        "filesScanned": self.files_scanned,
                    },
                }
            ],
        }

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")

    @staticmethod
    def _confidence_to_precision(confidence: float) -> str:
        """Convert confidence score to SARIF precision."""
        if confidence >= 0.9:
            return "very-high"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return self.model_dump()
