"""
Tests for schema.py - Pydantic models and SARIF conversion.
"""

import json
from datetime import datetime

import pytest

from claudecode.schema import (
    CodeLocation,
    ScanResults,
    SecurityFinding,
    Severity,
    VulnerabilityCategory,
)


class TestCodeLocation:
    """Tests for CodeLocation model."""

    def test_valid_code_location(self):
        """Test creating a valid CodeLocation."""
        location = CodeLocation(
            file_path="src/auth.py",
            start_line=10,
            end_line=15,
            snippet="def authenticate(user, password):",
        )

        assert location.file_path == "src/auth.py"
        assert location.start_line == 10
        assert location.end_line == 15
        assert location.snippet is not None

    def test_end_line_validation(self):
        """Test that end_line must be >= start_line."""
        with pytest.raises(ValueError):
            CodeLocation(
                file_path="test.py",
                start_line=10,
                end_line=5,  # Invalid: end before start
            )


class TestSecurityFinding:
    """Tests for SecurityFinding model."""

    def test_create_security_finding(self):
        """Test creating a complete SecurityFinding."""
        finding = SecurityFinding(
            id="SEC-001",
            title="SQL Injection Vulnerability",
            description="User input is directly concatenated into SQL query",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.INJECTION,
            cwe_id="CWE-89",
            owasp_id="A03:2021",
            location=CodeLocation(
                file_path="api/db.py", start_line=42, end_line=44
            ),
            remediation="Use parameterized queries or an ORM",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            confidence=0.95,
            is_new=True,
        )

        assert finding.id == "SEC-001"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == 0.95

    def test_to_dict(self):
        """Test converting finding to dictionary."""
        finding = SecurityFinding(
            id="SEC-002",
            title="XSS Vulnerability",
            description="Unescaped user input rendered in HTML",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.XSS,
            location=CodeLocation(file_path="web/views.py", start_line=100, end_line=100),
            remediation="Escape user input before rendering",
            confidence=0.85,
        )

        result = finding.to_dict()
        assert isinstance(result, dict)
        assert result["id"] == "SEC-002"
        assert result["severity"] == "MEDIUM"


class TestScanResults:
    """Tests for ScanResults model."""

    def test_create_scan_results(self):
        """Test creating ScanResults with factory method."""
        findings = [
            SecurityFinding(
                id="SEC-001",
                title="Test Finding",
                description="Test description",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.INJECTION,
                location=CodeLocation(file_path="test.py", start_line=1, end_line=1),
                remediation="Fix it",
                confidence=0.9,
            )
        ]

        results = ScanResults.create(
            repository="owner/repo",
            commit_sha="abc123",
            findings=findings,
            files_scanned=5,
            model_used="claude-sonnet-4",
            scan_duration_seconds=45.2,
            pr_number=123,
        )

        assert results.repository == "owner/repo"
        assert results.pr_number == 123
        assert len(results.findings) == 1
        assert results.files_scanned == 5
        assert "SEC-001" in results.scan_id or results.scan_id  # UUID format

    def test_generate_summary(self):
        """Test summary generation."""
        findings = [
            SecurityFinding(
                id="SEC-001",
                title="Critical Issue",
                description="Test",
                severity=Severity.CRITICAL,
                category=VulnerabilityCategory.INJECTION,
                location=CodeLocation(file_path="test.py", start_line=1, end_line=1),
                remediation="Fix",
                confidence=0.9,
            ),
            SecurityFinding(
                id="SEC-002",
                title="High Issue",
                description="Test",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.XSS,
                location=CodeLocation(file_path="test.py", start_line=2, end_line=2),
                remediation="Fix",
                confidence=0.8,
            ),
        ]

        results = ScanResults.create(
            repository="test/repo",
            commit_sha="def456",
            findings=findings,
            files_scanned=10,
            model_used="claude-sonnet-4",
            scan_duration_seconds=30.0,
        )

        assert "2 security" in results.summary.lower()
        assert "critical" in results.summary.lower()
        assert "high" in results.summary.lower()

    def test_empty_findings_summary(self):
        """Test summary with no findings."""
        results = ScanResults.create(
            repository="test/repo",
            commit_sha="ghi789",
            findings=[],
            files_scanned=10,
            model_used="claude-sonnet-4",
            scan_duration_seconds=15.0,
        )

        assert "no security issues" in results.summary.lower()


class TestSARIFConversion:
    """Tests for SARIF format conversion."""

    def test_to_sarif_basic(self):
        """Test basic SARIF conversion."""
        finding = SecurityFinding(
            id="SEC-001",
            title="SQL Injection",
            description="SQL injection vulnerability found",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.INJECTION,
            cwe_id="CWE-89",
            owasp_id="A03:2021",
            location=CodeLocation(file_path="api/db.py", start_line=10, end_line=12),
            remediation="Use parameterized queries",
            confidence=0.95,
        )

        results = ScanResults.create(
            repository="test/repo",
            commit_sha="abc",
            findings=[finding],
            files_scanned=1,
            model_used="claude-sonnet-4",
            scan_duration_seconds=10.0,
        )

        sarif = results.to_sarif()

        # Validate SARIF structure
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "Claude Code Security Review"
        assert len(run["results"]) == 1
        assert len(run["tool"]["driver"]["rules"]) == 1

        # Validate result
        result = run["results"][0]
        assert result["ruleId"] == "SEC-001"
        assert result["level"] == "error"  # HIGH -> error
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "api/db.py"

    def test_sarif_severity_mapping(self):
        """Test that severity levels map correctly to SARIF."""
        test_cases = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]

        for severity, expected_level in test_cases:
            finding = SecurityFinding(
                id=f"SEC-{severity.value}",
                title="Test",
                description="Test",
                severity=severity,
                category=VulnerabilityCategory.INJECTION,
                location=CodeLocation(file_path="test.py", start_line=1, end_line=1),
                remediation="Fix",
                confidence=0.8,
            )

            results = ScanResults.create(
                repository="test/repo",
                commit_sha="xyz",
                findings=[finding],
                files_scanned=1,
                model_used="claude-sonnet-4",
                scan_duration_seconds=1.0,
            )

            sarif = results.to_sarif()
            assert sarif["runs"][0]["results"][0]["level"] == expected_level

    def test_sarif_with_snippet(self):
        """Test SARIF conversion includes code snippets."""
        finding = SecurityFinding(
            id="SEC-001",
            title="Test",
            description="Test",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.INJECTION,
            location=CodeLocation(
                file_path="test.py",
                start_line=5,
                end_line=5,
                snippet='query = "SELECT * FROM users WHERE id = " + user_input',
            ),
            remediation="Fix",
            confidence=0.8,
        )

        results = ScanResults.create(
            repository="test/repo",
            commit_sha="abc",
            findings=[finding],
            files_scanned=1,
            model_used="claude-sonnet-4",
            scan_duration_seconds=1.0,
        )

        sarif = results.to_sarif()
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        
        assert "snippet" in region
        assert "SELECT *" in region["snippet"]["text"]
