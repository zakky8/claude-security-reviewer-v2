"""
Infrastructure-as-Code (IaC) security scanner.
Detects security issues in Terraform, Dockerfile, Kubernetes YAML, and GitHub Actions workflows.
"""

import hashlib
import re
from typing import Dict, List

import yaml

from claudecode.schema import CodeLocation, SecurityFinding, Severity, VulnerabilityCategory


class IaCScanner:
    """Scanner for Infrastructure-as-Code security issues."""

    def __init__(self) -> None:
        """Initialize IaC scanner with rule patterns."""
        self.terraform_rules = self._init_terraform_rules()
        self.dockerfile_rules = self._init_dockerfile_rules()
        self.k8s_rules = self._init_k8s_rules()
        self.gha_rules = self._init_gha_rules()

    def scan_file(self, file_path: str, content: str) -> List[SecurityFinding]:
        """
        Scan an IaC file for security issues.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            List of security findings
        """
        if file_path.endswith(".tf"):
            return self._scan_terraform(file_path, content)
        elif "Dockerfile" in file_path or file_path.endswith(".dockerfile"):
            return self._scan_dockerfile(file_path, content)
        elif file_path.endswith((".yaml", ".yml")) and self._is_k8s_file(content):
            return self._scan_kubernetes(file_path, content)
        elif file_path.startswith(".github/workflows/") and file_path.endswith((".yaml", ".yml")):
            return self._scan_github_actions(file_path, content)
        else:
            return []

    def _init_terraform_rules(self) -> List[Dict]:
        """Initialize Terraform security rules."""
        return [
            {
                "id": "tf-public-s3",
                "pattern": r'acl\s*=\s*"public-read',
                "title": "Public S3 Bucket",
                "description": "S3 bucket is configured with public-read ACL, making it publicly accessible.",
                "severity": Severity.HIGH,
                "cwe": "CWE-732",
                "remediation": "Remove public ACL and use bucket policies with explicit permissions instead.",
            },
            {
                "id": "tf-unencrypted-s3",
                "pattern": r"resource\s+\"aws_s3_bucket\"(?:(?!server_side_encryption).)*?}",
                "title": "Unencrypted S3 Bucket",
                "description": "S3 bucket does not have server-side encryption enabled.",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-311",
                "remediation": "Enable server-side encryption with aws_s3_bucket_server_side_encryption_configuration.",
            },
            {
                "id": "tf-open-sg",
                "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
                "title": "Security Group Open to World",
                "description": "Security group rule allows access from any IP address (0.0.0.0/0).",
                "severity": Severity.HIGH,
                "cwe": "CWE-284",
                "remediation": "Restrict CIDR blocks to specific IP ranges or use security group references.",
            },
            {
                "id": "tf-wildcard-principal",
                "pattern": r'"Principal"\s*:\s*"?\*"?',
                "title": "Wildcard Principal in IAM Policy",
                "description": "IAM policy uses wildcard (*) for Principal, potentially granting excessive permissions.",
                "severity": Severity.HIGH,
                "cwe": "CWE-285",
                "remediation": "Specify explicit principals instead of using wildcards.",
            },
        ]

    def _init_dockerfile_rules(self) -> List[Dict]:
        """Initialize Dockerfile security rules."""
        return [
            {
                "id": "docker-root-user",
                "pattern": r"^(?!.*USER\s+(?!root)).*FROM",
                "title": "Container Running as Root",
                "description": "Container does not specify a non-root USER, will run as root by default.",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-250",
                "remediation": "Add 'USER <non-root-user>' directive before the ENTRYPOINT/CMD.",
            },
            {
                "id": "docker-add-url",
                "pattern": r"^ADD\s+https?://",
                "title": "ADD with URL",
                "description": "Using ADD with URLs is discouraged as it doesn't verify content and can't use cache.",
                "severity": Severity.LOW,
                "cwe": "CWE-494",
                "remediation": "Use RUN with curl/wget instead for better control and caching.",
            },
            {
                "id": "docker-no-check-cert",
                "pattern": r"--no-check-certificate",
                "title": "Certificate Verification Disabled",
                "description": "Certificate verification is disabled, making the container vulnerable to MITM attacks.",
                "severity": Severity.HIGH,
                "cwe": "CWE-295",
                "remediation": "Remove --no-check-certificate flag and properly configure CA certificates.",
            },
            {
                "id": "docker-env-secrets",
                "pattern": r"^ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)=",
                "title": "Secrets in ENV",
                "description": "Sensitive values appear to be stored in ENV variables, which are visible in image history.",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-798",
                "remediation": "Use Docker secrets or mount secrets at runtime instead of baking them into the image.",
            },
        ]

    def _init_k8s_rules(self) -> List[Dict]:
        """Initialize Kubernetes security rules."""
        return [
            {
                "id": "k8s-privileged",
                "pattern": r"privileged:\s*true",
                "title": "Privileged Container",
                "description": "Container is configured to run in privileged mode, granting full access to host.",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-250",
                "remediation": "Remove privileged: true or add specific capabilities instead.",
            },
            {
                "id": "k8s-host-network",
                "pattern": r"hostNetwork:\s*true",
                "title": "Host Network Access",
                "description": "Pod has access to host network namespace, bypassing network policies.",
                "severity": Severity.HIGH,
                "cwe": "CWE-250",
                "remediation": "Remove hostNetwork: true unless absolutely necessary.",
            },
            {
                "id": "k8s-no-limits",
                "pattern": r"kind:\s*(?:Pod|Deployment)(?:(?!resources:).)*?(?:(?!limits:).)*?$",
                "title": "No Resource Limits",
                "description": "Container does not have CPU/memory limits, risking resource exhaustion.",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-770",
                "remediation": "Add resources.limits for cpu and memory.",
            },
            {
                "id": "k8s-writable-root",
                "pattern": r"readOnlyRootFilesystem:\s*false",
                "title": "Writable Root Filesystem",
                "description": "Container filesystem is writable, increasing attack surface.",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-732",
                "remediation": "Set readOnlyRootFilesystem: true and use volumes for writable directories.",
            },
        ]

    def _init_gha_rules(self) -> List[Dict]:
        """Initialize GitHub Actions security rules."""
        return [
            {
                "id": "gha-pull-request-target",
                "pattern": r"on:\s*\n\s*pull_request_target:",
                "title": "Dangerous pull_request_target Trigger",
                "description": "pull_request_target runs in the context of the base branch with write access to secrets.",
                "severity": Severity.HIGH,
                "cwe": "CWE-269",
                "remediation": "Use pull_request trigger instead, or carefully validate PR content before execution.",
            },
            {
                "id": "gha-script-injection",
                "pattern": r"\$\{\{\s*github\.event\.(issue|pull_request|comment)",
                "title": "Potential Script Injection",
                "description": "User-controlled input from github.event is used in inline scripts without sanitization.",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-94",
                "remediation": "Pass user input as environment variables, not inline in run: commands.",
            },
            {
                "id": "gha-write-all",
                "pattern": r"permissions:\s*\n\s*.*:\s*write-all",
                "title": "Overly Permissive Token",
                "description": "Workflow has write-all permissions, granting excessive access.",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-250",
                "remediation": "Use principle of least privilege, specify only required permissions.",
            },
        ]

    def _scan_terraform(self, file_path: str, content: str) -> List[SecurityFinding]:
        """Scan Terraform file for security issues."""
        findings: List[SecurityFinding] = []
        lines = content.split("\n")

        for rule in self.terraform_rules:
            for line_num, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    finding_id = self._generate_finding_id(file_path, line_num, rule["id"])

                    finding = SecurityFinding(
                        id=finding_id,
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        category=VulnerabilityCategory.CONFIG,
                        cwe_id=rule["cwe"],
                        owasp_id="A05:2021",
                        location=CodeLocation(file_path=file_path, start_line=line_num, end_line=line_num, snippet=line),
                        remediation=rule["remediation"],
                        references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                        confidence=0.85,
                        is_new=True,
                    )
                    findings.append(finding)

        return findings

    def _scan_dockerfile(self, file_path: str, content: str) -> List[SecurityFinding]:
        """Scan Dockerfile for security issues."""
        findings: List[SecurityFinding] = []
        lines = content.split("\n")

        for rule in self.dockerfile_rules:
            for line_num, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    finding_id = self._generate_finding_id(file_path, line_num, rule["id"])

                    finding = SecurityFinding(
                        id=finding_id,
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        category=VulnerabilityCategory.CONFIG,
                        cwe_id=rule["cwe"],
                        owasp_id="A05:2021",
                        location=CodeLocation(file_path=file_path, start_line=line_num, end_line=line_num, snippet=line),
                        remediation=rule["remediation"],
                        references=["https://docs.docker.com/develop/dev-best-practices/"],
                        confidence=0.85,
                        is_new=True,
                    )
                    findings.append(finding)

        return findings

    def _scan_kubernetes(self, file_path: str, content: str) -> List[SecurityFinding]:
        """Scan Kubernetes YAML for security issues."""
        findings: List[SecurityFinding] = []
        lines = content.split("\n")

        for rule in self.k8s_rules:
            for line_num, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line):
                    finding_id = self._generate_finding_id(file_path, line_num, rule["id"])

                    finding = SecurityFinding(
                        id=finding_id,
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        category=VulnerabilityCategory.CONFIG,
                        cwe_id=rule["cwe"],
                        owasp_id="A05:2021",
                        location=CodeLocation(file_path=file_path, start_line=line_num, end_line=line_num, snippet=line),
                        remediation=rule["remediation"],
                        references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
                        confidence=0.85,
                        is_new=True,
                    )
                    findings.append(finding)

        return findings

    def _scan_github_actions(self, file_path: str, content: str) -> List[SecurityFinding]:
        """Scan GitHub Actions workflow for security issues."""
        findings: List[SecurityFinding] = []
        lines = content.split("\n")

        for rule in self.gha_rules:
            for line_num, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line):
                    finding_id = self._generate_finding_id(file_path, line_num, rule["id"])

                    finding = SecurityFinding(
                        id=finding_id,
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        category=VulnerabilityCategory.CODE_EXECUTION,
                        cwe_id=rule["cwe"],
                        owasp_id="A03:2021",
                        location=CodeLocation(file_path=file_path, start_line=line_num, end_line=line_num, snippet=line),
                        remediation=rule["remediation"],
                        references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"],
                        confidence=0.90,
                        is_new=True,
                    )
                    findings.append(finding)

        return findings

    def _is_k8s_file(self, content: str) -> bool:
        """Check if a YAML file is a Kubernetes manifest."""
        try:
            docs = yaml.safe_load_all(content)
            for doc in docs:
                if doc and isinstance(doc, dict):
                    if "apiVersion" in doc and "kind" in doc:
                        return True
        except yaml.YAMLError:
            pass
        return False

    def _generate_finding_id(self, file_path: str, line_num: int, rule_id: str) -> str:
        """Generate a stable unique ID for a finding."""
        content = f"{file_path}:{line_num}:{rule_id}"
        hash_digest = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"SEC-IAC-{hash_digest.upper()}"
