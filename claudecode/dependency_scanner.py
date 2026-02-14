"""
Dependency vulnerability scanning module.
Queries OSV.dev API for known vulnerabilities in project dependencies.
"""

import asyncio
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from claudecode.schema import CodeLocation, SecurityFinding, Severity, VulnerabilityCategory


class DependencyScanner:
    """Scanner for detecting vulnerabilities in project dependencies."""

    OSV_API_URL = "https://api.osv.dev/v1/query"
    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    # Supported dependency file formats
    SUPPORTED_FILES = {
        "requirements.txt": "pip",
        "Pipfile": "pip",
        "Pipfile.lock": "pip",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "go.mod": "Go",
        "go.sum": "Go",
        "Gemfile": "RubyGems",
        "Gemfile.lock": "RubyGems",
        "Cargo.toml": "crates.io",
        "Cargo.lock": "crates.io",
        "pom.xml": "Maven",
        "build.gradle": "Maven",
        "composer.json": "Packagist",
        "composer.lock": "Packagist",
    }

    def __init__(self, timeout: int = 30) -> None:
        """
        Initialize dependency scanner.

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout

    async def scan_file(self, file_path: str, content: str) -> List[SecurityFinding]:
        """
        Scan a dependency file for vulnerabilities.

        Args:
            file_path: Path to the dependency file
            content: File content

        Returns:
            List of security findings for vulnerable dependencies
        """
        file_name = Path(file_path).name

        if file_name not in self.SUPPORTED_FILES:
            return []

        ecosystem = self.SUPPORTED_FILES[file_name]
        packages = self._parse_dependencies(file_name, content)

        if not packages:
            return []

        vulnerabilities = await self._query_osv_batch(packages, ecosystem)
        return self._convert_to_findings(vulnerabilities, file_path, ecosystem)

    async def scan_multiple_files(
        self, files: List[Tuple[str, str]]
    ) -> List[SecurityFinding]:
        """
        Scan multiple dependency files concurrently.

        Args:
            files: List of (file_path, content) tuples

        Returns:
            Combined list of security findings from all files
        """
        tasks = [self.scan_file(file_path, content) for file_path, content in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: List[SecurityFinding] = []
        for result in results:
            if isinstance(result, Exception):
                # Log error but continue with other files
                continue
            all_findings.extend(result)

        return all_findings

    def _parse_dependencies(self, file_name: str, content: str) -> List[Dict[str, str]]:
        """
        Parse dependencies from various file formats.

        Args:
            file_name: Name of the dependency file
            content: File content

        Returns:
            List of {name, version} dictionaries
        """
        if file_name == "requirements.txt":
            return self._parse_requirements_txt(content)
        elif file_name == "package.json":
            return self._parse_package_json(content)
        elif file_name == "package-lock.json":
            return self._parse_package_lock(content)
        elif file_name == "go.mod":
            return self._parse_go_mod(content)
        elif file_name == "Gemfile.lock":
            return self._parse_gemfile_lock(content)
        elif file_name == "Cargo.lock":
            return self._parse_cargo_lock(content)
        elif file_name == "composer.lock":
            return self._parse_composer_lock(content)
        else:
            return []

    def _parse_requirements_txt(self, content: str) -> List[Dict[str, str]]:
        """Parse Python requirements.txt file."""
        packages = []
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Handle various formats: package==version, package>=version, etc.
            match = re.match(r"^([a-zA-Z0-9_-]+)\s*([=<>!]+)\s*([0-9.]+)", line)
            if match:
                packages.append({"name": match.group(1), "version": match.group(3)})

        return packages

    def _parse_package_json(self, content: str) -> List[Dict[str, str]]:
        """Parse npm package.json file."""
        try:
            data = json.loads(content)
            packages = []

            for dep_type in ["dependencies", "devDependencies"]:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        # Remove ^ or ~ prefixes
                        clean_version = version.lstrip("^~")
                        packages.append({"name": name, "version": clean_version})

            return packages
        except json.JSONDecodeError:
            return []

    def _parse_package_lock(self, content: str) -> List[Dict[str, str]]:
        """Parse npm package-lock.json file."""
        try:
            data = json.loads(content)
            packages = []

            if "packages" in data:
                for pkg_path, pkg_info in data["packages"].items():
                    if pkg_path == "":
                        continue
                    name = pkg_path.split("node_modules/")[-1]
                    if "version" in pkg_info:
                        packages.append({"name": name, "version": pkg_info["version"]})

            return packages
        except json.JSONDecodeError:
            return []

    def _parse_go_mod(self, content: str) -> List[Dict[str, str]]:
        """Parse Go go.mod file."""
        packages = []
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("require"):
                # Skip the word "require"
                line = line[7:].strip()

            match = re.match(r"^([a-zA-Z0-9._/-]+)\s+v([0-9.]+)", line)
            if match:
                packages.append({"name": match.group(1), "version": match.group(2)})

        return packages

    def _parse_gemfile_lock(self, content: str) -> List[Dict[str, str]]:
        """Parse Ruby Gemfile.lock file."""
        packages = []
        in_specs = False

        for line in content.split("\n"):
            if "specs:" in line:
                in_specs = True
                continue

            if in_specs:
                match = re.match(r"^\s+([a-zA-Z0-9_-]+)\s+\(([0-9.]+)\)", line)
                if match:
                    packages.append({"name": match.group(1), "version": match.group(2)})

        return packages

    def _parse_cargo_lock(self, content: str) -> List[Dict[str, str]]:
        """Parse Rust Cargo.lock file (TOML format)."""
        packages = []
        current_package = {}

        for line in content.split("\n"):
            line = line.strip()

            if line.startswith("[[package]]"):
                if current_package:
                    packages.append(current_package)
                current_package = {}
            elif line.startswith('name = "'):
                match = re.search(r'name = "([^"]+)"', line)
                if match:
                    current_package["name"] = match.group(1)
            elif line.startswith('version = "'):
                match = re.search(r'version = "([^"]+)"', line)
                if match:
                    current_package["version"] = match.group(1)

        if current_package:
            packages.append(current_package)

        return packages

    def _parse_composer_lock(self, content: str) -> List[Dict[str, str]]:
        """Parse PHP composer.lock file."""
        try:
            data = json.loads(content)
            packages = []

            for pkg_list in ["packages", "packages-dev"]:
                if pkg_list in data:
                    for pkg in data[pkg_list]:
                        if "name" in pkg and "version" in pkg:
                            # Remove 'v' prefix from version
                            version = pkg["version"].lstrip("v")
                            packages.append({"name": pkg["name"], "version": version})

            return packages
        except json.JSONDecodeError:
            return []

    async def _query_osv_batch(
        self, packages: List[Dict[str, str]], ecosystem: str
    ) -> List[Dict[str, Any]]:
        """
        Query OSV.dev API for multiple packages in batch.

        Args:
            packages: List of package dictionaries
            ecosystem: Package ecosystem

        Returns:
            List of vulnerability data from OSV.dev
        """
        if not packages:
            return []

        queries = []
        for pkg in packages:
            queries.append(
                {
                    "package": {"name": pkg["name"], "ecosystem": ecosystem},
                    "version": pkg["version"],
                }
            )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.OSV_BATCH_URL,
                    json={"queries": queries},
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = []

                        for result in data.get("results", []):
                            if "vulns" in result and result["vulns"]:
                                results.extend(result["vulns"])

                        return results
                    else:
                        return []
        except (aiohttp.ClientError, asyncio.TimeoutError):
            # Network error - return empty list
            return []

    def _convert_to_findings(
        self, vulnerabilities: List[Dict[str, Any]], file_path: str, ecosystem: str
    ) -> List[SecurityFinding]:
        """
        Convert OSV.dev vulnerability data to SecurityFinding objects.

        Args:
            vulnerabilities: Vulnerability data from OSV.dev
            file_path: Path to the dependency file
            ecosystem: Package ecosystem

        Returns:
            List of SecurityFinding objects
        """
        findings: List[SecurityFinding] = []

        for vuln in vulnerabilities:
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "No description available")

            # Determine severity from CVSS or database_specific
            severity = self._determine_severity(vuln)

            # Extract affected package and version
            affected = vuln.get("affected", [{}])[0]
            package_name = affected.get("package", {}).get("name", "Unknown")

            # Get fixed version if available
            fixed_version = self._get_fixed_version(affected)

            # Generate stable finding ID
            finding_id = self._generate_finding_id(file_path, package_name, vuln_id)

            finding = SecurityFinding(
                id=finding_id,
                title=f"Vulnerable Dependency: {package_name}",
                description=f"Package '{package_name}' has a known vulnerability ({vuln_id}): {summary}",
                severity=severity,
                category=VulnerabilityCategory.SUPPLY_CHAIN,
                cwe_id=self._extract_cwe(vuln),
                owasp_id="A06:2021",  # Vulnerable and Outdated Components
                location=CodeLocation(file_path=file_path, start_line=1, end_line=1),
                remediation=self._generate_remediation(package_name, fixed_version),
                references=self._extract_references(vuln),
                confidence=0.95,  # High confidence for OSV.dev data
                is_new=True,
            )

            findings.append(finding)

        return findings

    def _determine_severity(self, vuln: Dict[str, Any]) -> Severity:
        """Determine severity from vulnerability data."""
        # Check for CVSS score
        if "severity" in vuln:
            for sev_entry in vuln["severity"]:
                if sev_entry.get("type") == "CVSS_V3":
                    score = float(sev_entry.get("score", 0))
                    if score >= 9.0:
                        return Severity.CRITICAL
                    elif score >= 7.0:
                        return Severity.HIGH
                    elif score >= 4.0:
                        return Severity.MEDIUM
                    else:
                        return Severity.LOW

        # Fall back to database_specific severity
        db_specific = vuln.get("database_specific", {})
        severity_str = db_specific.get("severity", "").upper()

        if severity_str in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            return Severity[severity_str]

        # Default to HIGH for vulnerabilities without severity info
        return Severity.HIGH

    def _get_fixed_version(self, affected: Dict[str, Any]) -> Optional[str]:
        """Extract the fixed version from affected data."""
        ranges = affected.get("ranges", [])
        for range_data in ranges:
            events = range_data.get("events", [])
            for event in events:
                if "fixed" in event:
                    return event["fixed"]
        return None

    def _extract_cwe(self, vuln: Dict[str, Any]) -> Optional[str]:
        """Extract CWE ID from vulnerability data."""
        # Check in database_specific
        db_specific = vuln.get("database_specific", {})
        if "cwe_ids" in db_specific and db_specific["cwe_ids"]:
            return db_specific["cwe_ids"][0]

        # Check in references
        for ref in vuln.get("references", []):
            url = ref.get("url", "")
            if "cwe.mitre.org" in url:
                match = re.search(r"CWE-(\d+)", url)
                if match:
                    return f"CWE-{match.group(1)}"

        return None

    def _extract_references(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from vulnerability data."""
        refs = []
        for ref in vuln.get("references", []):
            if "url" in ref:
                refs.append(ref["url"])
        return refs[:5]  # Limit to 5 references

    def _generate_remediation(self, package_name: str, fixed_version: Optional[str]) -> str:
        """Generate remediation guidance."""
        if fixed_version:
            return (
                f"Update '{package_name}' to version {fixed_version} or later. "
                f"Review your dependency file and update the version constraint, "
                f"then run your package manager's update command."
            )
        else:
            return (
                f"A vulnerability was found in '{package_name}'. "
                f"Check the package repository for updates or security advisories. "
                f"Consider using an alternative package if no fix is available."
            )

    def _generate_finding_id(self, file_path: str, package_name: str, vuln_id: str) -> str:
        """Generate a stable unique ID for a finding."""
        content = f"{file_path}:{package_name}:{vuln_id}"
        hash_digest = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"SEC-DEP-{hash_digest.upper()}"
