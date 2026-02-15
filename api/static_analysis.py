import re
from typing import List, Dict, Any, TypedDict, Callable, Optional

class SecurityPattern(TypedDict, total=False):
    ruleName: str
    description: str
    severity: str
    recommendation: str
    path_check: Callable[[str], bool]
    substrings: List[str]
    regex: str

# Security patterns ported from claude-code/plugins/security-guidance/hooks/security_reminder_hook.py
SECURITY_PATTERNS: List[SecurityPattern] = [
    {
        "ruleName": "github_actions_workflow",
        "path_check": lambda path: ".github/workflows/" in path and (path.endswith(".yml") or path.endswith(".yaml")),
        "description": "GitHub Actions workflow command injection risk",
        "severity": "HIGH",
        "recommendation": "Use environment variables instead of direct context interpolation in run commands."
    },
    {
        "ruleName": "child_process_exec",
        "substrings": ["child_process.exec", "exec(", "execSync("],
        "description": "Command injection risk via child_process.exec",
        "severity": "HIGH",
        "recommendation": "Use execFile or spawn with argument arrays instead of shell execution."
    },
    {
        "ruleName": "new_function_injection",
        "substrings": ["new Function"],
        "description": "Code injection risk via new Function constructor",
        "severity": "HIGH",
        "recommendation": "Avoid dynamic code evaluation."
    },
    {
        "ruleName": "eval_injection",
        "regex": r"eval\s*\(",
        "description": "Arbitrary code execution risk via eval()",
        "severity": "CRITICAL",
        "recommendation": "Refactor to avoid eval(). Use JSON.parse() for data."
    },
    {
        "ruleName": "react_dangerously_set_html",
        "substrings": ["dangerouslySetInnerHTML"],
        "description": "XSS risk via dangerouslySetInnerHTML",
        "severity": "MEDIUM",
        "recommendation": "Ensure content is sanitized with DOMPurify."
    },
    {
        "ruleName": "document_write_xss",
        "substrings": ["document.write"],
        "description": "XSS risk via document.write()",
        "severity": "MEDIUM",
        "recommendation": "Use safer DOM manipulation methods."
    },
    {
        "ruleName": "innerHTML_xss",
        "substrings": [".innerHTML =", ".innerHTML="],
        "description": "XSS risk via innerHTML assignment",
        "severity": "MEDIUM",
        "recommendation": "Use textContent or a sanitizer library."
    },
    {
        "ruleName": "pickle_deserialization",
        "substrings": ["pickle.load", "pickle.loads"],
        "description": "Insecure deserialization risk via pickle",
        "severity": "CRITICAL",
        "recommendation": "Use JSON or safer serialization formats."
    },
    {
        "ruleName": "os_system_injection",
        "substrings": ["os.system", "from os import system"],
        "description": "Command injection risk via os.system",
        "severity": "HIGH",
        "recommendation": "Use subprocess.run() with a list of arguments."
    },
]

def run_static_analysis(file_name: str, content: str) -> List[Dict[str, Any]]:
    """Run static regex checks on file content."""
    findings = []
    
    # Normalize path
    normalized_path = file_name.replace("\\", "/")

    for pattern in SECURITY_PATTERNS:
        matched = False
        
        # Check path-based patterns
        if "path_check" in pattern:
            if pattern["path_check"](normalized_path):
                matched = True
        
        # Check content-based patterns
        if content:
            if "substrings" in pattern:
                for substring in pattern["substrings"]:
                    if substring in content:
                        matched = True
                        break
            
            if not matched and "regex" in pattern:
                if re.search(pattern["regex"], content, re.IGNORECASE):
                    matched = True
        
        if matched:
            findings.append({
                "title": f"Static Analysis: {pattern['description']}",
                "severity": pattern['severity'],
                "description": pattern['description'],
                "file": file_name,
                "line": 1, # Regex doesn't give line numbers easily without re-scanning, defaulting to 1
                "exploit_scenario": "This pattern is known to be dangerous and is flagged by static analysis.",
                "recommendation": pattern['recommendation'],
                "confidence": 1.0 # Static checks are definite pattern matches
            })
            
    return findings
