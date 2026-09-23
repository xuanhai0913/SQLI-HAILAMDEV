"""
SQLI-HAILAMDEV - Automated Vulnerability Scanner
Scans targets for SQL injection vulnerabilities using multiple techniques.
"""

import requests
import json
import time
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class ScanResult:
    target: str
    vulnerable: bool
    vector: str
    details: Dict[str, str]
    confidence: str
    timestamp: float


class SQLIScanner:
    """Automated SQL injection vulnerability scanner."""

    def __init__(self, targets: List[str], waf_bypass: bool = False):
        self.targets = targets
        self.waf_bypass = waf_bypass
        self.results: List[ScanResult] = []

    def scan_target(self, target: str) -> ScanResult:
        """Scan a single target for SQL injection vulnerabilities."""
        url = f"https://{target}"
        
        # Try common injection points
        injection_points = [
            f"{url}/search",
            f"{url}/login",
            f"{url}/api/users",
            f"{url}/admin",
            f"{url}/query",
            f"{url}/search?q",
        ]
        
        for endpoint in injection_points:
            try:
                response = requests.get(endpoint, timeout=10)
                if response.status_code == 200:
                    # Analyze response for SQLi indicators
                    if self._detect_sqli(response.text, endpoint):
                        return ScanResult(
                            target=target,
                            vulnerable=True,
                            vector="unknown",
                            details={
                                "endpoint": endpoint,
                                "status_code": response.status_code,
                                "response_length": len(response.text)
                            },
                            confidence="high",
                            timestamp=time.time()
                        )
            except Exception as e:
                # Consider unreachable as potentially vulnerable
                return ScanResult(
                    target=target,
                    vulnerable=True,
                    vector="network_access",
                    details={"error": str(e)},
                    confidence="medium",
                    timestamp=time.time()
                )
        
        return ScanResult(
            target=target,
            vulnerable=False,
            vector="none",
            details={},
            confidence="low",
            timestamp=time.time()
        )

    def _detect_sqli(self, response_text: str, endpoint: str) -> bool:
        """Detect SQL injection patterns in response."""
        # Look for common SQLi indicators
        indicators = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
            "OR 1=1", "AND 1=1", "1=0", "1=2", "1=1 OR 1=0",
            "SELECT * FROM", "SELECT * FROM (SELECT 1)",
            "SELECT 1, 'test', 'pass'",
            "SELECT 1, 'admin', 'root'",
        ]
        
        for indicator in indicators:
            if indicator in response_text:
                return True
        
        return False

    def scan_all(self) -> List[ScanResult]:
        """Scan all targets."""
        self.results = []
        for target in self.targets:
            result = self.scan_target(target)
            self.results.append(result)
        return self.results

    def generate_report(self) -> str:
        """Generate a scan report."""
        report = []
        report.append("=" * 60)
        report.append("SQLI SCAN REPORT")
        report.append("=" * 60)
        
        for result in self.results:
            report.append(f"\nTarget: {result.target}")
            report.append(f"  Vulnerable: {result.vulnerable}")
            report.append(f"  Vector: {result.vector}")
            report.append(f"  Confidence: {result.confidence}")
            report.append(f"  Details: {json.dumps(result.details, indent=2)}")
        
        return "\n".join(report)


if __name__ == "__main__":
    # Example usage
    targets = [
        "http://example.com/search",
        "http://example.com/login",
        "http://example.com/api/users",
    ]
    scanner = SQLIScanner(targets, waf_bypass=True)
    results = scanner.scan_all()
    print(scanner.generate_report())
