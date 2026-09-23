"""
SQLI-HAILAMDEV - Core SQL Injection Engine
Supports error-based, union-based, boolean-based, time-based, and stacked injections.
"""

import re
import json
import base64
import hashlib
import secrets
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class InjectionType(Enum):
    ERROR = "error"
    UNION = "union"
    BOOLEAN = "boolean"
    TIME = "time"
    STACKED = "stacked"


class SQLIResult(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    WAF_BYPASSED = "waf_bypassed"


@dataclass
class SQLIEvent:
    """Represents a SQL injection event."""
    timestamp: float
    injection_type: InjectionType
    target: str
    payload: str
    success: bool
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class SQLIEngine:
    """Core SQL injection engine with multi-type support."""

    def __init__(self, db_config: Dict[str, Any]):
        self.db_config = db_config
        self.results: List[SQLIEvent] = []
        self._initialize_detectors()

    def _initialize_detectors(self):
        """Initialize detection mechanisms for common SQLi patterns."""
        # Pattern detectors for different injection types
        self.error_patterns = [
            r"(\bSELECT\b.*\bUNION\b)|(\bSELECT\b.*\bDROP\b)|(\bINSERT\b.*\bINTO\b)",
            r"(\bEXEC\b.*\bEXECUTE\b)|(\bEXECUTE\b.*\bPREPARE\b)",
            r"(\bDESC\b.*\bFROM\b)|(\bSHOW\s+TABLE\b)",
        ]
        self.union_patterns = [
            r"UNION\s+SELECT",
            r"SELECT\s+.*\s+FROM\s+.*\s+WHERE",
            r"SELECT\s+.*\s+FROM\s+(\w+)",
        ]
        self.boolean_patterns = [
            r"AND\s*\(\s*(1|yes|true|1=1)\s*\)|AND\s*\(\s*(0|no|false|1=0)\s*\)",
            r"OR\s*\(\s*(1|yes|true)\s*\)|OR\s*\(\s*(0|no|false)\s*\)",
        ]
        self.time_patterns = [
            r"\bSLEEP\b",
            r"\bWAITFOR\b",
            r"\bEXECUTE\b.*\bTIME\b",
        ]
        self.stacked_patterns = [
            r"SELECT\s+.*\s+FROM\s+(\w+)\s+ORDER\s+BY\s+(?:(?:ASC|DESC))",
        ]

    def detect_error_injection(self, query: str) -> Tuple[bool, str]:
        """Detect error-based SQL injection."""
        for pattern in self.error_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True, f"Error-based pattern detected: {pattern}"
        return False, ""

    def detect_union_injection(self, query: str) -> Tuple[bool, str]:
        """Detect union-based SQL injection."""
        for pattern in self.union_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True, f"Union-based pattern detected: {pattern}"
        return False, ""

    def detect_boolean_injection(self, query: str) -> Tuple[bool, str]:
        """Detect boolean-based SQL injection."""
        for pattern in self.boolean_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True, f"Boolean-based pattern detected: {pattern}"
        return False, ""

    def detect_time_injection(self, query: str) -> Tuple[bool, str]:
        """Detect time-based SQL injection."""
        for pattern in self.time_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True, f"Time-based pattern detected: {pattern}"
        return False, ""

    def detect_stacked_injection(self, query: str) -> Tuple[bool, str]:
        """Detect stacked SQL injection."""
        for pattern in self.stacked_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True, f"Stacked pattern detected: {pattern}"
        return False, ""

    def generate_payload(self, injection_type: InjectionType, target: str, length: int = 100) -> str:
        """Generate a payload based on injection type."""
        if injection_type == InjectionType.ERROR:
            return self._generate_error_payload(length)
        elif injection_type == InjectionType.UNION:
            return self._generate_union_payload(length)
        elif injection_type == InjectionType.BOOLEAN:
            return self._generate_boolean_payload(length)
        elif injection_type == InjectionType.TIME:
            return self._generate_time_payload(length)
        elif injection_type == InjectionType.STACKED:
            return self._generate_stacked_payload(length)
        else:
            raise ValueError(f"Unsupported injection type: {injection_type}")

    def _generate_error_payload(self, length: int) -> str:
        """Generate error-based payload."""
        # Common error-based payloads
        payloads = [
            "SELECT 1; --",
            "SELECT * FROM users WHERE 1=1;",
            "SELECT * FROM (SELECT 1 AS col FROM dual) t;",
            "SELECT * FROM (SELECT 1) t;",
            "SELECT * FROM (SELECT 1) t WHERE 1=1;",
        ]
        return payloads[length % len(payloads)]

    def _generate_union_payload(self, length: int) -> str:
        """Generate union-based payload."""
        # Classic UNION SELECT payload
        payloads = [
            "SELECT 1 AS id, 'test' AS username, 'pass' AS password FROM (SELECT 1) t;",
            "SELECT 1, 'admin', 'root' FROM (SELECT 1) t;",
            "SELECT 1, 'user1', 'password123' FROM (SELECT 1) t;",
        ]
        return payloads[length % len(payloads)]

    def _generate_boolean_payload(self, length: int) -> str:
        """Generate boolean-based payload."""
        payloads = [
            "1=1",
            "1=0",
            "true",
            "false",
            "1=1 OR 1=0",
            "1=1 AND 1=1",
        ]
        return payloads[length % len(payloads)]

    def _generate_time_payload(self, length: int) -> str:
        """Generate time-based payload."""
        # Sleep/wait payloads
        payloads = [
            "SELECT * FROM users WHERE 1=1; --",
            "SELECT * FROM (SELECT 1) t; --",
            "SELECT * FROM (SELECT 1) t WHERE 1=1; --",
        ]
        return payloads[length % len(payloads)]

    def _generate_stacked_payload(self, length: int) -> str:
        """Generate stacked SQL injection payload."""
        # Stacked queries with multiple statements
        payloads = [
            "SELECT 1; SELECT 2; SELECT 3;",
            "1; 2; 3;",
            "SELECT 1; INSERT INTO test VALUES (1);",
        ]
        return payloads[length % len(payloads)]

    def execute_query(self, query: str, params: tuple = ()) -> Dict[str, Any]:
        """Execute a query (requires actual database connection)."""
        # Placeholder - actual execution would use db_config
        return {"status": "executed", "query": query[:100]}

    def analyze_query(self, query: str) -> SQLIEvent:
        """Analyze a query for potential SQL injection."""
        injection_type = None
        success = False
        details = {}

        # Check for error-based injection
        if self.detect_error_injection(query):
            injection_type = InjectionType.ERROR
            details["pattern"] = "error-based"
            details["confidence"] = "high"
            success = True

        # Check for union-based injection
        elif self.detect_union_injection(query):
            injection_type = InjectionType.UNION
            details["pattern"] = "union-based"
            details["confidence"] = "medium"
            success = True

        # Check for boolean-based injection
        elif self.detect_boolean_injection(query):
            injection_type = InjectionType.BOOLEAN
            details["pattern"] = "boolean-based"
            details["confidence"] = "low"
            success = True

        # Check for time-based injection
        elif self.detect_time_injection(query):
            injection_type = InjectionType.TIME
            details["pattern"] = "time-based"
            details["confidence"] = "low"
            success = True

        # Check for stacked injection
        elif self.detect_stacked_injection(query):
            injection_type = InjectionType.STACKED
            details["pattern"] = "stacked"
            details["confidence"] = "low"
            success = True

        if success:
            return SQLIEvent(
                timestamp=time.time(),
                injection_type=injection_type,
                target=query[:50],
                payload=query,
                success=True,
                details=details
            )
        else:
            return SQLIEvent(
                timestamp=time.time(),
                injection_type=InjectionType.ERROR,
                target=query[:50],
                payload=query,
                success=False,
                details={"reason": "No clear injection pattern detected"}
            )

    def run(self, query: str, target: str = "untested") -> List[SQLIEvent]:
        """Run analysis on a query."""
        return self.analyze_query(query)


# Example usage
if __name__ == "__main__":
    engine = SQLIEngine({})
    result = engine.run("SELECT 1; --", target="test")
    print(result)
