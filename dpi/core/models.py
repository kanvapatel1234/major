#!/usr/bin/env python3
"""
================================================================================
FPGA DPI Engine - Data Models and Rule Definitions
================================================================================
Defines core data structures for DPI rules, packet metadata, match results,
and default signature databases.
================================================================================
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class DPIRule:
    """Represents a hardware comparator rule."""

    rule_id: int
    name: str
    pattern: bytes
    protocol: str  # 'HTTP', 'TLS', 'CUSTOM'
    description: str = ""
    is_malicious: bool = False
    severity: str = "INFO"  # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

    def __len__(self) -> int:
        return len(self.pattern)


@dataclass
class PacketMetadata:
    """Extracted network layer metadata."""

    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    ip_proto: str
    payload_len: int


@dataclass
class MatchResult:
    """Result emitted when a DPI rule fires."""

    rule_id: int
    rule_name: str
    protocol: str
    offset: int  # 0-indexed offset within payload
    match_length: int  # Length of the matched pattern
    extracted_value: str  # Pattern or parsed value (e.g. SNI domain)
    packet_meta: PacketMetadata
    surrounding_hex: str  # Canonical 32-byte hex preview


@dataclass
class ClassificationVerdict:
    """Classification verdict returned after DPI inspection."""

    verdict: str  # "MALICIOUS" or "NORMAL"
    reason: str
    matched_rules: List[DPIRule]
    packet_meta: PacketMetadata
    is_malicious: bool
    threat_severity: str = "NONE"  # 'NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'


# ==============================================================================
# Default Rule Databases
# ==============================================================================
DEFAULT_HTTP_RULES: List[DPIRule] = [
    DPIRule(101, "HTTP_METHOD_GET", b"GET ", "HTTP", "HTTP GET Request Method", is_malicious=False, severity="INFO"),
    DPIRule(102, "HTTP_METHOD_POST", b"POST ", "HTTP", "HTTP POST Request Method", is_malicious=False, severity="INFO"),
    DPIRule(103, "HTTP_VERSION_1_1", b"HTTP/1.1", "HTTP", "HTTP 1.1 Protocol Header", is_malicious=False, severity="INFO"),
    DPIRule(104, "HTTP_HEADER_HOST", b"Host: ", "HTTP", "HTTP Host Header", is_malicious=False, severity="INFO"),
    DPIRule(105, "HTTP_HEADER_USER_AGENT", b"User-Agent: ", "HTTP", "HTTP User-Agent Header", is_malicious=False, severity="INFO"),
]

DEFAULT_CUSTOM_RULES: List[DPIRule] = [
    DPIRule(201, "CUSTOM_HEX_MAGIC_1337", b"\x13\x37\xca\xfe", "CUSTOM", "Custom Exploit Magic Hex Marker", is_malicious=True, severity="CRITICAL"),
    DPIRule(202, "MALICIOUS_SHELL_BIN_SH", b"/bin/sh", "CUSTOM", "Suspicious Shell Invocation / RCE Attack", is_malicious=True, severity="CRITICAL"),
    DPIRule(203, "MALICIOUS_SHELL_BIN_BASH", b"/bin/bash", "CUSTOM", "Bash Shell Invocation / RCE Attack", is_malicious=True, severity="CRITICAL"),
    DPIRule(204, "MALICIOUS_CMD_EXE", b"cmd.exe", "CUSTOM", "Windows Command Shell Invocation", is_malicious=True, severity="CRITICAL"),
    DPIRule(205, "MALICIOUS_SQL_SELECT", b"SELECT ", "CUSTOM", "SQL Injection / Query Marker", is_malicious=True, severity="HIGH"),
    DPIRule(206, "MALICIOUS_SQL_UNION", b"UNION SELECT", "CUSTOM", "SQL Injection UNION Attack", is_malicious=True, severity="CRITICAL"),
    DPIRule(207, "MALICIOUS_PATH_TRAVERSAL", b"../../", "CUSTOM", "Directory Path Traversal Attack", is_malicious=True, severity="HIGH"),
    DPIRule(208, "MALICIOUS_ETC_PASSWD", b"/etc/passwd", "CUSTOM", "Sensitive Credential File Access", is_malicious=True, severity="CRITICAL"),
    DPIRule(209, "MALICIOUS_XSS_SCRIPT", b"<script>", "CUSTOM", "Cross-Site Scripting (XSS) Injection", is_malicious=True, severity="HIGH"),
]

TLS_RULE_CLIENT_HELLO = DPIRule(
    301, "TLS_CLIENT_HELLO_SNI", b"\x16", "TLS", "TLS Client Hello Handshake & SNI", is_malicious=False, severity="INFO"
)


def parse_custom_rule(rule_arg: str) -> Optional[DPIRule]:
    """
    Parses a CLI custom rule argument string: 'ID:NAME:PATTERN'.
    Pattern can be plain ASCII or hex encoded starting with '0x'.
    """
    try:
        parts = rule_arg.split(":", 2)
        if len(parts) != 3:
            raise ValueError("Expected ID:NAME:PATTERN format.")
        rule_id = int(parts[0])
        rule_name = parts[1].strip()
        pat_str = parts[2]

        # Check if hex format (starts with 0x)
        if pat_str.startswith("0x") or pat_str.startswith("0X"):
            pattern_bytes = bytes.fromhex(pat_str[2:])
        else:
            pattern_bytes = pat_str.encode("utf-8")

        # By default custom rules added via CLI are treated as potential threat indicators
        is_mal = "NORMAL" not in rule_name.upper() and "BENIGN" not in rule_name.upper()

        return DPIRule(
            rule_id,
            rule_name,
            pattern_bytes,
            "CUSTOM",
            f"CLI Custom Rule: {rule_name}",
            is_malicious=is_mal,
            severity="HIGH" if is_mal else "INFO",
        )
    except Exception as e:
        print(f"[-] Invalid custom rule specification '{rule_arg}': {e}")
        return None
