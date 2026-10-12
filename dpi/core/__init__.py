"""
FPGA-Oriented Deep Packet Inspection (DPI) Core Package
"""

from core.formatter import Colors, HexPreviewFormatter
from core.models import (
    DPIRule,
    PacketMetadata,
    MatchResult,
    ClassificationVerdict,
    DEFAULT_HTTP_RULES,
    DEFAULT_CUSTOM_RULES,
    TLS_RULE_CLIENT_HELLO,
    parse_custom_rule,
)
from core.matcher import HardwareShiftRegisterMatcher
from core.tls_parser import TLSFSMParser
from core.engine import DPIEngine
from core.cli import parse_arguments, main

__all__ = [
    "Colors",
    "HexPreviewFormatter",
    "DPIRule",
    "PacketMetadata",
    "MatchResult",
    "ClassificationVerdict",
    "DEFAULT_HTTP_RULES",
    "DEFAULT_CUSTOM_RULES",
    "TLS_RULE_CLIENT_HELLO",
    "parse_custom_rule",
    "HardwareShiftRegisterMatcher",
    "TLSFSMParser",
    "DPIEngine",
    "parse_arguments",
    "main",
]
