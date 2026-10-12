#!/usr/bin/env python3
"""
================================================================================
FPGA-Oriented Deep Packet Inspection (DPI) Engine
================================================================================
A modular, hardware-aligned DPI engine built in Python using Scapy and Npcap.
Designed as a software prototype for eventual implementation in FPGA (Verilog/VHDL).

Divided modularly across functional packages:
- core.formatter:  ANSI Colors & canonical 32-byte Hex/ASCII window formatter
- core.models:     DPIRule, PacketMetadata, MatchResult & signature databases
- core.matcher:    HardwareShiftRegisterMatcher (Pipelined tapped delay line)
- core.tls_parser: TLSFSMParser (Streaming byte-counter FSM & SNI extractor)
- core.engine:     DPIEngine (Protocol demux, pre-filtering, telemetry pipeline)
- core.cli:        Command-line interface, interface resolution & execution
================================================================================
"""

import sys
import os

# Ensure the package directory is accessible in sys.path
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

from core import (
    Colors,
    HexPreviewFormatter,
    DPIRule,
    PacketMetadata,
    MatchResult,
    ClassificationVerdict,
    DEFAULT_HTTP_RULES,
    DEFAULT_CUSTOM_RULES,
    TLS_RULE_CLIENT_HELLO,
    parse_custom_rule,
    HardwareShiftRegisterMatcher,
    TLSFSMParser,
    DPIEngine,
    parse_arguments,
    main,
)

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

if __name__ == "__main__":
    main()
