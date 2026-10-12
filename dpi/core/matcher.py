#!/usr/bin/env python3
"""
================================================================================
FPGA DPI Engine - Hardware Shift Register Matcher
================================================================================
Models an FPGA pipelined sliding window / tapped delay line pattern matcher.
Provides exact 0-indexed byte alignment relative to packet payload stream.
================================================================================
"""

from typing import List, Tuple
from core.models import DPIRule


class HardwareShiftRegisterMatcher:
    """
    Models an FPGA Pipelined Sliding Window / Shift Register Matcher.

    Hardware Equivalence:
    ---------------------
    In Verilog, a byte-serial or multi-byte (AXI4-Stream) data path feeds a
    tapped delay line:
        shift_reg <= {shift_reg[WINDOW_SIZE-2:0], rx_data_byte};
    In each clock cycle, fixed comparators evaluate whether:
        shift_reg[RULE_LEN-1:0] == RULE_PATTERN
    When a match occurs, the start offset corresponds to:
        match_offset = cycle_count - rule_len + 1.

    This class provides that exact 0-indexed byte alignment behavior.
    """

    def __init__(self, rules: List[DPIRule]):
        self.rules: List[DPIRule] = rules
        self.max_pattern_len = max([len(r.pattern) for r in rules]) if rules else 0

    def match_payload(self, payload: bytes) -> List[Tuple[DPIRule, int]]:
        """
        Scans payload using sliding-window logic and returns list of (rule, offset).
        Offset is 0-indexed byte position where the pattern starts.
        """
        matches: List[Tuple[DPIRule, int]] = []
        payload_len = len(payload)
        if payload_len == 0 or not self.rules:
            return matches

        # Hardware-modeled sliding window inspection
        for rule in self.rules:
            pat = rule.pattern
            pat_len = len(pat)
            if pat_len > payload_len:
                continue

            # Sliding comparison across payload stream
            # In hardware, this is evaluated in parallel across pipeline stages
            start_pos = 0
            while True:
                pos = payload.find(pat, start_pos)
                if pos == -1:
                    break
                matches.append((rule, pos))
                start_pos = pos + 1

        # Sort matches chronologically by their byte offset in the packet stream
        matches.sort(key=lambda x: x[1])
        return matches
