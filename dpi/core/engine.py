#!/usr/bin/env python3
"""
================================================================================
FPGA DPI Engine - Core Controller & Pipeline
================================================================================
Main Deep Packet Inspection Controller.
Oversees:
- L2/L3/L4 Protocol Demux & 5-Tuple Extraction
- Zero-Payload Packet Filtering (discards SYN/ACK/FIN handshake frames)
- Sliding-window shift-register pattern matching
- TLS Handshake & SNI FSM extraction
- Telemetry, statistics, and execution summaries
================================================================================
"""

import time
from collections import Counter
from typing import List, Tuple, Optional

try:
    from scapy.all import IP, IPv6, TCP, Raw
except ImportError:
    pass  # Scapy is handled at entry-point verification

from core.models import (
    DPIRule,
    PacketMetadata,
    ClassificationVerdict,
    DEFAULT_HTTP_RULES,
    DEFAULT_CUSTOM_RULES,
    TLS_RULE_CLIENT_HELLO,
)
from core.formatter import Colors, HexPreviewFormatter
from core.matcher import HardwareShiftRegisterMatcher
from core.tls_parser import TLSFSMParser


class DPIEngine:
    """
    Main Deep Packet Inspection Controller.
    Oversees live sniffing, hardware shift-register matching, protocol FSM,
    and telemetry statistics.
    """

    def __init__(
        self,
        target_ports: Tuple[int, ...] = (80, 443),
        custom_rules: Optional[List[DPIRule]] = None,
        use_colors: bool = True,
    ):
        self.target_ports = target_ports
        if not use_colors:
            Colors.disable()

        # Initialize signature databases
        self.http_rules = list(DEFAULT_HTTP_RULES)
        self.custom_rules = list(custom_rules or DEFAULT_CUSTOM_RULES)

        # Hardware matchers for HTTP and Custom rules
        self.http_matcher = HardwareShiftRegisterMatcher(self.http_rules)
        self.custom_matcher = HardwareShiftRegisterMatcher(self.custom_rules)

        # Telemetry / Statistics
        self.stats = {
            "total_packets": 0,
            "tcp_target_packets": 0,
            "zero_payload_skipped": 0,
            "inspected_packets": 0,
            "total_payload_bytes": 0,
            "normal_packets": 0,
            "malicious_packets": 0,
            "matches_by_rule": Counter(),
            "sni_extracted": Counter(),
            "start_time": time.time(),
            "stop_time": 0.0,
        }

    def print_banner(self, interface: str):
        """Displays initialization telemetry banner."""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 80}")
        print("  FPGA-ORIENTED DEEP PACKET INSPECTION (DPI) ENGINE — LIVE CAPTURE")
        print(f"{'=' * 80}{Colors.RESET}")
        print(f"  {Colors.BOLD}Interface:{Colors.RESET}          {interface}")
        print(f"  {Colors.BOLD}Target Ports:{Colors.RESET}       {', '.join(map(str, self.target_ports))} (HTTP / HTTPS)")
        print(f"  {Colors.BOLD}Filtering Mode:{Colors.RESET}     Hardware Pre-filter (Discarding zero-payload SYN/ACK)")
        print(f"  {Colors.BOLD}Active Rules:{Colors.RESET}       {len(self.http_rules)} HTTP + {len(self.custom_rules)} Custom + TLS SNI FSM")
        print(f"  {Colors.BOLD}Output Format:{Colors.RESET}      Timestamp, 5-Tuple, Rule ID, Shift-Reg Offset, 32B Hex Dump")
        print(f"  {Colors.YELLOW}[*] Listening for live traffic... Press Ctrl+C to stop and display statistics.{Colors.RESET}\n")

    def classify_payload(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        timestamp: Optional[float] = None,
        ip_proto: str = "IPv4",
        verbose: bool = True,
    ) -> ClassificationVerdict:
        """
        Classifies an extracted payload as NORMAL or MALICIOUS using DPI matching.
        Directly consumes outputs from the hardware packet parser or network stream.
        """
        ts = timestamp if timestamp is not None else time.time()
        payload_len = len(payload)

        pkt_meta = PacketMetadata(
            timestamp=ts,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            ip_proto=ip_proto,
            payload_len=payload_len,
        )

        # Stage 1: Zero-Payload check (discards pure SYN/ACK/FIN handshake frames)
        if payload_len == 0:
            self.stats["zero_payload_skipped"] += 1
            self.stats["normal_packets"] += 1
            return ClassificationVerdict(
                verdict="NORMAL",
                reason="Zero-payload handshake frame (SYN/ACK/FIN)",
                matched_rules=[],
                packet_meta=pkt_meta,
                is_malicious=False,
                threat_severity="NONE",
            )

        self.stats["inspected_packets"] += 1
        self.stats["total_payload_bytes"] += payload_len

        matched_rules: List[DPIRule] = []
        is_malicious = False
        highest_severity = "NONE"
        severity_rank = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

        # Stage 2: Malicious / Custom Threat Signature Detection
        custom_matches = self.custom_matcher.match_payload(payload)
        for rule, offset in custom_matches:
            matched_rules.append(rule)
            self.stats["matches_by_rule"][rule.rule_id] += 1
            if rule.is_malicious:
                is_malicious = True
                if severity_rank.get(rule.severity, 0) > severity_rank.get(highest_severity, 0):
                    highest_severity = rule.severity
            if verbose:
                self._emit_match(rule, offset, len(rule.pattern), repr(rule.pattern), pkt_meta, payload)

        # Stage 3: Protocol Signatures (HTTP & TLS)
        http_matches = []
        if src_port == 80 or dst_port == 80 or not (src_port == 443 or dst_port == 443):
            http_matches = self.http_matcher.match_payload(payload)
            for rule, offset in http_matches:
                matched_rules.append(rule)
                self.stats["matches_by_rule"][rule.rule_id] += 1
                if verbose:
                    self._emit_match(rule, offset, len(rule.pattern), rule.pattern.decode("ascii", errors="replace"), pkt_meta, payload)

        tls_info = None
        if src_port == 443 or dst_port == 443 or (payload_len >= 5 and payload[0] == 0x16):
            tls_info = TLSFSMParser.parse_client_hello(payload)
            if tls_info:
                sni = tls_info.get("sni")
                if sni:
                    self.stats["sni_extracted"][sni] += 1
                    matched_rules.append(TLS_RULE_CLIENT_HELLO)
                    self.stats["matches_by_rule"][TLS_RULE_CLIENT_HELLO.rule_id] += 1
                    if verbose:
                        detail = f"SNI='{sni}' (Record: {tls_info['record_version_str']}, Client: {tls_info['client_version_str']})"
                        self._emit_match(
                            TLS_RULE_CLIENT_HELLO,
                            tls_info["sni_offset"] if tls_info["sni_offset"] >= 0 else 0,
                            len(sni),
                            detail,
                            pkt_meta,
                            payload,
                        )

        # Stage 4: Formulate Classification Verdict
        if is_malicious:
            self.stats["malicious_packets"] += 1
            mal_names = [r.name for r in matched_rules if r.is_malicious]
            reason = f"Threat signature(s) detected: {', '.join(mal_names)}"
            verdict = "MALICIOUS"
        else:
            self.stats["normal_packets"] += 1
            if tls_info and tls_info.get("sni"):
                reason = f"Valid TLS Handshake (SNI: '{tls_info['sni']}')"
            elif http_matches:
                names = ", ".join([r.name for r, _ in http_matches])
                reason = f"Valid HTTP Traffic ({names})"
            else:
                reason = "Benign application payload (no threat signatures matched)"
            verdict = "NORMAL"

        return ClassificationVerdict(
            verdict=verdict,
            reason=reason,
            matched_rules=matched_rules,
            packet_meta=pkt_meta,
            is_malicious=is_malicious,
            threat_severity=highest_severity if is_malicious else "NONE",
        )

    def process_packet(self, packet) -> Optional[ClassificationVerdict]:
        """
        Top-level packet handler for live capture / PCAP replay.
        Directly models hardware pipeline:
        Stage 1: L2/L3/L4 Protocol Demux & 5-Tuple Extraction
        Stage 2: Zero-Payload Length Filter (Discard SYN/ACK pure handshakes)
        Stage 3: Application Stream Slicing & Shift-Register Inspection
        Stage 4: Telemetry & Classification Emission
        """
        self.stats["total_packets"] += 1

        try:
            # Stage 1: Protocol Demux
            if not packet.haslayer(TCP):
                return None

            tcp_layer = packet[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)

            # Filter for configured ports
            if src_port not in self.target_ports and dst_port not in self.target_ports:
                return None

            self.stats["tcp_target_packets"] += 1

            # Extract IP 5-tuple
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ip_proto = "IPv4"
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                ip_proto = "IPv6"
            else:
                src_ip = "Unknown"
                dst_ip = "Unknown"
                ip_proto = "Raw"

            # Stage 2: Payload Extraction
            payload: bytes = b""
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
            elif hasattr(tcp_layer, "payload") and tcp_layer.payload:
                payload = bytes(tcp_layer.payload)

            ts = float(packet.time) if hasattr(packet, "time") else time.time()
            return self.classify_payload(
                payload=payload,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                timestamp=ts,
                ip_proto=ip_proto,
                verbose=True,
            )

        except Exception:
            # Resilient handling for malformed packets
            return None

    def _emit_match(
        self,
        rule: DPIRule,
        offset: int,
        match_len: int,
        value_str: str,
        meta: PacketMetadata,
        payload: bytes,
    ) -> None:
        """
        Formats and prints hardware-oriented match report.
        """
        hex_preview = HexPreviewFormatter.render(payload, offset, match_len)
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta.timestamp))
        sub_sec = f"{meta.timestamp % 1:.6f}"[1:]  # .123456

        header_color = Colors.RED if rule.is_malicious else Colors.GREEN
        header_tag = "[!] DPI MALICIOUS THREAT DETECTED" if rule.is_malicious else "[+] DPI MATCH DETECTED"

        print(f"\n{header_color}{Colors.BOLD}{header_tag} [Rule ID: {rule.rule_id}]{Colors.RESET}")
        print(f"    {Colors.BOLD}Signature:{Colors.RESET}       {Colors.YELLOW}{rule.name}{Colors.RESET} ({rule.protocol})")
        print(f"    {Colors.BOLD}Severity:{Colors.RESET}        {Colors.RED if rule.is_malicious else Colors.CYAN}{rule.severity}{Colors.RESET}")
        print(f"    {Colors.BOLD}Description:{Colors.RESET}     {rule.description}")
        print(f"    {Colors.BOLD}Extracted Value:{Colors.RESET} {Colors.WHITE}{value_str}{Colors.RESET}")
        print(
            f"    {Colors.BOLD}Packet Meta:{Colors.RESET}     {ts_str}{sub_sec} | {meta.src_ip}:{meta.src_port} -> {meta.dst_ip}:{meta.dst_port} ({meta.ip_proto})"
        )
        print(f"    {Colors.BOLD}Payload Length:{Colors.RESET}  {meta.payload_len} bytes")
        print(
            f"    {Colors.BOLD}Shift-Reg Offset:{Colors.RESET}{Colors.GREEN}{Colors.BOLD} 0x{offset:04X} ({offset} decimal){Colors.RESET}  <-- Hardware Tap Index"
        )
        print(f"    {Colors.BOLD}Hex Window (32-Byte Shift Register Surrounding Context):{Colors.RESET}")
        print(hex_preview)
        print(f"    {Colors.DIM}{'-' * 77}{Colors.RESET}")

    def print_summary(self) -> None:
        """
        Prints structured FPGA verification summary and telemetry statistics on exit.
        """
        self.stats["stop_time"] = time.time()
        duration = max(0.001, self.stats["stop_time"] - self.stats["start_time"])

        print(f"\n\n{Colors.CYAN}{Colors.BOLD}{'=' * 80}")
        print("  DPI ENGINE EXECUTION SUMMARY & HARDWARE TELEMETRY")
        print(f"{'=' * 80}{Colors.RESET}")
        print(f"  {Colors.BOLD}Session Duration:{Colors.RESET}         {duration:.2f} seconds")
        print(f"  {Colors.BOLD}Total Packets Sniffed:{Colors.RESET}    {self.stats['total_packets']}")
        print(f"  {Colors.BOLD}Target TCP Packets:{Colors.RESET}       {self.stats['tcp_target_packets']}")
        print(f"  {Colors.BOLD}Zero-Payload Discarded:{Colors.RESET}   {self.stats['zero_payload_skipped']} (Pure SYN/ACK/FIN handshakes)")
        print(f"  {Colors.BOLD}Payload Packets Inspected:{Colors.RESET}{self.stats['inspected_packets']}")
        print(f"  {Colors.BOLD}Total Bytes Inspected:{Colors.RESET}    {self.stats['total_payload_bytes']} bytes")
        print(f"  {Colors.BOLD}Normal Packets Classified:{Colors.RESET}{Colors.GREEN} {self.stats['normal_packets']}{Colors.RESET}")
        print(f"  {Colors.BOLD}Malicious Threats Blocked:{Colors.RESET}{Colors.RED}{Colors.BOLD} {self.stats['malicious_packets']}{Colors.RESET}")

        throughput_pps = self.stats["inspected_packets"] / duration
        throughput_kbps = (self.stats["total_payload_bytes"] / 1024.0) / duration
        print(f"  {Colors.BOLD}Inspection Throughput:{Colors.RESET}    {throughput_pps:.1f} pkts/sec ({throughput_kbps:.2f} KB/sec)")

        # Signature Match Breakdown Table
        print(f"\n  {Colors.YELLOW}{Colors.BOLD}SIGNATURE MATCH BREAKDOWN:{Colors.RESET}")
        print(f"  {'-' * 74}")
        print(f"  {'Rule ID':<10} {'Signature Name':<28} {'Protocol':<10} {'Matches':<10} {'% of Pkts'}")
        print(f"  {'-' * 74}")

        all_rules_dict = {r.rule_id: r for r in self.http_rules + self.custom_rules + [TLS_RULE_CLIENT_HELLO]}

        total_matches = sum(self.stats["matches_by_rule"].values())
        if total_matches == 0:
            print(f"  {Colors.DIM}No signature matches recorded during this session.{Colors.RESET}")
        else:
            for rule_id, count in sorted(self.stats["matches_by_rule"].items(), key=lambda x: x[1], reverse=True):
                r = all_rules_dict.get(rule_id)
                name = r.name if r else f"CUSTOM_RULE_{rule_id}"
                proto = r.protocol if r else "UNKNOWN"
                pct = (count / max(1, self.stats["inspected_packets"])) * 100
                print(f"  {rule_id:<10} {name:<28} {proto:<10} {count:<10} {pct:>6.1f}%")

        print(f"  {'-' * 74}")
        print(f"  {'TOTAL':<10} {'All Signatures':<28} {'':<10} {total_matches:<10}")

        # Unique SNIs Table
        if self.stats["sni_extracted"]:
            print(f"\n  {Colors.GREEN}{Colors.BOLD}IDENTIFIED TLS DOMAINS (Server Name Indication):{Colors.RESET}")
            print(f"  {'-' * 74}")
            print(f"  {'Domain Name':<55} {'Occurrences':<10}")
            print(f"  {'-' * 74}")
            for sni, count in self.stats["sni_extracted"].most_common(10):
                print(f"  {sni:<55} {count:<10}")
            print(f"  {'-' * 74}")

        print(f"\n{Colors.CYAN}{'=' * 80}{Colors.RESET}\n")
