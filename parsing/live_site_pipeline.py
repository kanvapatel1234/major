#!/usr/bin/env python3
"""
================================================================================
Continuous Live Packet Intercept & Hardware DPI Scoreboard Pipeline
================================================================================
1. Captures live HTTP (Port 80) and HTTPS (Port 443) network traffic via Scapy.
2. Filters out pure zero-payload handshake frames (SYN/ACK).
3. Dumps raw wire frames to packet_data.hex.
4. Executes Icarus Verilog hardware simulation (packet_parser_top.v + dpi_engine.v).
5. Computes Python Golden Reference DPI signature matches and byte offsets.
6. Automatically scoreboards Verilog hardware outputs against golden values.
================================================================================
"""

import os
import sys
import re
import subprocess
from typing import Tuple, Optional
from scapy.all import sniff, IP, TCP, Raw

# -----------------------------------------------------------------------------
# 1. TOOL PATHS & FILE LOCATIONS
# -----------------------------------------------------------------------------
IVERILOG_BIN = r"D:\iverilog\bin\iverilog.exe"
VVP_BIN = r"D:\iverilog\bin\vvp.exe"

PARSING_DIR = os.path.dirname(os.path.abspath(__file__))
HEX_PATH = os.path.join(PARSING_DIR, "packet_data.hex")
SIM_PATH = os.path.join(PARSING_DIR, "parser_sim")

# ANSI Color codes for formatted terminal output
CLR_RESET   = "\033[0m"
CLR_BOLD    = "\033[1m"
CLR_GREEN   = "\033[92m"
CLR_RED     = "\033[91m"
CLR_YELLOW  = "\033[93m"
CLR_CYAN    = "\033[96m"
CLR_MAGENTA = "\033[95m"

# -----------------------------------------------------------------------------
# 2. COMPILE HARDWARE PARSER & DPI CORE ONCE
# -----------------------------------------------------------------------------
print(f"\n{CLR_CYAN}{CLR_BOLD}{'=' * 95}")
print("  CONTINUOUS LIVE PACKET DPI HARDWARE SCOREBOARD PIPELINE")
print(f"{'=' * 95}{CLR_RESET}")
print(f"[*] Compiling packet_parser_top.v, dpi_engine.v, and tb_parser.v...")

compile_cmd = [
    IVERILOG_BIN,
    "-s", "tb_parser",
    "-o", "parser_sim",
    "packet_parser_top.v",
    "dpi_engine.v",
    "tb_parser.v",
]
res_compile = subprocess.run(compile_cmd, cwd=PARSING_DIR, capture_output=True, text=True)
if res_compile.returncode != 0:
    print(f"{CLR_RED}[Error] Icarus Verilog compilation failed:{CLR_RESET}\n{res_compile.stderr}")
    sys.exit(1)

print(f"{CLR_GREEN}[+] Hardware simulation compiled successfully!{CLR_RESET}\n")
print(f"{CLR_YELLOW}[*] Listening for live web traffic (TCP Ports 80 & 443)...{CLR_RESET}")
print(f"{CLR_YELLOW}[*] Open a browser or make HTTP/TLS requests to trigger hardware inspection.{CLR_RESET}")
print(f"{CLR_YELLOW}[*] Press Ctrl+C at any time to terminate and display summary statistics.{CLR_RESET}\n")

print(f"{'PKT #':<6} | {'5-TUPLE (SRC:SPORT -> DST:DPORT)':<35} | {'PAYLOAD':<9} | {'SIGNATURE':<20} | {'OFFSET':<8} | {'SCOREBOARD'}")
print("-" * 105)

packet_counter = 0
stats = {
    "total_captured": 0,
    "zero_payload_skipped": 0,
    "inspected": 0,
    "matches": 0,
    "scoreboard_pass": 0,
    "scoreboard_fail": 0,
}

# -----------------------------------------------------------------------------
# 3. PYTHON GOLDEN REFERENCE DPI ENGINE
# -----------------------------------------------------------------------------
RULE_NAMES = {
    1: "HTTP_GET ('GET ')",
    2: "HTTP_POST ('POST')",
    3: "HTTP_RESP ('HTTP')",
    4: "TLS_CLIENT_HELLO",
    5: "MALICIOUS ('EVIL')",
}

def golden_reference_dpi(payload: bytes, transport_port: int) -> Tuple[int, int, str, int]:
    """
    Hardware-identical sliding window pattern matcher in Python.
    Evaluates:
      - Rule 5: 'EVIL'     (All ports)
      - Rule 1: 'GET '     (Port 80)
      - Rule 2: 'POST'     (Port 80)
      - Rule 3: 'HTTP'     (Port 80)
      - Rule 4: 0x160301/3 (Port 443)
    Models exact byte-by-byte hardware sliding shift register timing.
    """
    candidates = []

    # Rule 5: 'EVIL' (highest threat priority)
    pos_evil = payload.find(b"EVIL")
    if pos_evil != -1:
        candidates.append((pos_evil + 4 - 1, 5, pos_evil))

    # Port 80 HTTP rules
    if transport_port == 80 or transport_port == 0:
        pos_get = payload.find(b"GET ")
        if pos_get != -1:
            candidates.append((pos_get + 4 - 1, 1, pos_get))

        pos_post = payload.find(b"POST")
        if pos_post != -1:
            candidates.append((pos_post + 4 - 1, 2, pos_post))

        pos_http = payload.find(b"HTTP")
        if pos_http != -1:
            candidates.append((pos_http + 4 - 1, 3, pos_http))

    # Port 443 TLS rules
    if transport_port == 443 or transport_port == 0:
        pos_tls10 = payload.find(b"\x16\x03\x01")
        if pos_tls10 != -1:
            candidates.append((pos_tls10 + 3 - 1, 4, pos_tls10))
        pos_tls12 = payload.find(b"\x16\x03\x03")
        if pos_tls12 != -1:
            candidates.append((pos_tls12 + 3 - 1, 4, pos_tls12))

    if not candidates:
        return 0, 0, "NONE (CLEAN)", 0

    # Sort by arrival of the pattern's final byte (exact hardware shift register trigger time)
    # Tie-break priority: Rule 5 > Rule 1 > Rule 2 > Rule 3 > Rule 4
    priority_order = {5: 0, 1: 1, 2: 2, 3: 3, 4: 4}
    candidates.sort(key=lambda c: (c[0], priority_order.get(c[1], 99)))

    first_trigger = candidates[0]
    matched_rule_id = first_trigger[1]
    matched_offset = first_trigger[2]
    rule_name = RULE_NAMES.get(matched_rule_id, f"RULE_{matched_rule_id}")

    return 1, matched_rule_id, rule_name, matched_offset

# -----------------------------------------------------------------------------
# 4. LIVE PACKET PROCESSOR & SCOREBOARD
# -----------------------------------------------------------------------------
def process_live_packet(pkt):
    global packet_counter
    stats["total_captured"] += 1

    # Filter: Must have TCP payload
    if not pkt.haslayer(TCP):
        return
    if not pkt.haslayer(Raw) or len(pkt[Raw].load) == 0:
        stats["zero_payload_skipped"] += 1
        return

    packet_counter += 1
    stats["inspected"] += 1

    raw_bytes = bytes(pkt)
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport  = int(pkt[TCP].sport)
    dport  = int(pkt[TCP].dport)
    scapy_payload = bytes(pkt[Raw].load)
    payload_len = len(scapy_payload)

    # Determine transport port (min of src and dst port)
    transport_port = 80 if (sport == 80 or dport == 80) else (443 if (sport == 443 or dport == 443) else min(sport, dport))

    # Python Golden Reference
    exp_match, exp_rule, exp_rule_name, exp_offset = golden_reference_dpi(scapy_payload, transport_port)
    if exp_match:
        stats["matches"] += 1

    # Write wire bytes to hex file for $readmemh
    with open(HEX_PATH, "w") as f:
        for b in raw_bytes:
            f.write(f"{b:02x}\n")

    # Run compiled Verilog hardware simulation
    res_sim = subprocess.run([VVP_BIN, "parser_sim"], cwd=PARSING_DIR, capture_output=True, text=True)
    sim_out = res_sim.stdout

    # Parse Verilog DUT simulation outputs
    src_match  = re.search(r"Source IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
    dst_match  = re.search(r"Destination IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
    sport_m    = re.search(r"Source Port\s*:\s*(\d+)", sim_out)
    dport_m    = re.search(r"Destination Port\s*:\s*(\d+)", sim_out)
    bytes_m    = re.search(r"Payload Bytes\s*:\s*(\d+)", sim_out)
    dpi_sig_m  = re.search(r"DPI Match\s*:\s*(\d+)", sim_out)
    dpi_rule_m = re.search(r"DPI Rule ID\s*:\s*(\d+)", sim_out)
    dpi_off_m  = re.search(r"DPI Offset\s*:\s*(\d+)", sim_out)

    if not all([src_match, dst_match, sport_m, dport_m, bytes_m, dpi_sig_m, dpi_rule_m, dpi_off_m]):
        status_str = f"{CLR_RED}[SIM PARSE ERROR]{CLR_RESET}"
        stats["scoreboard_fail"] += 1
        print(f"#{packet_counter:<5} | {src_ip}:{sport} -> {dst_ip}:{dport:<5} | {payload_len:>5} B  | {'ERROR':<20} | {'-':<8} | {status_str}")
        return

    hw_dpi_match  = int(dpi_sig_m.group(1))
    hw_dpi_rule   = int(dpi_rule_m.group(1))
    hw_dpi_offset = int(dpi_off_m.group(1))
    hw_bytes      = int(bytes_m.group(1))

    # Scoreboard Checks
    match_ok  = (hw_dpi_match == exp_match)
    rule_ok   = (hw_dpi_rule == exp_rule)
    offset_ok = (hw_dpi_offset == exp_offset) if exp_match == 1 else True
    payload_ok = (hw_bytes == payload_len)

    passed = match_ok and rule_ok and offset_ok and payload_ok
    if passed:
        stats["scoreboard_pass"] += 1
        status_str = f"{CLR_GREEN}[PASS (HW MATCH)]{CLR_RESET}" if exp_match else f"{CLR_CYAN}[PASS (CLEAN)]{CLR_RESET}"
    else:
        stats["scoreboard_fail"] += 1
        status_str = f"{CLR_RED}[MISMATCH FAIL]{CLR_RESET}"

    tuple_str = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
    off_str = f"0x{hw_dpi_offset:04X}" if hw_dpi_match else "-"
    sig_color = CLR_RED if hw_dpi_rule == 5 else (CLR_YELLOW if hw_dpi_match else CLR_RESET)
    sig_str = f"{sig_color}{exp_rule_name}{CLR_RESET}"

    print(f"#{packet_counter:<5} | {tuple_str:<35} | {payload_len:>5} B  | {sig_str:<30} | {off_str:<8} | {status_str}")


# -------------------------------------------------------------
# 5. START CONTINUOUS INTERCEPT
# -------------------------------------------------------------
filter_rule = "ip and tcp and (port 80 or port 443)"
try:
    sniff(filter=filter_rule, prn=process_live_packet, store=False)
except KeyboardInterrupt:
    print(f"\n\n{CLR_CYAN}{CLR_BOLD}{'=' * 80}")
    print("  LIVE HARDWARE SCOREBOARD EXECUTION SUMMARY")
    print(f"{'=' * 80}{CLR_RESET}")
    print(f"  {CLR_BOLD}Total TCP Packets Intercepted:{CLR_RESET}   {stats['total_captured']}")
    print(f"  {CLR_BOLD}Zero-Payload Handshakes Skipped:{CLR_RESET} {stats['zero_payload_skipped']}")
    print(f"  {CLR_BOLD}Payload Packets Evaluated:{CLR_RESET}       {stats['inspected']}")
    print(f"  {CLR_BOLD}DPI Signatures Triggered:{CLR_RESET}        {stats['matches']}")
    print(f"  {CLR_BOLD}Scoreboard Matches Passed:{CLR_RESET}       {CLR_GREEN}{stats['scoreboard_pass']}{CLR_RESET}")
    print(f"  {CLR_BOLD}Scoreboard Mismatches:{CLR_RESET}           {CLR_RED if stats['scoreboard_fail'] > 0 else CLR_GREEN}{stats['scoreboard_fail']}{CLR_RESET}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}\n")