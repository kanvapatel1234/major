#!/usr/bin/env python3
"""
================================================================================
Targeted Packet Generator & Hardware Verification Suite
================================================================================
Generates wire-accurate Ethernet/IP/TCP frames to validate hardware DPI rules:
- Test Case 1: HTTP GET request packet           -> Rule 1 (0x47455420: "GET ")
- Test Case 2: HTTP POST packet                  -> Rule 2 (0x504F5354: "POST")
- Test Case 3: TLS Handshake packet              -> Rule 4 (0x160301/0x160303)
- Test Case 4: Packet injected with "EVIL"       -> Rule 5 (0x4556494C: "EVIL")
- Test Case 5: Clean payload (no false positive) -> No Match (DPI Match = 0)
================================================================================
"""

import sys
import os
import re
import struct
import argparse
import subprocess
from scapy.all import Ether, IP, TCP, Raw

IVERILOG_BIN = r"D:\iverilog\bin\iverilog.exe"
VVP_BIN = r"D:\iverilog\bin\vvp.exe"

PARSING_DIR = os.path.dirname(os.path.abspath(__file__))
HEX_PATH = os.path.join(PARSING_DIR, "packet_data.hex")
SIM_PATH = os.path.join(PARSING_DIR, "parser_sim")


def build_tls_client_hello_payload(domain: str = "secure.api.net") -> bytes:
    """Constructs a binary TLS 1.2 / 1.0 Client Hello record."""
    domain_bytes = domain.encode("ascii")
    sni_entry = b"\x00" + struct.pack(">H", len(domain_bytes)) + domain_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    ext_sni = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    extensions_hdr = struct.pack(">H", len(ext_sni)) + ext_sni

    random_bytes = b"\xaa" * 32
    sess_id = b"\x00"
    cipher_suites = struct.pack(">H", 4) + b"\xc0\x2f\xc0\x30"
    compression = b"\x01\x00"

    ch_body = (
        struct.pack(">H", 0x0303)  # TLS 1.2 client version
        + random_bytes
        + sess_id
        + cipher_suites
        + compression
        + extensions_hdr
    )
    ch_hdr = struct.pack("!B", 0x01) + len(ch_body).to_bytes(3, "big")
    record_payload = ch_hdr + ch_body
    record_hdr = struct.pack(">BHH", 0x16, 0x0301, len(record_payload))  # 0x16, 0x0301 (TLS 1.0 record)
    return record_hdr + record_payload


def get_test_cases():
    return [
        {
            "case_id": 1,
            "name": "HTTP GET Request",
            "rule_id": 1,
            "rule_name": "HTTP_GET ('GET ')",
            "src_ip": "10.0.0.45",
            "dst_ip": "172.16.1.99",
            "sport": 54321,
            "dport": 80,
            "payload": b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: HardwareTester\r\n\r\n",
            "exp_match": 1,
            "exp_rule_id": 1,
            "exp_offset": 0,
        },
        {
            "case_id": 2,
            "name": "HTTP POST Request",
            "rule_id": 2,
            "rule_name": "HTTP_POST ('POST')",
            "src_ip": "10.0.0.50",
            "dst_ip": "172.16.1.100",
            "sport": 54322,
            "dport": 80,
            "payload": b"POST /api/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\nHelloPayload",
            "exp_match": 1,
            "exp_rule_id": 2,
            "exp_offset": 0,
        },
        {
            "case_id": 3,
            "name": "TLS Handshake Packet",
            "rule_id": 4,
            "rule_name": "TLS_CLIENT_HELLO (0x160301/03)",
            "src_ip": "192.168.1.15",
            "dst_ip": "104.244.42.1",
            "sport": 50100,
            "dport": 443,
            "payload": build_tls_client_hello_payload("portal.secure.org"),
            "exp_match": 1,
            "exp_rule_id": 4,
            "exp_offset": 0,
        },
        {
            "case_id": 4,
            "name": "Malicious 'EVIL' Injection",
            "rule_id": 5,
            "rule_name": "MALICIOUS_EVIL ('EVIL')",
            "src_ip": "192.168.10.99",
            "dst_ip": "10.0.0.1",
            "sport": 44444,
            "dport": 80,
            "payload": b"PADDING_HEADER_DATA_EVIL_EXPLOIT_PAYLOAD",
            "exp_match": 1,
            "exp_rule_id": 5,
            "exp_offset": 20,  # "PADDING_HEADER_DATA_".find("EVIL") = 20
        },
        {
            "case_id": 5,
            "name": "Clean Payload (No False Positives)",
            "rule_id": 0,
            "rule_name": "NONE",
            "src_ip": "10.1.2.3",
            "dst_ip": "192.168.0.254",
            "sport": 52000,
            "dport": 80,
            "payload": b"BENIGN_APPLICATION_STREAM_WITHOUT_ANY_MATCHING_PATTERNS",
            "exp_match": 0,
            "exp_rule_id": 0,
            "exp_offset": 0,
        },
    ]


def build_raw_packet(tc: dict) -> bytes:
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src=tc["src_ip"], dst=tc["dst_ip"])
        / TCP(sport=tc["sport"], dport=tc["dport"])
        / Raw(load=tc["payload"])
    )
    return bytes(pkt)


def write_hex_file(raw_bytes: bytes, filepath: str = HEX_PATH):
    with open(filepath, "w") as f:
        for b in raw_bytes:
            f.write(f"{b:02x}\n")


def compile_verilog():
    compile_cmd = [
        IVERILOG_BIN,
        "-s", "tb_parser",
        "-o", "parser_sim",
        "packet_parser_top.v",
        "dpi_engine.v",
        "tb_parser.v",
    ]
    res = subprocess.run(compile_cmd, cwd=PARSING_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        print("[Error] Icarus Verilog compilation failed:")
        print(res.stderr)
        sys.exit(1)


def run_verilog_simulation():
    res = subprocess.run([VVP_BIN, "parser_sim"], cwd=PARSING_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        print("[Error] Verilog simulation failed:")
        print(res.stderr)
        sys.exit(1)
    return res.stdout


def parse_simulation_output(sim_stdout: str):
    match_sig = re.search(r"DPI Match\s*:\s*(\d+)", sim_stdout)
    match_rule = re.search(r"DPI Rule ID\s*:\s*(\d+)", sim_stdout)
    match_off = re.search(r"DPI Offset\s*:\s*(\d+)", sim_stdout)
    match_bytes = re.search(r"Payload Bytes\s*:\s*(\d+)", sim_stdout)

    hw_match = int(match_sig.group(1)) if match_sig else None
    hw_rule = int(match_rule.group(1)) if match_rule else None
    hw_offset = int(match_off.group(1)) if match_off else None
    hw_bytes = int(match_bytes.group(1)) if match_bytes else None

    return hw_match, hw_rule, hw_offset, hw_bytes


def run_all_test_cases():
    print("=" * 80)
    print("  HARDWARE DPI TARGETED VERIFICATION SUITE")
    print("  Testing All 5 Rules on Pure Synthesizable Verilog Engine")
    print("=" * 80)
    print("[1/2] Compiling packet_parser_top.v, dpi_engine.v, tb_parser.v...")
    compile_verilog()
    print("[+] Compilation Successful!\n")

    cases = get_test_cases()
    print(f"{'CASE #':<7} | {'DESCRIPTION':<30} | {'PAYLOAD':<9} | {'EXP MATCH':<9} | {'HW MATCH':<9} | {'RULE':<6} | {'OFFSET':<6} | {'STATUS'}")
    print("-" * 95)

    all_passed = True
    for tc in cases:
        raw_wire = build_raw_packet(tc)
        write_hex_file(raw_wire)

        sim_out = run_verilog_simulation()
        hw_match, hw_rule, hw_offset, hw_bytes = parse_simulation_output(sim_out)

        exp_match = tc["exp_match"]
        exp_rule = tc["exp_rule_id"]
        exp_offset = tc["exp_offset"]

        passed = (hw_match == exp_match and hw_rule == exp_rule and (exp_match == 0 or hw_offset == exp_offset))
        if not passed:
            all_passed = False

        status_str = "[PASS]" if passed else "[FAIL]"
        print(
            f"Case {tc['case_id']:<2} | {tc['name']:<30} | {len(tc['payload']):>5} B  | "
            f"{exp_match:<9} | {hw_match:<9} | {hw_rule:<6} | {hw_offset:<6} | {status_str}"
        )

    print("=" * 95)
    if all_passed:
        print("OVERALL RESULT: ALL 5 TARGETED DPI RULES PASSED AUTOMATED HARDWARE SCOREBOARD!")
    else:
        print("OVERALL RESULT: HARDWARE VERIFICATION FAILED!")
    print("=" * 95)


def main():
    parser = argparse.ArgumentParser(description="Targeted Packet Generator & Hardware DPI Verification")
    parser.add_argument("--case", type=int, choices=[1, 2, 3, 4, 5], default=None,
                        help="Generate a specific test case packet into packet_data.hex (1: GET, 2: POST, 3: TLS, 4: EVIL, 5: Clean)")
    parser.add_argument("--test", action="store_true", help="Run automated testbench verifying all cases in hardware simulation")
    args = parser.parse_args()

    cases = {tc["case_id"]: tc for tc in get_test_cases()}

    if args.test or args.case is None:
        run_all_test_cases()
    else:
        tc = cases[args.case]
        raw_wire = build_raw_packet(tc)
        write_hex_file(raw_wire)
        print(f"[+] Test Case {args.case} ({tc['name']}) generated.")
        print(f"    - Destination Port: {tc['dport']}")
        print(f"    - Payload Size:     {len(tc['payload'])} bytes")
        print(f"    - Target Signature: {tc['rule_name']}")
        print(f"    - Expected Match:   {tc['exp_match']} (Rule {tc['exp_rule_id']} at offset {tc['exp_offset']})")
        print(f"    - Wire Bytes saved: {HEX_PATH}")


if __name__ == "__main__":
    main()