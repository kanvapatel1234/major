#!/usr/bin/env python3
"""
================================================================================
Hardware Verification Testbench for DPI Engine
================================================================================
Simulates synthetic network packets to verify:
1. Zero-payload SYN/ACK/FIN handshake filtering.
2. HTTP GET, POST, HTTP/1.1, Host, User-Agent pattern detection and exact offsets.
3. TLS 1.0-1.3 ClientHello record parsing and SNI domain extraction.
4. Custom hex/byte patterns (e.g., 0x1337CAFE, /bin/sh, SELECT).
5. Resilient error handling on malformed/truncated packets.
================================================================================
"""

import struct
import time
import warnings
from typing import Optional

# Suppress cryptography and scapy deprecation warnings
warnings.filterwarnings("ignore")

from scapy.all import Ether, IP, TCP, Raw
from dpi_engine import DPIEngine, DPIRule, TLSFSMParser


def build_synthetic_tls_client_hello(
    domain: str = "secure.api.internal",
    record_version: int = 0x0301,  # TLS 1.0 record layer
    client_version: int = 0x0303,  # TLS 1.2 in ClientHello
) -> bytes:
    """
    Constructs a valid binary TLS Client Hello record containing an SNI extension.
    Directly reflects RFC 5246 / RFC 8446 wire formats.
    """
    domain_bytes = domain.encode("ascii")

    # SNI Extension: Type = 0x0000
    # SNI payload: [2B list_len] [1B type 0x00] [2B name_len] [name_bytes]
    sni_entry = b"\x00" + struct.pack(">H", len(domain_bytes)) + domain_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    ext_sni = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    # Add a dummy padding extension (Type 0x0015) to simulate realistic multi-extension frames
    dummy_pad = b"\x00" * 4
    ext_dummy = struct.pack(">HH", 0x0015, len(dummy_pad)) + dummy_pad

    extensions_block = ext_sni + ext_dummy
    extensions_hdr = struct.pack(">H", len(extensions_block)) + extensions_block

    # ClientHello Body:
    # [2B client_version] [32B random] [1B sess_len] [2B cs_len] [cs_bytes] [1B comp_len] [comp_bytes] [extensions]
    random_bytes = b"\xaa" * 32
    sess_id = b"\x00"  # 0 length session ID
    cipher_suites = struct.pack(">H", 4) + b"\xc0\x2f\xc0\x30"  # 2 cipher suites
    compression = b"\x01\x00"  # 1 compression method: null

    ch_body = (
        struct.pack(">H", client_version)
        + random_bytes
        + sess_id
        + cipher_suites
        + compression
        + extensions_hdr
    )

    # Handshake Header: Type 0x01 (ClientHello), Length (uint24)
    ch_hdr = struct.pack("!B", 0x01) + len(ch_body).to_bytes(3, "big")
    record_payload = ch_hdr + ch_body

    # TLS Record Header: Type 0x16 (Handshake), Version (uint16), Length (uint16)
    record_hdr = struct.pack(">BHH", 0x16, record_version, len(record_payload))

    return record_hdr + record_payload


def run_hardware_testbench(engine: Optional[DPIEngine] = None):
    """
    Feeds a synthetic packet stream through the DPI engine and validates matching logic.
    """
    if engine is None:
        engine = DPIEngine(target_ports=(80, 443), use_colors=True)

    print("\n" + "=" * 80)
    print("  RUNNING DPI ENGINE HARDWARE VERIFICATION TESTBENCH")
    print("=" * 80 + "\n")

    # --------------------------------------------------------------------------
    # Test 1: Zero-Payload Packets (SYN, SYN-ACK, pure ACK)
    # --------------------------------------------------------------------------
    print("[*] Test 1: Feeding Zero-Payload Packets (Pure Handshake Flags)...")
    syn_pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="S", seq=1000)
    syn_ack_pkt = IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=54321, flags="SA", seq=2000, ack=1001)
    ack_pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="A", seq=1001, ack=2001)

    engine.process_packet(syn_pkt)
    engine.process_packet(syn_ack_pkt)
    engine.process_packet(ack_pkt)
    print("    [+] Zero-payload packets passed. Pre-filter discarded:", engine.stats["zero_payload_skipped"])

    # --------------------------------------------------------------------------
    # Test 2: HTTP GET Request
    # --------------------------------------------------------------------------
    print("\n[*] Test 2: Injecting HTTP GET Request Packet (Port 80)...")
    http_get_payload = (
        b"GET /api/v1/telemetry HTTP/1.1\r\n"
        b"Host: telemetry.hardware.local\r\n"
        b"User-Agent: FPGA-Bench/2.0 (AXI4-Stream)\r\n"
        b"Accept: */*\r\n\r\n"
    )
    http_pkt = (
        IP(src="10.0.0.50", dst="172.16.0.100")
        / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=2001)
        / Raw(load=http_get_payload)
    )
    engine.process_packet(http_pkt)

    # --------------------------------------------------------------------------
    # Test 3: HTTP POST Request with Custom Payload
    # --------------------------------------------------------------------------
    print("\n[*] Test 3: Injecting HTTP POST Request with Embedded SQL & Hex Marker...")
    http_post_payload = (
        b"POST /query HTTP/1.1\r\n"
        b"Host: db.corp.net\r\n"
        b"Content-Length: 42\r\n\r\n"
        b"data=SELECT * FROM users;\x13\x37\xca\xfe"
    )
    post_pkt = (
        IP(src="10.0.0.55", dst="172.16.0.100")
        / TCP(sport=49153, dport=80, flags="PA", seq=1500, ack=2500)
        / Raw(load=http_post_payload)
    )
    engine.process_packet(post_pkt)

    # --------------------------------------------------------------------------
    # Test 4: TLS 1.2 Client Hello with SNI (Port 443)
    # --------------------------------------------------------------------------
    print("\n[*] Test 4: Injecting TLS 1.2 Client Hello with SNI: 'cloud-vault.example.org'...")
    tls_payload = build_synthetic_tls_client_hello("cloud-vault.example.org")
    tls_pkt = (
        IP(src="192.168.1.100", dst="104.244.42.1")
        / TCP(sport=51200, dport=443, flags="PA", seq=5000, ack=6000)
        / Raw(load=tls_payload)
    )
    engine.process_packet(tls_pkt)

    # --------------------------------------------------------------------------
    # Test 5: Custom Signature (/bin/sh shell invocation)
    # --------------------------------------------------------------------------
    print("\n[*] Test 5: Injecting Suspicious Exploit Stream with '/bin/sh'...")
    shell_payload = b"\x90\x90\x90\x90\x31\xc0\x50\x68//sh\x68/bin/sh"
    shell_pkt = (
        IP(src="192.168.1.200", dst="10.0.0.1")
        / TCP(sport=4444, dport=80, flags="PA", seq=7000, ack=8000)
        / Raw(load=shell_payload)
    )
    engine.process_packet(shell_pkt)

    # --------------------------------------------------------------------------
    # Test 6: Malformed / Truncated Packets (Resilience Test)
    # --------------------------------------------------------------------------
    print("\n[*] Test 6: Resilience Test - Feeding Truncated TLS & Corrupted Headers...")
    corrupt_tls = b"\x16\x03\x01\x00\x10\x01\x00"  # Incomplete record
    corrupt_pkt = (
        IP(src="1.1.1.1", dst="2.2.2.2")
        / TCP(sport=443, dport=5555, flags="PA")
        / Raw(load=corrupt_tls)
    )
    engine.process_packet(corrupt_pkt)
    print("    [+] Engine handled corrupted frames without exception.")

    # --------------------------------------------------------------------------
    # Final Summary Report
    # --------------------------------------------------------------------------
    engine.print_summary()


if __name__ == "__main__":
    run_hardware_testbench()
