import subprocess
import sys
import os
import re
from scapy.all import sniff, IP, TCP, Raw

# Add dpi folder to Python sys.path so we can consume the DPI engine
DPI_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dpi"))
if DPI_DIR not in sys.path:
    sys.path.insert(0, DPI_DIR)

from dpi_engine import DPIEngine, Colors

IVERILOG_BIN = r"D:\iverilog\bin\iverilog.exe"
VVP_BIN = r"D:\iverilog\bin\vvp.exe"

# -------------------------------------------------------------
# 1. BUILD VERILOG HARDWARE SIMULATION ONCE
# -------------------------------------------------------------
print("[Setup] Compiling Verilog Parser & Testbench...")
compile_cmd = [IVERILOG_BIN, "-s", "tb_parser", "-o", "parser_sim", "packet_parser_top.v", "dpi_engine.v", "tb_parser.v"]
res_compile = subprocess.run(compile_cmd, capture_output=True, text=True)

if res_compile.returncode != 0:
    print("[Error] Icarus Verilog compilation failed:\n", res_compile.stderr)
    sys.exit(1)

# Initialize DPI Engine
dpi_engine = DPIEngine(target_ports=(80, 443), use_colors=True)

print("[Setup] Compilation successful! Hardware Parser connected to DPI Classification Engine.\n")
print(f"{'PKT #':<6} | {'SRC IP':<15} | {'DST IP':<15} | {'SPORT':<5} | {'DPORT':<5} | {'PAYLOAD':<9} | {'HW PARSE':<10} | {'DPI VERDICT':<13} | {'CLASSIFICATION DETAILS'}")
print("-" * 125)

packet_counter = 0

# -------------------------------------------------------------
# 2. PACKET INTERCEPT, HARDWARE EXTRACTION & DPI CLASSIFICATION
# -------------------------------------------------------------
def process_live_packet(pkt):
    global packet_counter
    packet_counter += 1

    raw_bytes = bytes(pkt)
    src_ip_str = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
    dst_ip_str = pkt[IP].dst if pkt.haslayer(IP) else "0.0.0.0"
    src_port   = pkt[TCP].sport if pkt.haslayer(TCP) else 0
    dst_port   = pkt[TCP].dport if pkt.haslayer(TCP) else 0

    exp_src_ip = f"{int.from_bytes(bytes(map(int, src_ip_str.split('.'))), 'big'):08x}" if pkt.haslayer(IP) else "00000000"
    exp_dst_ip = f"{int.from_bytes(bytes(map(int, dst_ip_str.split('.'))), 'big'):08x}" if pkt.haslayer(IP) else "00000000"
    
    # Expected payload directly from Scapy Layer
    scapy_payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    exp_payload_len = len(scapy_payload)
    exp_payload_hex = scapy_payload[:32].hex().lower()

    # Write full frame bytes to hex file for Verilog $readmemh
    with open("packet_data.hex", "w") as f:
        for b in raw_bytes:
            f.write(f"{b:02x}\n")

    # Run compiled simulation
    res_sim = subprocess.run([VVP_BIN, "parser_sim"], capture_output=True, text=True)
    sim_out = res_sim.stdout

    # Parse simulation output from hardware testbench
    src_match     = re.search(r"Source IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
    dst_match     = re.search(r"Destination IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
    sport_match   = re.search(r"Source Port\s*:\s*(\d+)", sim_out)
    dport_match   = re.search(r"Destination Port\s*:\s*(\d+)", sim_out)
    present_match = re.search(r"Payload Present\s*:\s*(\d+)", sim_out)
    bytes_match   = re.search(r"Payload Bytes\s*:\s*(\d+)", sim_out)
    hex_match     = re.search(r"Payload Hex\s*:\s*([0-9a-fA-F]*)", sim_out)

    if all([src_match, dst_match, sport_match, dport_match, present_match, bytes_match]):
        hw_src_hex   = src_match.group(1).lower()
        hw_dst_hex   = dst_match.group(1).lower()
        hw_sport     = int(sport_match.group(1))
        hw_dport     = int(dport_match.group(1))
        hw_p_present = int(present_match.group(1))
        hw_p_len     = int(bytes_match.group(1))
        hw_p_hex     = hex_match.group(1).lower() if hex_match else ""

        # Convert hex IP addresses from Verilog back to dotted-decimal notation
        hw_src_ip = f"{int(hw_src_hex[0:2], 16)}.{int(hw_src_hex[2:4], 16)}.{int(hw_src_hex[4:6], 16)}.{int(hw_src_hex[6:8], 16)}"
        hw_dst_ip = f"{int(hw_dst_hex[0:2], 16)}.{int(hw_dst_hex[2:4], 16)}.{int(hw_dst_hex[4:6], 16)}.{int(hw_dst_hex[6:8], 16)}"

        # Validate Headers against software reference
        headers_ok = (hw_src_hex == exp_src_ip and hw_dst_hex == exp_dst_ip and 
                      hw_sport == src_port and hw_dport == dst_port)
        
        # Validate Payload bytes
        sample_len = min(len(hw_p_hex), len(exp_payload_hex))
        if exp_payload_len == 0:
            payload_ok = (hw_p_len == 0)
        else:
            payload_bytes_ok = (hw_p_len == exp_payload_len)
            payload_sample_ok = (hw_p_hex[:sample_len] == exp_payload_hex[:sample_len]) if sample_len > 0 else True
            payload_ok = payload_bytes_ok and payload_sample_ok

        hw_status = "[VALID]" if (headers_ok and payload_ok) else "[MISMATCH]"
        payload_desc = f"{hw_p_len} B" if hw_p_present else "0 B (ACK)"

        # -----------------------------------------------------------------
        # STEP 3: FORWARD PARSED HARDWARE DATA TO DPI CLASSIFICATION ENGINE
        # -----------------------------------------------------------------
        pkt_time = float(pkt.time) if hasattr(pkt, "time") else None
        verdict = dpi_engine.classify_payload(
            payload=scapy_payload,
            src_ip=hw_src_ip,
            dst_ip=hw_dst_ip,
            src_port=hw_sport,
            dst_port=hw_dport,
            timestamp=pkt_time,
            verbose=False,
        )

        if verdict.is_malicious:
            dpi_str = f"{Colors.RED}{Colors.BOLD}[MALICIOUS]{Colors.RESET}"
            details_str = f"{Colors.RED}{verdict.reason}{Colors.RESET}"
        else:
            dpi_str = f"{Colors.GREEN}[NORMAL]{Colors.RESET}"
            details_str = f"{Colors.CYAN}{verdict.reason}{Colors.RESET}"

        print(f"{packet_counter:<6} | {hw_src_ip:<15} | {hw_dst_ip:<15} | {hw_sport:<5} | {hw_dport:<5} | {payload_desc:<9} | {hw_status:<10} | {dpi_str:<22} | {details_str}")
    else:
        print(f"{packet_counter:<6} | {src_ip_str:<15} | {dst_ip_str:<15} | {src_port:<5} | {dst_port:<5} | {'ERROR':<9} | {'[FAIL]':<10} | {'[SKIPPED]':<13} | Hardware parse failure")

# -------------------------------------------------------------
# 3. START STREAMING INTERCEPT
# -------------------------------------------------------------
filter_rule = "ip and tcp and (port 80 or port 443)"
try:
    sniff(filter=filter_rule, prn=process_live_packet, store=False)
except KeyboardInterrupt:
    print("\n[Stopped] Live packet processing terminated by user.")
    dpi_engine.print_summary()