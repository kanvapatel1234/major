import subprocess
import sys
import re
from scapy.all import Ether, IP, TCP, Raw

# -------------------------------------------------------------
# 1. TOOL PATH CONFIGURATION
# -------------------------------------------------------------
# Specify the full path to your Icarus Verilog tools
IVERILOG_BIN = r"D:\iverilog\bin\iverilog.exe"
VVP_BIN = r"D:\iverilog\bin\vvp.exe"

# -------------------------------------------------------------
# 2. DEFINE TEST PACKET WITH SCAPY
# -------------------------------------------------------------
src_ip_str = "10.0.0.45"
dst_ip_str = "172.16.1.99"
src_port_num = 54321
dst_port_num = 443
payload_data = "TEST_SCAPY_PAYLOAD"

pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
      IP(src=src_ip_str, dst=dst_ip_str) / \
      TCP(sport=src_port_num, dport=dst_port_num) / \
      Raw(load=payload_data)

raw_bytes = bytes(pkt)

# Expected hex values for scoreboarding
exp_src_ip = f"{int.from_bytes(bytes(map(int, src_ip_str.split('.'))), 'big'):08x}"
exp_dst_ip = f"{int.from_bytes(bytes(map(int, dst_ip_str.split('.'))), 'big'):08x}"
exp_src_port = f"{src_port_num:04x}"
exp_dst_port = f"{dst_port_num:04x}"

# Write hex file for Verilog $readmemh
with open("packet_data.hex", "w") as f:
    for b in raw_bytes:
        f.write(f"{b:02x}\n")

print(f"[Python] Packet generated ({len(raw_bytes)} bytes)")
print(f"[Python] Expected Src IP  : {src_ip_str} -> {exp_src_ip}")
print(f"[Python] Expected Dst IP  : {dst_ip_str} -> {exp_dst_ip}")
print(f"[Python] Expected Src Port: {src_port_num} -> {exp_src_port}")
print(f"[Python] Expected Dst Port: {dst_port_num} -> {exp_dst_port}")
print("-" * 50)

# -------------------------------------------------------------
# 3. RUN ICARUS VERILOG COMPILATION & SIMULATION
# -------------------------------------------------------------
print("[Verilog] Compiling packet_parser_top.v, dpi_engine.v, and tb_parser.v...")
compile_cmd = [IVERILOG_BIN, "-s", "tb_parser", "-o", "parser_sim", "packet_parser_top.v", "dpi_engine.v", "tb_parser.v"]
sim_cmd = [VVP_BIN, "parser_sim"]

# Compile
res_compile = subprocess.run(compile_cmd, capture_output=True, text=True)
if res_compile.returncode != 0:
    print("[Error] Icarus Verilog compilation failed:")
    print(res_compile.stderr)
    sys.exit(1)

# Simulate
res_sim = subprocess.run(sim_cmd, capture_output=True, text=True)
if res_sim.returncode != 0:
    print("[Error] Verilog simulation execution failed:")
    print(res_sim.stderr)
    sys.exit(1)

print("[Verilog Hardware Output]:")
print(res_sim.stdout)

# -------------------------------------------------------------
# 4. AUTOMATED SCOREBOARD (PASS/FAIL CHECK)
# -------------------------------------------------------------
output = res_sim.stdout

# Extract values printed by tb_parser using regex
src_ip_match = re.search(r"Source IP\s*:\s*([0-9a-fA-F]{8})", output)
dst_ip_match = re.search(r"Destination IP\s*:\s*([0-9a-fA-F]{8})", output)
src_port_match = re.search(r"Source Port\s*:\s*(\d+)", output)
dst_port_match = re.search(r"Destination Port\s*:\s*(\d+)", output)

if all([src_ip_match, dst_ip_match, src_port_match, dst_port_match]):
    actual_src_ip = src_ip_match.group(1).lower()
    actual_dst_ip = dst_ip_match.group(1).lower()
    actual_src_port = int(src_port_match.group(1))
    actual_dst_port = int(dst_port_match.group(1))

    checks = [
        ("Source IP", actual_src_ip == exp_src_ip, f"{actual_src_ip} vs {exp_src_ip}"),
        ("Destination IP", actual_dst_ip == exp_dst_ip, f"{actual_dst_ip} vs {exp_dst_ip}"),
        ("Source Port", actual_src_port == src_port_num, f"{actual_src_port} vs {src_port_num}"),
        ("Destination Port", actual_dst_port == dst_port_num, f"{actual_dst_port} vs {dst_port_num}"),
    ]

    all_passed = True
    print("-" * 50)
    print("AUTOMATED VERIFICATION SUMMARY:")
    for name, passed, detail in checks:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {name}: {detail}")
        if not passed:
            all_passed = False

    print("=" * 50)
    if all_passed:
        print("OVERALL RESULT: ALL CHECKS PASSED")
    else:
        print("OVERALL RESULT: VERIFICATION FAILED")
    print("=" * 50)
else:
    print("[Warning] Could not parse all expected fields from Verilog output.")