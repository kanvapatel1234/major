#!/usr/bin/env python3
"""
================================================================================
FPGA DPI Engine - Command-Line Interface & Execution Controller
================================================================================
Parses CLI options, resolves network interfaces, configures custom rules,
registers signal handlers, and triggers live sniffing, PCAP replay, or testbench.
================================================================================
"""

import sys
import os
import signal
import argparse
import warnings

warnings.filterwarnings("ignore")

try:
    from scapy.all import sniff, conf, get_if_list
except ImportError:
    print("[-] Error: Scapy is not installed. Please run: pip install scapy")
    sys.exit(1)

from core.formatter import Colors
from core.models import DEFAULT_CUSTOM_RULES, parse_custom_rule
from core.engine import DPIEngine


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for the DPI engine."""
    parser = argparse.ArgumentParser(
        description="FPGA-Oriented Deep Packet Inspection (DPI) Engine using Scapy & Npcap.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Hardware Mapping Notes:
  - This tool models sliding-window shift registers and streaming protocol FSMs.
  - Byte offsets are 0-indexed relative to raw TCP payload (AXI4-Stream data beat).
  - Pure SYN/ACK packets are pre-filtered at L4 to match FPGA ingress pre-filters.

Examples:
  python dpi_engine.py                         # Sniff on default Npcap interface
  python dpi_engine.py -i 0                    # Sniff on interface index 0
  python dpi_engine.py --list-ifaces           # Show all detected network interfaces
  python dpi_engine.py --test                  # Run hardware verification test suite
  python dpi_engine.py --custom-rule 401:XSS_TAG:"<script>"
        """,
    )

    parser.add_argument(
        "-i", "--iface",
        type=str,
        default=None,
        help="Network interface name or index to sniff on (default: scapy conf.iface).",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default="80,443",
        help="Comma-separated TCP ports to inspect (default: 80,443).",
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="List all detected network interfaces and exit.",
    )
    parser.add_argument(
        "--custom-rule",
        action="append",
        metavar="ID:NAME:PATTERN",
        help="Add custom rule. Format: 'ID:NAME:PATTERN' (e.g., '401:SQL_ADMIN:admin' or '402:MAGIC:0xdeadbeef')",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Execute automated synthetic packet test bench verifying shift-register and SNI offsets.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors for log files or plain text output.",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Read and inspect packets from an offline PCAP file instead of live capture.",
    )

    return parser.parse_args()


def main():
    """Main CLI entry point."""
    args = parse_arguments()

    if args.no_color:
        Colors.disable()

    # List interfaces option
    if args.list_ifaces:
        print(f"\n{Colors.CYAN}{Colors.BOLD}Detected Network Interfaces:{Colors.RESET}")
        print(f"{'-' * 70}")
        if_list = get_if_list()
        for idx, iface in enumerate(if_list):
            is_def = " (DEFAULT)" if iface == conf.iface else ""
            print(f"  [{idx}] {iface}{is_def}")
        print(f"{'-' * 70}\n")
        return

    # Target ports
    try:
        target_ports = tuple(int(p.strip()) for p in args.ports.split(","))
    except ValueError:
        print(f"[-] Invalid ports argument: {args.ports}")
        sys.exit(1)

    # Custom rules
    custom_rules = list(DEFAULT_CUSTOM_RULES)
    if args.custom_rule:
        for r_str in args.custom_rule:
            parsed = parse_custom_rule(r_str)
            if parsed:
                custom_rules.append(parsed)

    # Initialize Engine
    engine = DPIEngine(target_ports=target_ports, custom_rules=custom_rules, use_colors=not args.no_color)

    # Synthetic Test Benchmark mode
    if args.test:
        from test_dpi import run_hardware_testbench
        run_hardware_testbench(engine)
        return

    # Interface resolution
    selected_iface = conf.iface
    if args.iface:
        if_list = get_if_list()
        try:
            idx = int(args.iface)
            if 0 <= idx < len(if_list):
                selected_iface = if_list[idx]
            else:
                print(f"[-] Interface index {idx} out of range (0-{len(if_list)-1})")
                sys.exit(1)
        except ValueError:
            selected_iface = args.iface

    # Setup Graceful Exit on Ctrl+C (SIGINT)
    def sigint_handler(signum, frame):
        engine.print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    # PCAP Offline Replay Mode
    if args.pcap:
        if not os.path.exists(args.pcap):
            print(f"[-] PCAP file not found: {args.pcap}")
            sys.exit(1)
        print(f"[*] Reading and inspecting PCAP file: {args.pcap}")
        from scapy.all import rdpcap
        packets = rdpcap(args.pcap)
        for pkt in packets:
            engine.process_packet(pkt)
        engine.print_summary()
        return

    # Live Sniff Mode
    engine.print_banner(str(selected_iface))
    port_bpf_filter = " or ".join([f"port {p}" for p in target_ports])
    bpf_filter = f"tcp and ({port_bpf_filter})"

    try:
        sniff(
            filter=bpf_filter,
            prn=engine.process_packet,
            store=False,
            iface=selected_iface,
        )
    except KeyboardInterrupt:
        engine.print_summary()
    except Exception as e:
        print(f"\n[-] Sniffing error: {e}")
        engine.print_summary()


if __name__ == "__main__":
    main()
