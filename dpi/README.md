# FPGA-Oriented Deep Packet Inspection (DPI) Engine

A modular, hardware-aligned Deep Packet Inspection (DPI) engine developed in Python using **Scapy** and **Npcap**. Designed as a high-fidelity algorithmic reference and software testbed for eventual implementation in **FPGA hardware (Verilog / SystemVerilog)**.

---

## 1. Architectural Overview & Hardware Mapping

When transitioning DPI logic from software to an FPGA (e.g., AMD Xilinx UltraScale+ / Intel Agilex), traditional software abstractions (regular expressions, string copies, dynamic memory allocation) must be replaced by **fixed-latency pipelines, streaming shift registers, and hardware Finite State Machines (FSMs)**.

This Python engine strictly models those hardware primitives:

```
                      +---------------------------------------+
                      |       Live Network Interface          |
                      |        (Npcap / AXI4-Stream)          |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |   L2/L3/L4 Protocol Demux & Filter    |
                      |  - Match TCP Ports: 80, 443           |
                      |  - Discard Zero-Payload (SYN/ACK/FIN) |
                      +-------------------+-------------------+
                                          | Raw Payload Stream
                    +---------------------+---------------------+
                    |                                           |
                    v                                           v
    +-------------------------------+           +-------------------------------+
    | Hardware Shift Register Unit  |           |   TLS Handshake Parser FSM    |
    | (Tapped Delay Line Matcher)   |           | (Counter/Offset State Machine)|
    +---------------+---------------+           +---------------+---------------+
                    |                                           |
                    | [GET , POST , HTTP/1.1,                   | [Record 0x16, HS 0x01,
                    |  Host: , User-Agent: ,                    |  Skip Random/Ciphers,
                    |  Custom Hex/Strings]                      |  Extract SNI Domain]
                    |                                           |
                    +---------------------+---------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |     Hardware Match Telemetry Unit     |
                      | - 0-Indexed Payload Shift-Reg Offset  |
                      | - Canonical 32-Byte Window Hex Dump   |
                      | - Rule ID & Signature Attribution     |
                      +---------------------------------------+
```

### Hardware Primitive Mapping

| Python Component | FPGA Hardware Implementation Equivalent |
| :--- | :--- |
| **Ingress Pre-Filter** | Hardware drop unit: inspects `IP.total_length == (IP.ihl*4 + TCP.data_offset*4)`. If equal, asserts `tkeep=0` / drop before FIFO buffer. |
| **`HardwareShiftRegisterMatcher`** | Pipelined Tapped Delay Line: `shift_reg <= {shift_reg[W-2:0], s_axis_tdata};` with parallel comparator banks. |
| **Match Offset** | Exact clock cycle counter `offset <= cycle_count - PATTERN_LEN + 1` relative to `s_axis_tvalid & s_axis_tready` assertion on payload start. |
| **`TLSFSMParser`** | Byte-counter FSM: transitions states (`RECORD_HDR`, `HANDSHAKE_HDR`, `SKIP_RANDOM`, `EXTENSIONS`) using length registers to isolate SNI without buffering whole packets. |
| **Hex Window** | On-chip circular BRAM / dual-port SRAM inspection buffer captured around the match trigger address. |

### Modular Architecture & Code Organization

The codebase is organized into functionally cohesive modules under `core/`:

```
dpi/
├── core/
│   ├── __init__.py      # Core package exports
│   ├── formatter.py     # Terminal ANSI Colors & canonical 32-byte Hex/ASCII window formatter
│   ├── models.py        # DPIRule, PacketMetadata, MatchResult & default rule databases
│   ├── matcher.py       # HardwareShiftRegisterMatcher (Pipelined tapped delay line)
│   ├── tls_parser.py    # TLSFSMParser (Streaming byte-counter FSM & SNI extractor)
│   ├── engine.py        # DPIEngine (Demux, pre-filtering, rule dispatch, telemetry)
│   └── cli.py           # Command-line argument parsing and live capture driver
├── dpi_engine.py        # Main executable entry point & backwards-compatible public facade
├── test_dpi.py          # Synthetic hardware verification testbench
└── README.md            # Hardware architecture, mappings, and usage guide
```

---

## 2. Rule Database & Signatures

### HTTP Signatures (Port 80)
- **Rule 101**: `HTTP_METHOD_GET` (`b"GET "`)
- **Rule 102**: `HTTP_METHOD_POST` (`b"POST "`)
- **Rule 103**: `HTTP_VERSION_1_1` (`b"HTTP/1.1"`)
- **Rule 104**: `HTTP_HEADER_HOST` (`b"Host: "`)
- **Rule 105**: `HTTP_HEADER_USER_AGENT` (`b"User-Agent: "`)

### TLS / HTTPS Handshake Parser (Port 443)
- **Rule 301**: `TLS_CLIENT_HELLO_SNI`
  - Validates TLS Record Layer: Content Type `0x16` (Handshake), Version `0x0300`-`0x0304` (SSL 3.0 through TLS 1.3).
  - Validates Handshake Type `0x01` (Client Hello).
  - Traverses variable-length fields (Session ID, Cipher Suites, Compression).
  - Parses TLS Extensions looking for Extension Type `0x0000` (Server Name Indication).
  - Extracts the plaintext domain string and exact 0-indexed byte offset.

### Custom / Threat Signatures
- **Rule 201**: `CUSTOM_HEX_MAGIC_1337` (`b"\x13\x37\xca\xfe"`)
- **Rule 202**: `CUSTOM_SHELL_CMD` (`b"/bin/sh"`)
- **Rule 203**: `CUSTOM_SQL_SELECT` (`b"SELECT "`)
- Plus support for runtime user-defined patterns via `--custom-rule ID:NAME:PATTERN`.

---

## 3. Installation & Requirements

Ensure Python 3.8+ and Scapy with Npcap (on Windows) or libpcap (on Linux) are installed:

```powershell
pip install scapy
```

*Note: On Windows, Npcap must be installed in "WinPcap API-compatible Mode" to enable promiscuous live capture.*

---

## 4. Usage

### 4.1 Running the Hardware Verification Testbench (Offline Mode)
Before running on live traffic, execute the integrated testbench. This generates synthetic TCP streams (handshakes, HTTP requests, TLS ClientHellos, shell payloads, malformed frames) and validates zero-payload filtering and exact byte offsets:

```powershell
python dpi_engine.py --test
```

### 4.2 Listing Available Network Interfaces
To inspect which Npcap adapters are active:

```powershell
python dpi_engine.py --list-ifaces
```

### 4.3 Live Traffic Sniffing (Default Interface)
Sniff TCP ports 80 and 443 on the default interface:

```powershell
python dpi_engine.py
```

### 4.4 Specifying an Interface Index or Name
```powershell
# Sniff using interface index 4
python dpi_engine.py -i 4

# Or specify by interface device path
python dpi_engine.py -i "\Device\NPF_{4DC21F01-AAA2-493E-8F64-29B22CCD9720}"
```

### 4.5 Adding Custom Rules from the Command Line
You can supply string rules or hex sequences (prefixed with `0x`):

```powershell
# Custom ASCII string pattern:
python dpi_engine.py --custom-rule "401:XSS_SCRIPT:<script>"

# Custom Hex Byte Pattern (e.g. 0xDEADBEEF):
python dpi_engine.py --custom-rule "402:MAGIC_HEADER:0xdeadbeef"
```

### 4.6 Offline PCAP Inspection
```powershell
python dpi_engine.py --pcap capture.pcap
```

---

## 5. Sample Hardware Output

When a signature fires, the tool prints:
1. **Rule ID & Signature Name**
2. **Packet Metadata (5-Tuple)**: `Timestamp | Src IP:Port -> Dst IP:Port (Protocol)`
3. **Shift-Reg Offset**: Exact 0-indexed byte position where the pattern starts in the application payload.
4. **Hex Window (32-Byte Context)**: Canonical 16-byte aligned lines showing byte offsets, hex bytes (with matching bytes highlighted), and printable ASCII.

```
[+] DPI MATCH DETECTED [Rule ID: 301]
    Signature:       TLS_CLIENT_HELLO_SNI (TLS)
    Description:     TLS Client Hello Handshake & SNI
    Extracted Value: SNI='cloud-vault.example.org' (Record: TLS 1.0, Client: TLS 1.2 / TLS 1.3 Draft)
    Packet Meta:     2026-10-07 10:56:25.761194 | 192.168.1.100:51200 -> 104.244.42.1:443 (IPv4)
    Payload Length:  94 bytes
    Shift-Reg Offset: 0x003F (63 decimal)  <-- Hardware Tap Index
    Hex Window (32-Byte Shift Register Surrounding Context):
    Offset     +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C +D +E +F   ASCII Representation
    -----------------------------------------------------------------------------
    0x0037   00 00 1C 00 1A 00 00 17   63 6C 6F 75 64 2D 76 61 | ........cloud-va |
    0x0047   75 6C 74 2E 65 78 61 6D   70 6C 65 2E 6F 72 67 00 | ult.example.org. |
    -----------------------------------------------------------------------------
```

When interrupted with `Ctrl+C`, the engine gracefully renders an execution summary and breakdown:

```
================================================================================
  DPI ENGINE EXECUTION SUMMARY & HARDWARE TELEMETRY
================================================================================
  Session Duration:         14.20 seconds
  Total Packets Sniffed:    1,248
  Target TCP Packets:       980
  Zero-Payload Discarded:   612 (Pure SYN/ACK/FIN handshakes)
  Payload Packets Inspected:368
  Total Bytes Inspected:    284,520 bytes
  Inspection Throughput:    25.9 pkts/sec (19.57 KB/sec)

  SIGNATURE MATCH BREAKDOWN:
  --------------------------------------------------------------------------
  Rule ID    Signature Name               Protocol   Matches    % of Pkts
  --------------------------------------------------------------------------
  103        HTTP_VERSION_1_1             HTTP       45           12.2%
  104        HTTP_HEADER_HOST             HTTP       45           12.2%
  101        HTTP_METHOD_GET              HTTP       32            8.7%
  301        TLS_CLIENT_HELLO_SNI         TLS        28            7.6%
  105        HTTP_HEADER_USER_AGENT       HTTP       22            6.0%
  --------------------------------------------------------------------------
  TOTAL      All Signatures                          172       

  IDENTIFIED TLS DOMAINS (Server Name Indication):
  --------------------------------------------------------------------------
  Domain Name                                             Occurrences
  --------------------------------------------------------------------------
  api.github.com                                          12        
  update.microsoft.com                                    8         
  cloudflare-dns.com                                      5         
  --------------------------------------------------------------------------
================================================================================
```

---

## 6. Verilog / RTL Implementation Guidance

For hardware designers implementing this in Verilog:
1. **AXI4-Stream Bus Width**: For 10GbE MACs (64-bit `@` 156.25 MHz) or 100GbE (512-bit `@` 322 MHz), pattern matching requires sliding windows across word boundaries. The 0-indexed byte offset generated here corresponds to:
   $$\text{Offset} = (\text{Beat\_Count} \times W) + \text{Byte\_Lane\_Index}$$
2. **TLS FSM Counter**: The TLS parser state machine in RTL requires an internal 16-bit decrement counter:
   - When entering `SKIP_RANDOM`, load counter with `32`. Decrement by $W$ bytes per beat.
   - When entering variable-length blocks (Cipher Suites, Extensions), load counter from the incoming big-endian length field.
3. **CAM vs Shift Register**: For small signature counts ($\le 32$ strings), pipelined register comparators consume negligible LUTs. For large Snort/Suricata rule sets, implement an Aho-Corasick trie mapped to dual-port Block RAM (BRAM) or UltraRAM (URAM).
