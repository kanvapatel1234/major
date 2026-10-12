#!/usr/bin/env python3
"""
================================================================================
FPGA DPI Engine - Hardware FSM Protocol Parser (TLS / HTTPS)
================================================================================
Models an FPGA Finite State Machine (FSM) parsing streaming TLS records:
- TLS 1.0 - 1.3 Record Layer validation
- ClientHello Handshake parsing
- Server Name Indication (SNI) extension extraction
================================================================================
"""

import struct
from typing import Dict, Optional, Any


class TLSFSMParser:
    """
    Models an FPGA Finite State Machine (FSM) parsing streaming TLS records.

    Hardware FSM States:
    --------------------
    0: IDLE / RECORD_HEADER_WAIT  (5 bytes: ContentType, Version[2], Length[2])
    1: CHECK_HANDSHAKE_TYPE       (1 byte: Type 0x01 = ClientHello)
    2: SKIP_HS_LEN_AND_VERSION    (5 bytes: HS Length[3], Version[2])
    3: SKIP_RANDOM                (32 bytes)
    4: SKIP_SESSION_ID            (1 byte length + N bytes data)
    5: SKIP_CIPHER_SUITES         (2 bytes length + M bytes data)
    6: SKIP_COMPRESSION           (1 byte length + K bytes data)
    7: EXTENSIONS_HEADER          (2 bytes total extensions length)
    8: SCAN_EXTENSIONS            (Iterate 2-byte type + 2-byte len)
    9: PARSE_SNI_BODY             (Extract server name length & string)
    """

    TLS_RECORD_HANDSHAKE = 0x16
    TLS_HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOST_NAME = 0x00

    TLS_VERSION_NAMES = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2 / TLS 1.3 Draft",
        0x0304: "TLS 1.3",
    }

    @classmethod
    def parse_client_hello(cls, payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses TLS record layer and extracts Client Hello parameters & SNI domain.
        Returns a dictionary with parsed details or None if not a valid ClientHello.
        Robust against truncated or malformed payloads.
        """
        payload_len = len(payload)

        # State 0: Record Layer Header (Minimum 5 bytes)
        if payload_len < 5:
            return None

        content_type = payload[0]
        if content_type != cls.TLS_RECORD_HANDSHAKE:
            return None

        record_version = struct.unpack(">H", payload[1:3])[0]
        record_length = struct.unpack(">H", payload[3:5])[0]

        # Valid TLS record versions: SSL 3.0 (0x0300) through TLS 1.3 (0x0304)
        if record_version < 0x0300 or record_version > 0x0304:
            return None

        ptr = 5
        # State 1: Handshake Layer Header
        if ptr >= payload_len:
            return None

        handshake_type = payload[ptr]
        if handshake_type != cls.TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        # State 2: Handshake length (3 bytes) & Client Version (2 bytes)
        if ptr + 4 > payload_len:
            return None
        handshake_len = int.from_bytes(payload[ptr + 1 : ptr + 4], "big")
        ptr += 4

        if ptr + 34 > payload_len:
            return None
        client_version = struct.unpack(">H", payload[ptr : ptr + 2])[0]
        ptr += 2

        # State 3: Skip 32-byte Random
        ptr += 32

        # State 4: Session ID
        if ptr >= payload_len:
            return None
        session_id_len = payload[ptr]
        ptr += 1 + session_id_len

        # State 5: Cipher Suites
        if ptr + 2 > payload_len:
            return None
        cipher_suites_len = struct.unpack(">H", payload[ptr : ptr + 2])[0]
        ptr += 2 + cipher_suites_len

        # State 6: Compression Methods
        if ptr >= payload_len:
            return None
        compression_len = payload[ptr]
        ptr += 1 + compression_len

        # State 7: Extensions Header
        if ptr + 2 > payload_len:
            return {
                "record_version": record_version,
                "client_version": client_version,
                "record_length": record_length,
                "sni": None,
                "sni_offset": -1,
            }

        extensions_total_len = struct.unpack(">H", payload[ptr : ptr + 2])[0]
        ptr += 2
        extensions_end = min(ptr + extensions_total_len, payload_len)

        # State 8 & 9: Scan Extensions for SNI (0x0000)
        sni_hostname: Optional[str] = None
        sni_offset: int = -1

        while ptr + 4 <= extensions_end:
            ext_type = struct.unpack(">H", payload[ptr : ptr + 2])[0]
            ext_len = struct.unpack(">H", payload[ptr + 2 : ptr + 4])[0]
            ext_body_start = ptr + 4
            ext_body_end = ext_body_start + ext_len

            if ext_body_end > extensions_end:
                break  # Truncated extension

            if ext_type == cls.EXTENSION_SNI:
                # SNI Structure:
                # - Server Name List Length: 2 bytes
                #   - Server Name Type: 1 byte (0x00 = host_name)
                #   - Server Name Length: 2 bytes
                #   - Server Name: N bytes ASCII
                if ext_body_start + 2 <= ext_body_end:
                    s_ptr = ext_body_start + 2
                    while s_ptr + 3 <= ext_body_end:
                        name_type = payload[s_ptr]
                        name_len = struct.unpack(">H", payload[s_ptr + 1 : s_ptr + 3])[0]
                        name_val_start = s_ptr + 3
                        name_val_end = name_val_start + name_len

                        if name_val_end <= ext_body_end:
                            if name_type == cls.SNI_TYPE_HOST_NAME:
                                sni_raw = payload[name_val_start:name_val_end]
                                try:
                                    sni_hostname = sni_raw.decode("ascii", errors="replace")
                                except Exception:
                                    sni_hostname = repr(sni_raw)
                                sni_offset = name_val_start
                                break
                        s_ptr = name_val_end

                if sni_hostname:
                    break

            ptr = ext_body_end

        rec_ver_str = cls.TLS_VERSION_NAMES.get(record_version, f"0x{record_version:04X}")
        cli_ver_str = cls.TLS_VERSION_NAMES.get(client_version, f"0x{client_version:04X}")

        return {
            "record_version": record_version,
            "record_version_str": rec_ver_str,
            "client_version": client_version,
            "client_version_str": cli_ver_str,
            "record_length": record_length,
            "sni": sni_hostname,
            "sni_offset": sni_offset,
        }
