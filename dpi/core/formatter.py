#!/usr/bin/env python3
"""
================================================================================
FPGA DPI Engine - Terminal Formatter and Hex Preview
================================================================================
Handles ANSI color codes and hardware-aligned 32-byte hex/ASCII window rendering.
================================================================================
"""


class Colors:
    """ANSI color codes for hardware terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_BLUE = "\033[44m"
    BG_DARK = "\033[100m"

    @classmethod
    def disable(cls):
        """Disable all ANSI escape sequences for plain-text / log output."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""
        cls.BG_BLUE = ""
        cls.BG_DARK = ""


class HexPreviewFormatter:
    """
    Renders a canonical 32-byte memory window around a matched signature offset.
    Formats exact byte positions, hex bytes, and printable ASCII.
    """

    @staticmethod
    def render(payload: bytes, match_offset: int, match_len: int, window_size: int = 32) -> str:
        """
        Generates a 32-byte window around match_offset.
        - Highlights or aligns with standard 16-byte boundaries.
        - Shows hex dump and printable ASCII.
        """
        payload_len = len(payload)
        if payload_len == 0:
            return "    [Empty Payload]"

        # Calculate window start and end to frame ~32 bytes around the match
        # Try to show up to 8 bytes prior context, and remainder forward
        pre_context = 8
        win_start = max(0, match_offset - pre_context)
        win_end = min(payload_len, win_start + window_size)

        # Adjust window start if near the end of payload
        if (win_end - win_start) < window_size and win_start > 0:
            win_start = max(0, win_end - window_size)

        window_bytes = payload[win_start:win_end]
        match_end = match_offset + match_len

        lines = []
        lines.append(
            f"    {Colors.DIM}Offset     +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C +D +E +F   ASCII Representation{Colors.RESET}"
        )
        lines.append(f"    {Colors.DIM}-----------------------------------------------------------------------------{Colors.RESET}")

        # Chunk into 16-byte aligned lines
        for i in range(0, len(window_bytes), 16):
            chunk = window_bytes[i : i + 16]
            chunk_base = win_start + i
            hex_parts = []
            ascii_parts = []

            for byte_idx, b in enumerate(chunk):
                curr_abs_offset = chunk_base + byte_idx
                is_match_byte = match_offset <= curr_abs_offset < match_end

                b_hex = f"{b:02X}"
                b_char = chr(b) if 32 <= b <= 126 else "."

                if is_match_byte:
                    hex_parts.append(f"{Colors.GREEN}{Colors.BOLD}{b_hex}{Colors.RESET}")
                    ascii_parts.append(f"{Colors.GREEN}{Colors.BOLD}{b_char}{Colors.RESET}")
                else:
                    hex_parts.append(f"{b_hex}")
                    ascii_parts.append(f"{Colors.DIM}{b_char}{Colors.RESET}")

                if byte_idx == 7:
                    hex_parts.append("")  # Mid-line divider

            # Pad hex string if chunk < 16
            pad_count = 16 - len(chunk)
            if pad_count > 0:
                for p in range(pad_count):
                    hex_parts.append("  ")
                    if p + len(chunk) == 7:
                        hex_parts.append("")

            # Assemble hex column
            hex_str_left = " ".join(hex_parts[:8])
            hex_str_right = " ".join(hex_parts[8:])
            hex_col = f"{hex_str_left}  {hex_str_right}".strip()

            ascii_col = "".join(ascii_parts)
            lines.append(
                f"    {Colors.CYAN}0x{chunk_base:04X}{Colors.RESET}   {hex_col:<49} | {ascii_col} |"
            )

        return "\n".join(lines)
