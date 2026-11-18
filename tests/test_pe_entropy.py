"""
Unit tests for GhostByteSec PE Entropy Analyzer.

No real malware is used. The integration test builds a tiny, harmless,
non-runnable PE-shaped file in a temporary folder.
"""

import contextlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pe_entropy  # noqa: E402


def build_minimal_pe(sections):
    """
    Build a minimal 32-bit PE image for testing.

    `sections` is a list of (name_bytes, data_bytes). The result is only
    meant to be parsed by pefile. It is not a runnable program.
    """
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x40)  # e_lfanew

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,          # Machine: i386
        len(sections),   # NumberOfSections
        0, 0, 0,         # timestamp, symbol table, symbol count
        224,             # SizeOfOptionalHeader (PE32)
        0x0102,          # Characteristics
    )

    optional = bytearray(224)
    struct.pack_into("<H", optional, 0, 0x10B)               # Magic PE32
    struct.pack_into("<I", optional, 32, section_alignment)  # SectionAlignment
    struct.pack_into("<I", optional, 36, file_alignment)     # FileAlignment
    struct.pack_into("<I", optional, 56,
                     section_alignment * (len(sections) + 1))  # SizeOfImage
    struct.pack_into("<I", optional, 60, headers_size)       # SizeOfHeaders
    struct.pack_into("<I", optional, 92, 16)                 # NumberOfRvaAndSizes

    table = bytearray()
    body = bytearray()
    raw_offset = headers_size
    for index, (name, data) in enumerate(sections):
        padded = data + b"\x00" * (-len(data) % file_alignment)
        table += struct.pack(
            "<8sIIIIIIHHI",
            name.ljust(8, b"\x00"),
            len(data),                                # VirtualSize
            section_alignment * (index + 1),          # VirtualAddress
            len(padded),                              # SizeOfRawData
            raw_offset,                               # PointerToRawData
            0, 0, 0, 0,
            0x60000020,
        )
        body += padded
        raw_offset += len(padded)

    header_block = (
        bytes(dos_header) + b"PE\x00\x00" + coff + bytes(optional) + bytes(table)
    )
    header_block += b"\x00" * (headers_size - len(header_block))
    return header_block + bytes(body)


class ClassifyEntropyTests(unittest.TestCase):
    def test_below_threshold_is_normal(self):
        self.assertEqual(pe_entropy.classify_entropy(6.99), "NORMAL RANGE")

    def test_zero_entropy_is_normal(self):
        self.assertEqual(pe_entropy.classify_entropy(0.0), "NORMAL RANGE")

    def test_exactly_threshold_is_investigate(self):
        self.assertEqual(pe_entropy.classify_entropy(7.0), "INVESTIGATE")

    def test_above_threshold_is_investigate(self):
        self.assertEqual(pe_entropy.classify_entropy(7.5), "INVESTIGATE")

    def test_maximum_entropy_is_investigate(self):
        self.assertEqual(pe_entropy.classify_entropy(8.0), "INVESTIGATE")

    def test_threshold_constant_is_seven(self):
        self.assertEqual(pe_entropy.HIGH_ENTROPY_THRESHOLD, 7.0)


class DecodeSectionNameTests(unittest.TestCase):
    def test_strips_nul_padding(self):
        self.assertEqual(pe_entropy.decode_section_name(b".text\x00\x00\x00"), ".text")

    def test_full_length_name(self):
        self.assertEqual(pe_entropy.decode_section_name(b"abcdefgh"), "abcdefgh")

    def test_invalid_bytes_do_not_crash(self):
        result = pe_entropy.decode_section_name(b"\xff\xfe\x00\x00\x00\x00\x00\x00")
        self.assertIsInstance(result, str)


class AnalyzePeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, content):
        path = Path(self.tmp.name) / name
        path.write_bytes(content)
        return path

    def test_reports_low_and_high_entropy_sections(self):
        low = b"A" * 1024                  # entropy 0.0
        high = bytes(range(256)) * 4       # entropy 8.0
        path = self.write(
            "sample.bin", build_minimal_pe([(b".text", low), (b".packed", high)])
        )

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            pe_entropy.analyze_pe(path)
        output = buffer.getvalue()

        self.assertIn(".text", output)
        self.assertIn(".packed", output)
        self.assertIn("NORMAL RANGE", output)
        self.assertIn("INVESTIGATE", output)
        self.assertIn("clue, not proof", output)

    def test_non_pe_file_exits_with_error(self):
        path = self.write("notpe.txt", b"this is not a PE file")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with self.assertRaises(SystemExit) as ctx:
                pe_entropy.analyze_pe(path)
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("Invalid or unsupported PE file", buffer.getvalue())

    def test_missing_file_exits_with_error(self):
        path = Path(self.tmp.name) / "does-not-exist.exe"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with self.assertRaises(SystemExit) as ctx:
                pe_entropy.analyze_pe(path)
        self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
