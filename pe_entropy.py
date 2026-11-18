#!/usr/bin/env python3

"""
GhostByteSec - PE Entropy Analyzer
Static analysis of Windows PE sections.
Never executes the analyzed file.
"""

import argparse
import sys
from pathlib import Path

import pefile

__version__ = "1.0.0"

# Shannon entropy ranges from 0.0 to 8.0 bits per byte.
# Sections at or above this value are flagged for a closer look.
HIGH_ENTROPY_THRESHOLD = 7.0

LINE_WIDTH = 65


def classify_entropy(entropy):
    """Return the status label for a section's entropy score."""
    if entropy >= HIGH_ENTROPY_THRESHOLD:
        return "INVESTIGATE"
    return "NORMAL RANGE"


def decode_section_name(raw_name):
    """Turn the 8-byte, NUL-padded section name into a readable string."""
    return raw_name.rstrip(b"\x00").decode("utf-8", errors="replace")


def print_banner(file_path):
    print("\n" + "=" * LINE_WIDTH)
    print("       GHOSTBYTESEC - PE ENTROPY ANALYZER")
    print("=" * LINE_WIDTH)

    print(f"\n[+] File: {file_path.name}")
    print("[+] Analysis: Static PE section inspection")
    print("\n" + "-" * LINE_WIDTH)

    print(f"{'SECTION':<12}{'RAW SIZE':>12}{'ENTROPY':>12}   STATUS")
    print("-" * LINE_WIDTH)


def analyze_pe(file_path):
    pe = None

    try:
        # pefile only PARSES the file's bytes. The file is never executed.
        # fast_load=True skips parsing the data directories (imports,
        # exports, resources), which we do not need for section entropy.
        pe = pefile.PE(str(file_path), fast_load=True)

        print_banner(file_path)

        # Each entry in pe.sections is one row of the PE section table.
        for section in pe.sections:
            name = decode_section_name(section.Name)

            # Entropy is computed over the section's raw bytes on disk.
            entropy = section.get_entropy()

            # SizeOfRawData is the section's size inside the file.
            raw_size = section.SizeOfRawData

            status = classify_entropy(entropy)

            print(
                f"{name:<12}"
                f"{raw_size:>12}"
                f"{entropy:>12.2f}   "
                f"{status}"
            )

        print("-" * LINE_WIDTH)
        print("\n[+] Analysis completed.")
        print("[!] High entropy is a clue, not proof of malware.")

    except pefile.PEFormatError:
        print("[-] Invalid or unsupported PE file.")
        sys.exit(1)

    except OSError as error:
        print(f"[-] File error: {error}")
        sys.exit(1)

    finally:
        # Always release the file handle / memory map held by pefile.
        if pe is not None:
            pe.close()


def main():
    parser = argparse.ArgumentParser(
        description="GhostByteSec PE Entropy Analyzer"
    )

    parser.add_argument(
        "file",
        type=Path,
        help="Path to a Windows EXE or DLL"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args()

    if not args.file.is_file():
        parser.error(f"File not found: {args.file}")

    analyze_pe(args.file)


if __name__ == "__main__":
    main()
