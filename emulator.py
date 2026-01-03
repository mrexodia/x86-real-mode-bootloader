#!/usr/bin/env python3
"""
x86 Real Mode Bootloader Emulator using Unicorn Engine and Capstone

This emulator loads a disk image and emulates the bootloader from the first 512 bytes,
logging every instruction execution with relevant registers and memory accesses.
"""

import sys
import argparse
from pathlib import Path

from bootemu import BootloaderEmulator


def main():
    parser = argparse.ArgumentParser(
        description="Emulate x86 real mode bootloader with instruction tracing"
    )
    parser.add_argument(
        "disk_image",
        type=str,
        help="Path to disk image file (bootloader loaded from first 512 bytes)",
    )
    parser.add_argument(
        "-m",
        "--max-instructions",
        type=int,
        default=1000000,
        help="Maximum number of instructions to execute (default: 1000000)",
    )
    parser.add_argument(
        "-g",
        "--geometry",
        type=str,
        metavar="C,H,S",
        help="Manual CHS geometry (cylinders,heads,sectors) e.g., 120,16,63",
    )
    parser.add_argument(
        "-f",
        "--floppy-type",
        type=str,
        choices=["360K", "720K", "1.2M", "1.44M", "2.88M"],
        help="Standard floppy disk type (implies --drive-number 0x00)",
    )
    parser.add_argument(
        "-d",
        "--drive-number",
        type=str,
        default="0x80",
        help="BIOS drive number (default: 0x80 for HDD, use 0x00 for floppy)",
    )

    args = parser.parse_args()

    # Check if disk image exists
    if not Path(args.disk_image).exists():
        print(f"Error: Disk image not found: {args.disk_image}")
        sys.exit(1)

    # Parse geometry if provided
    geometry: tuple[int, int, int] | None = None
    if args.geometry:
        try:
            parts = args.geometry.split(",")
            if len(parts) != 3:
                raise ValueError("Geometry must be in format C,H,S")
            geometry = tuple(int(p.strip()) for p in parts)  # type: ignore
        except ValueError as e:
            print(f"Error: Invalid geometry format: {e}")
            sys.exit(1)

    # Parse drive number
    try:
        drive_number = int(args.drive_number, 0)  # Supports 0x prefix
        if args.floppy_type and drive_number >= 0x80:
            drive_number = 0x00  # Override to floppy if floppy type specified
    except ValueError:
        print(f"Error: Invalid drive number: {args.drive_number}")
        sys.exit(1)

    # Create and run emulator
    emulator = BootloaderEmulator(
        disk_image_path=args.disk_image,
        max_instructions=args.max_instructions,
        geometry=geometry,
        floppy_type=args.floppy_type,
        drive_number=drive_number,
    )

    emulator.setup_cpu_state()
    emulator.run()


if __name__ == "__main__":
    main()
