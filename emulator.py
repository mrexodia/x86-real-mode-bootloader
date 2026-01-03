#!/usr/bin/env python3
"""
x86 Real Mode Bootloader Emulator using Unicorn Engine and Capstone

This emulator loads a disk image and emulates the bootloader from the first 512 bytes,
logging every instruction execution with relevant registers and memory accesses.

This is a compatibility wrapper that imports from the modular structure.
"""

from emulator.main import main

if __name__ == '__main__':
    main()