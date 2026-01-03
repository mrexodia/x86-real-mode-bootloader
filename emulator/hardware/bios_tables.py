"""BIOS memory tables initialization.

This module contains routines that set up BIOS data structures in memory (BDA,
IVT, DPT/FDPT, and BIOS interrupt stubs). Extracted from the original emulator
implementation.

These routines are intentionally conservative: behavior (including memory
layout/addresses) must remain stable because boot code depends on it.
"""

from __future__ import annotations

import ctypes
import struct

from ..hardware.memory import BIOSDataArea
from ..hardware.geometry import DiskParameterTable, FixedDiskParameterTable


def write_ivt_entry(emu, interrupt_number: int, segment: int, offset: int) -> None:
    """Write a far pointer to an IVT (Interrupt Vector Table) entry."""
    ivt_address = interrupt_number * 4
    data = struct.pack('<HH', offset, segment)
    emu.mem_write(ivt_address, data)


def create_bda(emu) -> BIOSDataArea:
    """Create and initialize BIOS Data Area."""
    emu.bda = BIOSDataArea()

    # Zero everything first
    ctypes.memset(ctypes.addressof(emu.bda), 0, ctypes.sizeof(emu.bda))

    # Essential memory configuration
    emu.bda.memory_size_kb = 640

    # Equipment word - minimal configuration
    equipment = 0x0020  # Minimal: video only
    if emu.drive_number < 0x80:
        equipment |= 0x0001  # Bit 0: Floppy drive installed

    emu.bda.equipment_list = equipment

    # Video configuration (80x25 color text mode)
    emu.bda.video_mode = 0x03
    emu.bda.video_columns = 80
    emu.bda.video_page_size = 4096
    emu.bda.video_page_offset = 0
    emu.bda.video_port = 0x3D4
    emu.bda.active_page = 0
    emu.bda.video_rows = 25
    emu.bda.char_height = 8

    # Cursor configuration
    emu.bda.cursor_pos[0] = 0x0000
    emu.bda.cursor_start_line = 6
    emu.bda.cursor_end_line = 7

    # Keyboard buffer (empty)
    emu.bda.kbd_buffer_head = 0x1E
    emu.bda.kbd_buffer_tail = 0x1E
    emu.bda.kbd_buffer_start = 0x1E
    emu.bda.kbd_buffer_end = 0x3E

    # Hard disk configuration
    emu.bda.num_hard_disks = 1 if emu.drive_number >= 0x80 else 0

    # Timer
    emu.bda.timer_counter = 0

    # Reset flag: Cold boot
    emu.bda.reset_flag = 0x0000

    return emu.bda


def write_bda_to_memory(emu) -> None:
    """Write BDA structure to Unicorn memory at 0x400."""
    if not getattr(emu, 'bda', None):
        return

    bda_bytes = bytes(emu.bda)
    assert len(bda_bytes) == 256, f"Invalid BDA size: {len(bda_bytes)}"
    emu.mem_write(0x400, bda_bytes)
    emu.logger.console(f"[*] Initialized BIOS Data Area (BDA) at 0x00400 ({len(bda_bytes)} bytes)")
    emu.logger.console(f"    Equipment: 0x{emu.bda.equipment_list:04X}")
    emu.logger.console(f"    Memory: {emu.bda.memory_size_kb} KB")
    emu.logger.console(f"    Video: Mode {emu.bda.video_mode}, {emu.bda.video_columns}x{emu.bda.video_rows+1}")


def create_int_stubs(emu) -> None:
    """Create INT N; IRET stubs in BIOS ROM area for all 256 interrupts."""
    STUB_BASE = 0xF0000

    for int_num in range(256):
        stub_addr = STUB_BASE + (int_num * 4)
        stub_code = bytes([0xCD, int_num, 0xCF])
        emu.mem_write(stub_addr, stub_code)


def setup_bios_tables(emu) -> None:
    """Initialize BIOS parameter tables and IVT entries."""
    emu.logger.console("[*] Setting up BIOS parameter tables...")

    create_bda(emu)
    write_bda_to_memory(emu)

    create_int_stubs(emu)

    for int_num in range(256):
        stub_offset = int_num * 4
        write_ivt_entry(emu, int_num, 0xF000, stub_offset)

    # Diskette Parameter Table (DPT)
    dpt = DiskParameterTable()
    dpt.step_rate_head_unload = 0xDF
    dpt.head_load_dma = 0x02
    dpt.motor_off_delay = 0x25
    dpt.bytes_per_sector = 0x02
    dpt.sectors_per_track = 0x12
    dpt.gap_length = 0x1B
    dpt.data_length = 0xFF
    dpt.format_gap = 0x6C
    dpt.format_fill = 0xF6
    dpt.head_settle = 0x0F
    dpt.motor_start = 0x08

    if emu.floppy_type or emu.drive_number < 0x80:
        dpt_location = "detected floppy"
    else:
        dpt_location = "default 1.44MB"

    if dpt_location == "detected floppy" and emu.floppy_type is None:
        dpt.sectors_per_track = emu.sectors_per_track

    DPT_ADDR = 0xFEFC7
    emu.mem_write(DPT_ADDR, bytes(dpt))
    write_ivt_entry(emu, 0x1E, 0xF000, 0xEFC7)
    emu.logger.console(f"  - INT 0x1E (DPT): {dpt_location} at 0x{DPT_ADDR:05X}")

    if emu.drive_number >= 0x80:
        fdpt = FixedDiskParameterTable()
        fdpt.cylinders = emu.cylinders
        fdpt.heads = emu.heads
        fdpt.reduced_write_current = 0
        fdpt.write_precomp = 0
        fdpt.ecc_burst = 0
        fdpt.control_byte = 0xC0
        fdpt.timeout_1 = 0
        fdpt.timeout_2 = 0
        fdpt.timeout_3 = 0
        fdpt.landing_zone = emu.cylinders
        fdpt.sectors_per_track = emu.sectors_per_track
        fdpt.reserved = 0

        FDPT_ADDR = 0xFE401
        emu.mem_write(FDPT_ADDR, bytes(fdpt))
        write_ivt_entry(emu, 0x41, 0xF000, 0xE401)
        emu.logger.console(f"  - INT 0x41 (FDPT): Drive 0x{emu.drive_number:02X} at 0x{FDPT_ADDR:05X}")
        emu.logger.console(f"    Geometry: {emu.cylinders}C x {emu.heads}H x {emu.sectors_per_track}S")

        write_ivt_entry(emu, 0x42, 0x0000, 0x0000)
    else:
        write_ivt_entry(emu, 0x41, 0x0000, 0x0000)
        write_ivt_entry(emu, 0x42, 0x0000, 0x0000)

    # Video tables (INT 0x1D, 0x1F, 0x43) - leave as NULL
    write_ivt_entry(emu, 0x1D, 0x0000, 0x0000)
    write_ivt_entry(emu, 0x1F, 0x0000, 0x0000)
    write_ivt_entry(emu, 0x43, 0x0000, 0x0000)
