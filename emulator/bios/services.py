"""BIOS interrupt services (modular implementation).

This file contains the BIOS interrupt routing logic. Each interrupt handler
is now in its own module for maintainability.
"""

from __future__ import annotations

from typing import Any

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from ..hardware.ivt import IVT_NAMES

from .int10 import Int10Handler
from .int11 import Int11Handler
from .int12 import Int12Handler
from .int13 import Int13Handler
from .int14 import Int14Handler
from .int15 import Int15Handler
from .int16 import Int16Handler
from .int17 import Int17Handler
from .int1a import Int1AHandler


class BIOSServices:
    """Implements BIOS interrupt services used by the emulator."""

    def __init__(self, emulator: Any):
        # We keep a loose type here to avoid circular imports.
        self.emu = emulator

        # Initialize all handlers
        self._handlers = {
            0x10: Int10Handler(emulator),
            0x11: Int11Handler(emulator),
            0x12: Int12Handler(emulator),
            0x13: Int13Handler(emulator),
            0x14: Int14Handler(emulator),
            0x15: Int15Handler(emulator),
            0x16: Int16Handler(emulator),
            0x17: Int17Handler(emulator),
            0x1A: Int1AHandler(emulator),
        }

    def handle_bios_interrupt(self, uc: Uc, intno: int):
        """Route interrupt to appropriate BIOS service handler."""
        emu = self.emu
        print(f"[*] Handling BIOS interrupt 0x{intno:02X} -> {IVT_NAMES.get(intno, 'Unknown')}")
        self._dump_registers(uc, intno, "BEFORE")

        handler = self._handlers.get(intno)
        if handler:
            handler.handle(uc)
        else:
            # Unhandled BIOS interrupt
            ip = uc.reg_read(UC_X86_REG_IP)
            if emu.verbose:
                print(f"[INT] Unhandled BIOS interrupt 0x{intno:02X} at 0x{ip:04X}")
            uc.emu_stop()

        self._dump_registers(uc, intno, "AFTER")

    def _dump_registers(self, uc: Uc, intno: int, label: str):
        """Dump register state for debugging."""
        ax = uc.reg_read(UC_X86_REG_AX)
        bx = uc.reg_read(UC_X86_REG_BX)
        cx = uc.reg_read(UC_X86_REG_CX)
        dx = uc.reg_read(UC_X86_REG_DX)
        si = uc.reg_read(UC_X86_REG_SI)
        di = uc.reg_read(UC_X86_REG_DI)
        bp = uc.reg_read(UC_X86_REG_BP)
        sp = uc.reg_read(UC_X86_REG_SP)
        cs = uc.reg_read(UC_X86_REG_CS)
        ds = uc.reg_read(UC_X86_REG_DS)
        es = uc.reg_read(UC_X86_REG_ES)
        ss = uc.reg_read(UC_X86_REG_SS)
        flags = uc.reg_read(UC_X86_REG_EFLAGS)
        cf = (flags >> 0) & 1
        zf = (flags >> 6) & 1
        print(
            f"[DEBUG] INT 0x{intno:02X} {label}: ax={ax:04x} bx={bx:04x} cx={cx:04x} dx={dx:04x} "
            f"si={si:04x} di={di:04x} bp={bp:04x} sp={sp:04x} cs={cs:04x} ds={ds:04x} "
            f"ss={ss:04x} es={es:04x} flags={flags:04x} cf={cf} zf={zf}"
        )

    def hook_interrupt(self, uc: Uc, intno, _user_data):
        """Hook called before INT instruction executes."""
        emu = self.emu

        # Read current CS:IP
        # NOTE: Unicorn has already advanced IP past the INT instruction (2 bytes)
        # So the actual INT location is IP - 2
        cs = uc.reg_read(UC_X86_REG_CS)
        ip = uc.reg_read(UC_X86_REG_IP)
        int_location_ip = ip - 2  # Where the INT actually is

        # Calculate physical address of INT instruction
        physical_addr = (cs << 4) + int_location_ip

        # BIOS stub range: 0xF0000 - 0xF0400 (256 interrupts * 4 bytes each = 1024 bytes)
        STUB_BASE = 0xF0000
        STUB_END = 0xF0400

        # Read IVT entry for this interrupt
        ivt_addr = intno * 4
        ivt_offset = int.from_bytes(uc.mem_read(ivt_addr, 2), 'little')
        ivt_segment = int.from_bytes(uc.mem_read(ivt_addr + 2, 2), 'little')

        # Check if we're executing from BIOS stub region
        # If so, always handle in Python regardless of IVT contents
        if STUB_BASE <= physical_addr < STUB_END:
            # Executing from BIOS stub - handle in Python
            self.handle_bios_interrupt(uc, intno)
            # IP is already advanced past the INT, so we're good
        else:
            # Not from stub - manually push interrupt frame and jump to IVT handler
            # NOTE: IP has already been advanced past the INT instruction by Unicorn
            sp = uc.reg_read(UC_X86_REG_SP)
            ss = uc.reg_read(UC_X86_REG_SS)
            flags = uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF

            # Push FLAGS, CS, IP (return address points AFTER INT instruction)
            # IP is already pointing after the INT, so just push it as-is
            sp -= 2
            emu.mem_write(ss * 16 + sp, flags.to_bytes(2, 'little'))
            sp -= 2
            emu.mem_write(ss * 16 + sp, cs.to_bytes(2, 'little'))
            sp -= 2
            emu.mem_write(ss * 16 + sp, ip.to_bytes(2, 'little'))

            uc.reg_write(UC_X86_REG_SP, sp)

            # Jump to IVT handler
            uc.reg_write(UC_X86_REG_CS, ivt_segment)
            uc.reg_write(UC_X86_REG_IP, ivt_offset)
