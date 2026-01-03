"""INT 0x15 - System Services handler."""

from __future__ import annotations

import struct

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int15Handler(BIOSHandler):
    """Handle INT 0x15 - System Services."""

    def handle(self, uc: Uc) -> None:
        """Route to appropriate system service function."""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x88:
            self._get_extended_memory(uc)
        elif ah == 0xC0:
            self._get_system_config(uc)
        elif ah == 0xE8:
            self._handle_e8_subfunction(uc)
        elif ah == 0x41:
            self._wait_external_event(uc)
        elif ah == 0x53:
            self._apm_function(uc)
        else:
            if self.emu.verbose:
                print(f"[INT 0x15] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def _get_extended_memory(self, uc: Uc) -> None:
        """AH=0x88: Get extended memory size."""
        if self.emu.verbose:
            print("[INT 0x15] Get extended memory size")
        # AX = extended memory in KB (above 1MB)
        uc.reg_write(UC_X86_REG_AX, 0)  # No extended memory
        self.clear_carry(uc)

    def _get_system_config(self, uc: Uc) -> None:
        """AH=0xC0: Get system configuration."""
        if self.emu.verbose:
            print("[INT 0x15] Get system configuration")
        # For now, return error
        self.set_carry(uc)

    def _handle_e8_subfunction(self, uc: Uc) -> None:
        """AH=0xE8: Handle E8 subfunctions."""
        al = uc.reg_read(UC_X86_REG_AX) & 0xFF
        if al == 0x20:
            self._e820_memory_map(uc)
        else:
            if self.emu.verbose:
                print(f"[INT 0x15] Unhandled E8h subfunction AL=0x{al:02X}")
            self.set_carry(uc)

    def _e820_memory_map(self, uc: Uc) -> None:
        """E820h: Query System Address Map."""
        emu = self.emu
        edx = uc.reg_read(UC_X86_REG_EDX)
        ebx = uc.reg_read(UC_X86_REG_EBX)
        es = uc.reg_read(UC_X86_REG_ES)
        di = uc.reg_read(UC_X86_REG_DI)

        # Check for SMAP signature
        if edx != 0x534D4150:  # 'SMAP'
            if emu.verbose:
                print(f"[INT 0x15, E820] Invalid signature: 0x{edx:08X}")
            self.set_carry(uc)
            return

        # Memory map entries
        memory_map = [
            (0x00000000, 0x00000000, 0x0009FC00, 0x00000000, 1),
            (0x0009FC00, 0x00000000, 0x00000400, 0x00000000, 2),
            (0x000A0000, 0x00000000, 0x00060000, 0x00000000, 2),
            (0x00100000, 0x00000000, 0x00F00000, 0x00000000, 1),
        ]

        # EBX is the continuation value (entry index)
        entry_index = ebx & 0xFFFF

        if entry_index >= len(memory_map):
            # No more entries
            if emu.verbose:
                print(f"[INT 0x15, E820] No more entries (index={entry_index})")
            self.set_carry(uc)
            return

        base_low, base_high, length_low, length_high, mem_type = memory_map[entry_index]

        if emu.verbose:
            print(
                f"[INT 0x15, E820] Entry {entry_index}: base=0x{base_high:08X}{base_low:08X}, "
                f"length=0x{length_high:08X}{length_low:08X}, type={mem_type}"
            )

        # Write entry to ES:DI
        addr = (es << 4) + di
        entry_data = struct.pack('<IIIII', base_low, base_high, length_low, length_high, mem_type)
        uc.mem_write(addr, entry_data)

        # Set return values
        uc.reg_write(UC_X86_REG_EAX, 0x534D4150)  # 'SMAP' signature
        uc.reg_write(UC_X86_REG_ECX, 20)  # Bytes written

        # Set EBX for next entry (0 if this was the last)
        next_index = entry_index + 1
        if next_index >= len(memory_map):
            uc.reg_write(UC_X86_REG_EBX, 0)  # Last entry
        else:
            uc.reg_write(UC_X86_REG_EBX, next_index)

        # Clear CF to indicate success
        self.clear_carry(uc)

    def _wait_external_event(self, uc: Uc) -> None:
        """AH=0x41: Wait on external event (unsupported)."""
        if self.emu.verbose:
            print("[INT 0x15] Wait on external event (unsupported)")
        self.set_carry(uc)

    def _apm_function(self, uc: Uc) -> None:
        """AH=0x53: APM BIOS function."""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        if self.emu.verbose:
            print(f"[INT 0x15] APM BIOS function AH=0x{ah:02X}")
        self.set_carry(uc)
