"""INT 0x17 - Printer Services handler."""

from __future__ import annotations

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int17Handler(BIOSHandler):
    """Handle INT 0x17 - Printer Services (return offline status)."""

    # Offline status - printer not ready/not selected
    OFFLINE_STATUS = 0x00

    def handle(self, uc: Uc) -> None:
        """Route to appropriate printer service function."""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dx = uc.reg_read(UC_X86_REG_DX) & 0xFF  # DL = printer number

        if ah == 0x00:
            self._print_character(uc, dx)
        elif ah == 0x01:
            self._initialize_printer(uc, dx)
        elif ah == 0x02:
            self._get_status(uc, dx)
        else:
            if self.emu.verbose:
                print(f"[INT 0x17] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def _print_character(self, uc: Uc, printer: int) -> None:
        """AH=0x00: Print character."""
        if self.emu.verbose:
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            print(f"[INT 0x17] Print character 0x{al:02X} to printer {printer} (OFFLINE)")
        uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | (self.OFFLINE_STATUS << 8))
        self.set_carry(uc)

    def _initialize_printer(self, uc: Uc, printer: int) -> None:
        """AH=0x01: Initialize printer."""
        if self.emu.verbose:
            print(f"[INT 0x17] Initialize printer {printer} (OFFLINE)")
        uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | (self.OFFLINE_STATUS << 8))
        self.set_carry(uc)

    def _get_status(self, uc: Uc, printer: int) -> None:
        """AH=0x02: Get printer status."""
        if self.emu.verbose:
            print(f"[INT 0x17] Get printer status for printer {printer} (OFFLINE)")
        uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | (self.OFFLINE_STATUS << 8))
        self.set_carry(uc)
