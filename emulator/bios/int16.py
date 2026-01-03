"""INT 0x16 - Keyboard Services handler."""

from __future__ import annotations

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int16Handler(BIOSHandler):
    """Handle INT 0x16 - Keyboard Services."""

    def handle(self, uc: Uc) -> None:
        """Route to appropriate keyboard service function."""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x00:
            self._read_keystroke(uc)
        elif ah == 0x01:
            self._check_keystroke(uc)
        elif ah == 0x02:
            self._get_shift_flags(uc)
        else:
            if self.emu.verbose:
                print(f"[INT 0x16] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def _read_keystroke(self, uc: Uc) -> None:
        """AH=0x00: Read keystroke."""
        if self.emu.verbose:
            print("[INT 0x16] Read keystroke")
        uc.reg_write(UC_X86_REG_AX, 0x1C0D)  # AL=0x0D (Enter), AH=0x1C (scan code)

    def _check_keystroke(self, uc: Uc) -> None:
        """AH=0x01: Check for keystroke."""
        if self.emu.verbose:
            print("[INT 0x16] Check for keystroke")
        self.set_zero(uc)  # ZF=1 means no key available

    def _get_shift_flags(self, uc: Uc) -> None:
        """AH=0x02: Get shift flags."""
        if self.emu.verbose:
            print("[INT 0x16] Get shift flags")
        uc.reg_write(UC_X86_REG_AX, 0)  # No shift keys pressed
