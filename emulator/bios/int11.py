"""INT 0x11 - Equipment List handler."""

from __future__ import annotations

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int11Handler(BIOSHandler):
    """Handle INT 0x11 - Get Equipment List."""

    def handle(self, uc: Uc) -> None:
        """Return equipment list from BDA."""
        emu = self.emu
        if emu.verbose:
            print("[INT 0x11] Get equipment list")
        # AX = equipment list word

        equipment = emu.bda.equipment_list
        if emu.verbose:
            print(f"  - Equipment from BDA: 0x{equipment:04X}")

        uc.reg_write(UC_X86_REG_AX, equipment)
