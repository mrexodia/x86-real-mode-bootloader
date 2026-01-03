"""INT 0x12 - Memory Size handler."""

from __future__ import annotations

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int12Handler(BIOSHandler):
    """Handle INT 0x12 - Get Memory Size."""

    def handle(self, uc: Uc) -> None:
        """Return memory size from BDA."""
        emu = self.emu
        self.log("[INT 0x12] Get memory size")

        memory_size_kb = emu.bda.memory_size_kb
        self.log(f"  - Memory size from BDA: {memory_size_kb} KB")

        uc.reg_write(UC_X86_REG_AX, memory_size_kb)
