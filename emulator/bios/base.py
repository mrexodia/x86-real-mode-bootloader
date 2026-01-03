"""Base class for BIOS interrupt handlers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

if TYPE_CHECKING:
    from typing import Any
    from ..logging import EmulatorLogger


class BIOSHandler(ABC):
    """Abstract base class for BIOS interrupt handlers."""

    def __init__(self, emulator: Any):
        """Initialize the handler with a reference to the emulator."""
        self.emu = emulator

    @property
    def logger(self) -> "EmulatorLogger":
        """Get the logger from the emulator."""
        return self.emu.logger

    def log(self, msg: str) -> None:
        """Log a message to the interrupt log."""
        self.logger.interrupt(msg)

    @abstractmethod
    def handle(self, uc: Uc) -> None:
        """Handle the interrupt.
        
        Args:
            uc: Unicorn engine instance.
        """
        pass

    def clear_carry(self, uc: Uc) -> None:
        """Clear the carry flag (success)."""
        flags = uc.reg_read(UC_X86_REG_EFLAGS)
        uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

    def set_carry(self, uc: Uc) -> None:
        """Set the carry flag (error)."""
        flags = uc.reg_read(UC_X86_REG_EFLAGS)
        uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

    def set_zero(self, uc: Uc) -> None:
        """Set the zero flag."""
        flags = uc.reg_read(UC_X86_REG_EFLAGS)
        uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0040)

    def clear_zero(self, uc: Uc) -> None:
        """Clear the zero flag."""
        flags = uc.reg_read(UC_X86_REG_EFLAGS)
        uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0040)
