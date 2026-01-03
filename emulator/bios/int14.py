"""INT 0x14 - Serial Port Services handler."""

from __future__ import annotations

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int14Handler(BIOSHandler):
    """Handle INT 0x14 - Serial Port Services."""

    def handle(self, uc: Uc) -> None:
        """Route to appropriate serial port service function."""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dx = uc.reg_read(UC_X86_REG_DX) & 0xFF  # DL = port number

        if ah == 0x00:
            self._initialize_port(uc, dx)
        elif ah == 0x01:
            self._write_character(uc, dx)
        elif ah == 0x02:
            self._read_character(uc, dx)
        elif ah == 0x03:
            self._get_status(uc, dx)
        else:
            self.log(f"[INT 0x14] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def _initialize_port(self, uc: Uc, port: int) -> None:
        """AH=0x00: Initialize serial port."""
        self.log(f"[INT 0x14] Initialize serial port DL=0x{port:02X}")
        uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | 0x2000)
        self.clear_carry(uc)

    def _write_character(self, uc: Uc, port: int) -> None:
        """AH=0x01: Write character to serial port."""
        al = uc.reg_read(UC_X86_REG_AX) & 0xFF
        self.log(
            f"[INT 0x14] Write character to serial port: 0x{al:02X} "
            f"({chr(al) if 32 <= al < 127 else '?'})"
        )
        uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | 0x0000)
        self.clear_carry(uc)

    def _read_character(self, uc: Uc, port: int) -> None:
        """AH=0x02: Read character from serial port."""
        self.log("[INT 0x14] Read character from serial port")
        uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | 0x8000)
        self.set_carry(uc)

    def _get_status(self, uc: Uc, port: int) -> None:
        """AH=0x03: Get serial port status."""
        self.log("[INT 0x14] Get serial port status")
        uc.reg_write(UC_X86_REG_AX, 0x6000)
        self.clear_carry(uc)
