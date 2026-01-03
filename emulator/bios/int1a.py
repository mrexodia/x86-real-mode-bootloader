"""INT 0x1A - Timer/Clock Services handler."""

from __future__ import annotations

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int1AHandler(BIOSHandler):
    """Handle INT 0x1A - Timer/Clock Services."""

    def handle(self, uc: Uc) -> None:
        """Route to appropriate timer/clock service function."""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x00:
            self._get_system_time(uc)
        elif ah == 0x01:
            self._set_system_time(uc)
        elif ah == 0x02:
            self._get_rtc_time(uc)
        elif ah == 0x03:
            self._set_rtc_time(uc)
        elif ah == 0x04:
            self._get_rtc_date(uc)
        elif ah == 0x05:
            self._set_rtc_date(uc)
        elif ah == 0x06:
            self._set_rtc_alarm(uc)
        elif ah == 0x07:
            self._reset_rtc_alarm(uc)
        else:
            self.log(f"[INT 0x1A] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def _get_system_time(self, uc: Uc) -> None:
        """AH=0x00: Get system time."""
        self.log("[INT 0x1A] Get system time")
        ticks = 65536 * 2  # ~2 hours worth of ticks
        cx = (ticks >> 16) & 0xFFFF
        dx = ticks & 0xFFFF
        ax = uc.reg_read(UC_X86_REG_AX) & 0xFF
        uc.reg_write(UC_X86_REG_AX, ax)
        uc.reg_write(UC_X86_REG_CX, cx)
        uc.reg_write(UC_X86_REG_DX, dx)
        self.clear_carry(uc)

    def _set_system_time(self, uc: Uc) -> None:
        """AH=0x01: Set system time."""
        cx = uc.reg_read(UC_X86_REG_CX)
        dx = uc.reg_read(UC_X86_REG_DX)
        self.log(f"[INT 0x1A] Set system time CX:DX=0x{cx:04X}:0x{dx:04X}")
        self.clear_carry(uc)

    def _get_rtc_time(self, uc: Uc) -> None:
        """AH=0x02: Get RTC time."""
        self.log("[INT 0x1A] Get RTC time")
        hours_bcd = 0x08
        minutes_bcd = 0x30
        seconds_bcd = 0x45
        dst_flag = 0x00
        uc.reg_write(UC_X86_REG_CX, (hours_bcd << 8) | minutes_bcd)
        uc.reg_write(UC_X86_REG_DX, (seconds_bcd << 8) | dst_flag)
        self.clear_carry(uc)

    def _set_rtc_time(self, uc: Uc) -> None:
        """AH=0x03: Set RTC time."""
        cx = uc.reg_read(UC_X86_REG_CX)
        dx = uc.reg_read(UC_X86_REG_DX)
        self.log(f"[INT 0x1A] Set RTC time CX=0x{cx:04X}, DX=0x{dx:04X}")
        self.clear_carry(uc)

    def _get_rtc_date(self, uc: Uc) -> None:
        """AH=0x04: Get RTC date."""
        self.log("[INT 0x1A] Get RTC date")
        year_bcd = 0x1990
        month_bcd = 0x01
        day_bcd = 0x15
        uc.reg_write(UC_X86_REG_CX, year_bcd)
        uc.reg_write(UC_X86_REG_DX, (month_bcd << 8) | day_bcd)
        self.clear_carry(uc)

    def _set_rtc_date(self, uc: Uc) -> None:
        """AH=0x05: Set RTC date."""
        cx = uc.reg_read(UC_X86_REG_CX)
        dx = uc.reg_read(UC_X86_REG_DX)
        self.log(f"[INT 0x1A] Set RTC date CX=0x{cx:04X}, DX=0x{dx:04X}")
        self.clear_carry(uc)

    def _set_rtc_alarm(self, uc: Uc) -> None:
        """AH=0x06: Set RTC alarm."""
        self.log("[INT 0x1A] Set RTC alarm")
        self.clear_carry(uc)

    def _reset_rtc_alarm(self, uc: Uc) -> None:
        """AH=0x07: Reset RTC alarm."""
        self.log("[INT 0x1A] Reset RTC alarm")
        self.clear_carry(uc)
