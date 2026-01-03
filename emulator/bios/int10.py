"""INT 0x10 - Video Services handler."""

from __future__ import annotations

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int10Handler(BIOSHandler):
    """Handle INT 0x10 - Video Services."""

    def handle(self, uc: Uc) -> None:
        """Route to appropriate video service function."""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x00:
            self._set_video_mode(uc)
        elif ah == 0x02:
            self._set_cursor_position(uc)
        elif ah == 0x03:
            self._get_cursor_position(uc)
        elif ah == 0x0E:
            self._teletype_output(uc)
        elif ah == 0x0F:
            self._get_video_mode(uc)
        elif ah == 0x1A:
            self._get_display_combination_code(uc)
        elif ah == 0x1B:
            self._get_functionality_state(uc)
        else:
            if self.emu.verbose:
                print(f"[INT 0x10] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def _set_video_mode(self, uc: Uc) -> None:
        """AH=0x00: Set video mode."""
        emu = self.emu
        al = uc.reg_read(UC_X86_REG_AX) & 0xFF
        if emu.verbose:
            print(f"[INT 0x10] Set video mode: 0x{al:02X}")

        # Update BDA video mode field (0x0449)
        if emu.bda:
            emu.bda.video_mode = al
            # Also update some typical values for text mode
            if al == 0x03:  # 80x25 text mode (most common)
                emu.bda.video_columns = 80
                emu.bda.video_rows = 24  # rows minus 1
                emu.bda.video_page_size = 4000  # 80*25*2 bytes
            elif al == 0x07:  # Monochrome text
                emu.bda.video_columns = 80
                emu.bda.video_rows = 24
                emu.bda.video_page_size = 4000
            # Write updated BDA to memory
            emu.write_bda_to_memory()

    def _set_cursor_position(self, uc: Uc) -> None:
        """AH=0x02: Set cursor position."""
        emu = self.emu
        bh = (uc.reg_read(UC_X86_REG_BX) >> 8) & 0xFF  # Page number
        dh = (uc.reg_read(UC_X86_REG_DX) >> 8) & 0xFF  # Row
        dl = uc.reg_read(UC_X86_REG_DX) & 0xFF  # Column

        if emu.verbose:
            print(f"[INT 0x10] Set cursor position: page={bh}, row={dh}, col={dl}")

        # Update cursor position in BDA (0x0450 + page*2)
        if emu.bda and bh < 8:  # Only 8 pages
            # Cursor position is stored as (row << 8) | col
            emu.bda.cursor_pos[bh] = (dh << 8) | dl
            # Write updated BDA to memory
            emu.write_bda_to_memory()

    def _get_cursor_position(self, uc: Uc) -> None:
        """AH=0x03: Get cursor position and shape."""
        emu = self.emu
        bh = (uc.reg_read(UC_X86_REG_BX) >> 8) & 0xFF  # Page number

        if emu.verbose:
            print(f"[INT 0x10] Get cursor position: page={bh}")

        # Read cursor position from BDA
        if emu.bda and bh < 8:
            cursor_pos = emu.bda.cursor_pos[bh]
            row = (cursor_pos >> 8) & 0xFF
            col = cursor_pos & 0xFF
            cursor_shape = emu.bda.cursor_shape

            # Return in DX (DH=row, DL=column) and CX (cursor shape)
            uc.reg_write(UC_X86_REG_DX, (row << 8) | col)
            uc.reg_write(UC_X86_REG_CX, cursor_shape)

            if emu.verbose:
                print(f"  - Returning: row={row}, col={col}, shape=0x{cursor_shape:04X}")
        else:
            # Default if BDA not available
            uc.reg_write(UC_X86_REG_DX, 0x0000)
            uc.reg_write(UC_X86_REG_CX, 0x0607)  # Default cursor shape

    def _teletype_output(self, uc: Uc) -> None:
        """AH=0x0E: Teletype output."""
        emu = self.emu
        al = uc.reg_read(UC_X86_REG_AX) & 0xFF
        if al == 0x0D:
            char = "\r"
        elif al == 0x0A:
            char = "\n"
        else:
            char = chr(al) if 32 <= al < 127 else f"\\x{al:02x}"
        if emu.verbose:
            print(f"[INT 0x10] Teletype output: {repr(char)}")
            emu.screen_output += char

    def _get_video_mode(self, uc: Uc) -> None:
        """AH=0x0F: Get current video mode."""
        emu = self.emu
        if emu.verbose:
            print("[INT 0x10] Get current video mode")

        # Read from BDA
        if emu.bda:
            video_mode = emu.bda.video_mode
            video_columns = emu.bda.video_columns
            active_page = emu.bda.active_page
        else:
            # Defaults if BDA not available
            video_mode = 0x03  # 80x25 color text
            video_columns = 80
            active_page = 0

        # Return: AL=mode, AH=columns, BH=active page
        uc.reg_write(UC_X86_REG_AX, (video_columns << 8) | video_mode)
        uc.reg_write(UC_X86_REG_BX, (uc.reg_read(UC_X86_REG_BX) & 0x00FF) | (active_page << 8))

        if emu.verbose:
            print(f"  - Returning: mode=0x{video_mode:02X}, columns={video_columns}, page={active_page}")

    def _get_display_combination_code(self, uc: Uc) -> None:
        """AH=0x1A: Get Display Combination Code."""
        emu = self.emu
        al = uc.reg_read(UC_X86_REG_AX) & 0xFF
        if emu.verbose:
            print(f"[INT 0x10] Get Display Combination Code: AL=0x{al:02X}")

        # Return: AL=0x1A (function supported), BL=display combination code
        # Display combination code 0x08 = VGA with color display
        uc.reg_write(UC_X86_REG_AX, 0x1A00)
        uc.reg_write(UC_X86_REG_BX, (uc.reg_read(UC_X86_REG_BX) & 0xFF00) | 0x08)

        # Clear CF (success)
        self.clear_carry(uc)

        if emu.verbose:
            print("  - Returning: AL=0x1A, BL=0x08 (VGA color)")

    def _get_functionality_state(self, uc: Uc) -> None:
        """AH=0x1B: Get Functionality/State Information."""
        emu = self.emu
        al = uc.reg_read(UC_X86_REG_AX) & 0xFF
        bx = uc.reg_read(UC_X86_REG_BX) & 0xFF
        if emu.verbose:
            print(f"[INT 0x10] Get Functionality/State Information: AL=0x{al:02X}, BL=0x{bx:02X}")

        if bx == 0x00:
            # Return functionality state information
            # ES:DI = buffer for returning state information
            # For simplicity, return unsupported
            self.set_carry(uc)
        else:
            # Other BL values - return error
            self.set_carry(uc)
