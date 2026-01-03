"""BIOS interrupt services (legacy behavior).

This file contains the BIOS interrupt handling logic extracted from
`BootloaderEmulator`. The goal is to keep behavior and trace output identical
while making the codebase modular.
"""

from __future__ import annotations

import struct
from typing import Any

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from ..hardware.ivt import IVT_NAMES


class BIOSServices:
    """Implements BIOS interrupt services used by the emulator."""

    def __init__(self, emulator: Any):
        # We keep a loose type here to avoid circular imports.
        self.emu = emulator

    def handle_bios_interrupt(self, uc: Uc, intno: int):
        """Route interrupt to appropriate BIOS service handler."""
        emu = self.emu
        print(f"[*] Handling BIOS interrupt 0x{intno:02X} -> {IVT_NAMES.get(intno, 'Unknown')}")
        self._dump_registers(uc, intno, "BEFORE")
        if intno == 0x10:
            # Video Services
            self.handle_int10(uc)
        elif intno == 0x11:
            # Get Equipment List
            self.handle_int11(uc)
        elif intno == 0x12:
            # Get Memory Size
            self.handle_int12(uc)
        elif intno == 0x13:
            # Disk Services
            self.handle_int13(uc)
        elif intno == 0x14:
            # Serial Port Services
            self.handle_int14(uc)
        elif intno == 0x15:
            # System Services
            self.handle_int15(uc)
        elif intno == 0x16:
            # Keyboard Services
            self.handle_int16(uc)
        elif intno == 0x17:
            # Printer Services
            self.handle_int17(uc)
        elif intno == 0x1A:
            # Timer/Clock Services
            self.handle_int1a(uc)
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

    def handle_int10(self, uc: Uc):
        """Handle INT 0x10 - Video Services."""
        emu = self.emu
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x00:
            # Set video mode
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

        elif ah == 0x02:
            # Set cursor position
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

        elif ah == 0x03:
            # Get cursor position and shape
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

        elif ah == 0x0E:
            # Teletype output
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

        elif ah == 0x0F:
            # Get current video mode
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

        elif ah == 0x1A:
            # Get Display Combination Code
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            if emu.verbose:
                print(f"[INT 0x10] Get Display Combination Code: AL=0x{al:02X}")

            # Return: AL=0x1A (function supported), BL=display combination code
            # Display combination code 0x08 = VGA with color display
            uc.reg_write(UC_X86_REG_AX, 0x1A00)
            uc.reg_write(UC_X86_REG_BX, (uc.reg_read(UC_X86_REG_BX) & 0xFF00) | 0x08)

            # Clear CF (success)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

            if emu.verbose:
                print("  - Returning: AL=0x1A, BL=0x08 (VGA color)")

        elif ah == 0x1B:
            # Get Functionality/State Information
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            bx = uc.reg_read(UC_X86_REG_BX) & 0xFF
            if emu.verbose:
                print(f"[INT 0x10] Get Functionality/State Information: AL=0x{al:02X}, BL=0x{bx:02X}")

            if bx == 0x00:
                # Return functionality state information
                # ES:DI = buffer for returning state information
                # For simplicity, return unsupported
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)  # Set CF (error)
            else:
                # Other BL values - return error
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)  # Set CF (error)

        else:
            if emu.verbose:
                print(f"[INT 0x10] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def handle_int13(self, uc: Uc):
        """Handle INT 0x13 - Disk Services."""
        emu = self.emu
        # Read all registers at the beginning
        ax = uc.reg_read(UC_X86_REG_AX)
        ah = (ax >> 8) & 0xFF
        al = ax & 0xFF

        bx = uc.reg_read(UC_X86_REG_BX)
        cx = uc.reg_read(UC_X86_REG_CX)
        ch = (cx >> 8) & 0xFF
        cl = cx & 0xFF

        dx = uc.reg_read(UC_X86_REG_DX)
        dh = (dx >> 8) & 0xFF
        dl = dx & 0xFF

        si = uc.reg_read(UC_X86_REG_SI)
        es = uc.reg_read(UC_X86_REG_ES)
        ds = uc.reg_read(UC_X86_REG_DS)
        flags = uc.reg_read(UC_X86_REG_EFLAGS)

        # Default return values
        ret_ah = 0x00  # Success by default
        ret_al = al  # Preserve AL by default
        error = False  # Clear carry by default (success)

        # Validate drive number for most operations
        if ah not in [0x00, 0x08, 0x15, 0x41, 0x42, 0x48] and dl != emu.drive_number:
            if emu.verbose:
                print(f"[INT 0x13] Function AH=0x{ah:02X} for drive 0x{dl:02X} - drive not found")
            ret_ah = 0x80  # Drive not ready/timeout
            error = True

        elif ah == 0x00:
            # Reset disk system
            if emu.verbose:
                print(f"[INT 0x13] Reset disk system for drive 0x{dl:02X}")
            ret_ah = 0x00

        elif ah == 0x01:
            # Get disk status
            if emu.verbose:
                print(f"[INT 0x13] Get disk status for drive 0x{dl:02X}")
            ret_ah = 0x00
            ret_al = 0x00  # Last operation status (no error)

        elif ah == 0x02:
            # Read sectors (CHS addressing)
            cylinder = ch | ((cl & 0xC0) << 2)
            sector = cl & 0x3F
            head = dh
            sectors_to_read = al
            buffer_addr = (es << 4) + bx

            if emu.verbose:
                print(f"[INT 0x13] Read sectors (CHS) for drive 0x{dl:02X}")
                print(f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={sectors_to_read}")
                print(f"  - Buffer: 0x{es:04X}:0x{bx:04X} (0x{buffer_addr:05X})")

            # Validate CHS values
            if sector == 0 or sector > emu.sectors_per_track:
                if emu.verbose:
                    print(f"  ⚠ Invalid sector: {sector} (valid: 1-{emu.sectors_per_track})")
                ret_ah = 0x04  # Sector not found
                ret_al = 0x00
                error = True
            elif cylinder >= emu.cylinders or head >= emu.heads:
                if emu.verbose:
                    print(f"  ⚠ Invalid CHS: C={cylinder} H={head} (max: {emu.cylinders-1}C, {emu.heads-1}H)")
                ret_ah = 0x04  # Sector not found
                ret_al = 0x00
                error = True
            else:
                lba = (cylinder * emu.heads + head) * emu.sectors_per_track + (sector - 1)

                if emu.verbose:
                    print(f"  - Converted to LBA: {lba}")

                disk_offset = lba * 512
                bytes_to_read = sectors_to_read * 512

                if disk_offset + bytes_to_read > emu.disk_size:
                    if emu.verbose:
                        print("  ⚠ Read beyond disk image!")
                    ret_ah = 0x04  # Sector not found
                    ret_al = 0x00
                    error = True
                else:
                    for i in range(sectors_to_read):
                        sector_data = emu.sector_read(lba + i)
                        if emu.verbose:
                            print(f"  ✓ Read {bytes_to_read} bytes from LBA {lba} to 0x{buffer_addr:05X}")
                            print(f"  - Data (32 bytes): {sector_data[:32].hex(' ')}")
                        emu.mem_write(buffer_addr + i * 512, sector_data)
                    ret_ah = 0x00
                    ret_al = sectors_to_read  # Sectors actually read

        elif ah == 0x03:
            # Write sectors (CHS addressing)
            cylinder = ch | ((cl & 0xC0) << 2)
            sector = cl & 0x3F
            head = dh
            sectors_to_write = al
            buffer_addr = (es << 4) + bx

            if emu.verbose:
                print(f"[INT 0x13] Write sectors (CHS) for drive 0x{dl:02X}")
                print(f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={sectors_to_write}")
                print(f"  - Buffer: 0x{es:04X}:0x{bx:04X} (0x{buffer_addr:05X})")

            lba = (cylinder * emu.heads + head) * emu.sectors_per_track + (sector - 1)

            if emu.verbose:
                print(f"  - Converted to LBA: {lba}")

            disk_offset = lba * 512
            bytes_to_write = sectors_to_write * 512

            if disk_offset + bytes_to_write <= emu.disk_size:
                data = uc.mem_read(buffer_addr, bytes_to_write)
                for i in range(sectors_to_write):
                    sector_data = data[i * 512:(i + 1) * 512]
                    if emu.verbose:
                        print(f"    - Writing sector {i+1}/{sectors_to_write} to LBA {lba + i}")
                    emu.sector_write(lba + i, sector_data)

                if emu.verbose:
                    print(f"  ✓ Wrote {bytes_to_write} bytes to LBA {lba} from 0x{buffer_addr:05X}")
                    print(f"  - Data (32 bytes): {bytes(data[:32]).hex(' ')}")

                ret_ah = 0x00
                ret_al = sectors_to_write  # Sectors actually written
            else:
                if emu.verbose:
                    print("  ⚠ Write beyond disk image!")
                ret_ah = 0x04  # Sector not found
                ret_al = 0x00
                error = True

        elif ah == 0x04:
            # Verify sectors (CHS addressing)
            cylinder = ch | ((cl & 0xC0) << 2)
            sector = cl & 0x3F
            head = dh
            sectors_to_verify = al

            if emu.verbose:
                print(f"[INT 0x13] Verify sectors (CHS) for drive 0x{dl:02X}")
                print(f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={sectors_to_verify}")

            lba = (cylinder * emu.heads + head) * emu.sectors_per_track + (sector - 1)
            disk_offset = lba * 512
            bytes_to_verify = sectors_to_verify * 512

            if disk_offset + bytes_to_verify <= emu.disk_size:
                ret_ah = 0x00
                ret_al = sectors_to_verify  # Sectors verified
            else:
                ret_ah = 0x04  # Sector not found
                ret_al = 0x00
                error = True

        elif ah == 0x08:
            # Get drive parameters - WRITES CX/DX
            if emu.verbose:
                print(f"[INT 0x13] Get drive parameters for drive 0x{dl:02X}")

            if dl < 0x80:  # Floppy
                ret_ah = 0x01  # Invalid parameter for now
                error = True
            else:
                max_cylinder = emu.cylinders - 1
                max_head = emu.heads - 1
                sectors = emu.sectors_per_track

                # Build CX register: sectors in low 6 bits, cylinder in upper 10 bits
                cx_value = sectors | ((max_cylinder & 0x300) >> 2) | ((max_cylinder & 0xFF) << 8)
                dx_value = 1 | (max_head << 8)  # DL = number of drives, DH = max head

                uc.reg_write(UC_X86_REG_CX, cx_value)
                uc.reg_write(UC_X86_REG_DX, dx_value)

                ret_ah = 0x00

                if emu.verbose:
                    print(f"  - Returning geometry: C={emu.cylinders}, H={emu.heads}, S={emu.sectors_per_track}")
                    print(f"  - CX=0x{cx_value:04X}, DX=0x{dx_value:04X}")

        elif ah == 0x0C:
            # Seek to track (CHS addressing)
            cylinder = ch | ((cl & 0xC0) << 2)
            head = dh

            if emu.verbose:
                print(f"[INT 0x13] Seek to track for drive 0x{dl:02X}")
                print(f"  - Cylinder={cylinder}, Head={head}")

            if cylinder < emu.cylinders and head < emu.heads:
                ret_ah = 0x00
            else:
                ret_ah = 0x40  # Seek failure
                error = True

        elif ah == 0x0D:
            # Reset hard disk controller
            if emu.verbose:
                print(f"[INT 0x13] Reset hard disk controller for drive 0x{dl:02X}")
            ret_ah = 0x00

        elif ah == 0x15:
            # Get disk type - WRITES CX/DX for fixed disks
            if emu.verbose:
                print(f"[INT 0x13] Get disk type for drive 0x{dl:02X}")

            if dl < 0x80:
                ret_ah = 0x00  # No disk or unsupported
                error = True
            else:
                ret_ah = 0x03  # Fixed disk installed
                # For AH=0x03, return disk size in CX:DX
                total_sectors = emu.disk_size // 512
                uc.reg_write(UC_X86_REG_CX, (total_sectors >> 16) & 0xFFFF)
                uc.reg_write(UC_X86_REG_DX, total_sectors & 0xFFFF)

        elif ah == 0x41:
            # Check INT 13 extensions present - WRITES BX/CX
            if emu.verbose:
                print(f"[INT 0x13] Check extensions present for drive 0x{dl:02X}")

            if bx == 0x55AA:
                ret_ah = 0x30  # Version 3.0
                uc.reg_write(UC_X86_REG_BX, 0xAA55)  # Reversed signature
                uc.reg_write(UC_X86_REG_CX, 0x0007)  # Support bits
            else:
                ret_ah = 0x01  # Invalid function
                error = True

        elif ah == 0x42:
            # Extended read - LBA
            if emu.verbose:
                print(f"[INT 0x13] Extended read for drive 0x{dl:02X}")

            packet_addr = (ds << 4) + si
            packet = uc.mem_read(packet_addr, 16)

            sectors = struct.unpack('<H', packet[2:4])[0]
            offset = struct.unpack('<H', packet[4:6])[0]
            segment = struct.unpack('<H', packet[6:8])[0]
            lba = struct.unpack('<Q', packet[8:16])[0]

            if emu.verbose:
                print(f"  - LBA: {lba}, Sectors: {sectors}, Buffer: 0x{segment:04X}:0x{offset:04X}")

            disk_offset = lba * 512
            buffer_addr = (segment << 4) + offset
            bytes_to_read = sectors * 512

            if disk_offset + bytes_to_read > emu.disk_size:
                if emu.verbose:
                    print("  ⚠ Read beyond disk image!")
                ret_ah = 0x01  # Invalid command
                error = True
            else:
                for i in range(sectors):
                    sector_data = emu.sector_read(lba + i)
                    if emu.verbose:
                        print(
                            f"  ✓ Read sector {i+1}/{sectors} from LBA {lba + i} to 0x{buffer_addr + i*512:05X}"
                        )
                        print(f"    - Data (32 bytes): {sector_data[:32].hex(' ')}")
                    emu.mem_write(buffer_addr + i * 512, sector_data)
                ret_ah = 0x00

        elif ah == 0x48:
            # Get extended drive parameters
            if emu.verbose:
                print(f"[INT 0x13] Get extended drive parameters for drive 0x{dl:02X}")

            buffer_addr = (ds << 4) + si
            buffer_header = uc.mem_read(buffer_addr, 2)
            buffer_size = struct.unpack('<H', buffer_header)[0]

            if emu.verbose:
                print(f"  - Buffer size requested: {buffer_size} bytes")

            total_sectors = emu.disk_size // 512

            params = bytearray(26)
            struct.pack_into('<H', params, 0, 26)
            struct.pack_into('<H', params, 2, 0x0002)
            struct.pack_into('<I', params, 4, emu.cylinders)
            struct.pack_into('<I', params, 8, emu.heads)
            struct.pack_into('<I', params, 12, emu.sectors_per_track)
            struct.pack_into('<Q', params, 16, total_sectors)
            struct.pack_into('<H', params, 24, 512)

            bytes_to_write = min(buffer_size, 26)
            uc.mem_write(buffer_addr, bytes(params[:bytes_to_write]))

            if emu.verbose:
                print(f"  - Returned {bytes_to_write} bytes")
                print(f"  - Total sectors: {total_sectors}")

            ret_ah = 0x00

        else:
            if emu.verbose:
                print(f"[INT 0x13] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()
            return

        # Write AH/AL at the end (always needed)
        uc.reg_write(UC_X86_REG_AX, (ret_ah << 8) | ret_al)

        # Set or clear carry flag
        if error:
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)
        else:
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

    def handle_int11(self, uc: Uc):
        """Handle INT 0x11 - Get Equipment List."""
        emu = self.emu
        if emu.verbose:
            print("[INT 0x11] Get equipment list")
        # AX = equipment list word

        equipment = emu.bda.equipment_list
        if emu.verbose:
            print(f"  - Equipment from BDA: 0x{equipment:04X}")

        uc.reg_write(UC_X86_REG_AX, equipment)

    def handle_int12(self, uc: Uc):
        """Handle INT 0x12 - Get Memory Size."""
        emu = self.emu
        if emu.verbose:
            print("[INT 0x12] Get memory size")

        memory_size_kb = emu.bda.memory_size_kb
        if emu.verbose:
            print(f"  - Memory size from BDA: {memory_size_kb} KB")

        uc.reg_write(UC_X86_REG_AX, memory_size_kb)

    def handle_int15(self, uc: Uc):
        """Handle INT 0x15 - System Services."""
        emu = self.emu
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x88:
            # Get extended memory size
            if emu.verbose:
                print("[INT 0x15] Get extended memory size")
            # AX = extended memory in KB (above 1MB)
            uc.reg_write(UC_X86_REG_AX, 0)  # No extended memory
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0xC0:
            # Get system configuration
            if emu.verbose:
                print("[INT 0x15] Get system configuration")
            # For now, return error
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        elif ah == 0xE8:
            # E820h - Query System Address Map
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            if al == 0x20:
                edx = uc.reg_read(UC_X86_REG_EDX)
                ebx = uc.reg_read(UC_X86_REG_EBX)
                es = uc.reg_read(UC_X86_REG_ES)
                di = uc.reg_read(UC_X86_REG_DI)

                # Check for SMAP signature
                if edx != 0x534D4150:  # 'SMAP'
                    if emu.verbose:
                        print(f"[INT 0x15, E820] Invalid signature: 0x{edx:08X}")
                    flags = uc.reg_read(UC_X86_REG_EFLAGS)
                    uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)  # Set CF
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
                    flags = uc.reg_read(UC_X86_REG_EFLAGS)
                    uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)  # Set CF
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
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
            else:
                if emu.verbose:
                    print(f"[INT 0x15] Unhandled E8h subfunction AL=0x{al:02X}")
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        elif ah == 0x41:
            if emu.verbose:
                print("[INT 0x15] Wait on external event (unsupported)")
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        elif ah == 0x53:
            if emu.verbose:
                print(f"[INT 0x15] APM BIOS function AH=0x{ah:02X}")
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        else:
            if emu.verbose:
                print(f"[INT 0x15] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def handle_int16(self, uc: Uc):
        """Handle INT 0x16 - Keyboard Services."""
        emu = self.emu
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x00:
            if emu.verbose:
                print("[INT 0x16] Read keystroke")
            uc.reg_write(UC_X86_REG_AX, 0x1C0D)  # AL=0x0D, AH=0x1C

        elif ah == 0x01:
            if emu.verbose:
                print("[INT 0x16] Check for keystroke")
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0040)  # Set ZF

        elif ah == 0x02:
            if emu.verbose:
                print("[INT 0x16] Get shift flags")
            uc.reg_write(UC_X86_REG_AX, 0)

        else:
            if emu.verbose:
                print(f"[INT 0x16] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def handle_int14(self, uc: Uc):
        """Handle INT 0x14 - Serial Port Services."""
        emu = self.emu
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dx = uc.reg_read(UC_X86_REG_DX) & 0xFF  # DL = port number

        if ah == 0x00:
            # Initialize serial port
            if emu.verbose:
                print(f"[INT 0x14] Initialize serial port DL=0x{dx:02X}")
            uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | 0x2000)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x01:
            # Write character to serial port
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            if emu.verbose:
                print(
                    f"[INT 0x14] Write character to serial port: 0x{al:02X} "
                    f"({chr(al) if 32 <= al < 127 else '?'})"
                )
            else:
                # Always output serial writes for visibility
                if 32 <= al < 127 or al in (0x0A, 0x0D):
                    print(f"[SERIAL] {chr(al)}", end="", flush=True)
            uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | 0x0000)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x02:
            if emu.verbose:
                print("[INT 0x14] Read character from serial port")
            uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | 0x8000)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        elif ah == 0x03:
            if emu.verbose:
                print("[INT 0x14] Get serial port status")
            uc.reg_write(UC_X86_REG_AX, 0x6000)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        else:
            if emu.verbose:
                print(f"[INT 0x14] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def handle_int17(self, uc: Uc):
        """Handle INT 0x17 - Printer Services (return offline status)."""
        emu = self.emu
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dx = uc.reg_read(UC_X86_REG_DX) & 0xFF  # DL = printer number

        offline_status = 0x00  # Offline/not ready/not selected

        if ah == 0x00:
            if emu.verbose:
                al = uc.reg_read(UC_X86_REG_AX) & 0xFF
                print(f"[INT 0x17] Print character 0x{al:02X} to printer {dx} (OFFLINE)")
            uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | (offline_status << 8))
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        elif ah == 0x01:
            if emu.verbose:
                print(f"[INT 0x17] Initialize printer {dx} (OFFLINE)")
            uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | (offline_status << 8))
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        elif ah == 0x02:
            if emu.verbose:
                print(f"[INT 0x17] Get printer status for printer {dx} (OFFLINE)")
            uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF) | (offline_status << 8))
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        else:
            if emu.verbose:
                print(f"[INT 0x17] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def handle_int1a(self, uc: Uc):
        """Handle INT 0x1A - Timer/Clock Services."""
        emu = self.emu
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x00:
            if emu.verbose:
                print("[INT 0x1A] Get system time")
            ticks = 65536 * 2  # ~2 hours worth of ticks
            cx = (ticks >> 16) & 0xFFFF
            dx = ticks & 0xFFFF
            ax = uc.reg_read(UC_X86_REG_AX) & 0xFF
            uc.reg_write(UC_X86_REG_AX, ax)
            uc.reg_write(UC_X86_REG_CX, cx)
            uc.reg_write(UC_X86_REG_DX, dx)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x01:
            if emu.verbose:
                cx = uc.reg_read(UC_X86_REG_CX)
                dx = uc.reg_read(UC_X86_REG_DX)
                print(f"[INT 0x1A] Set system time CX:DX=0x{cx:04X}:0x{dx:04X}")
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x02:
            if emu.verbose:
                print("[INT 0x1A] Get RTC time")
            hours_bcd = 0x08
            minutes_bcd = 0x30
            seconds_bcd = 0x45
            dst_flag = 0x00
            uc.reg_write(UC_X86_REG_CX, (hours_bcd << 8) | minutes_bcd)
            uc.reg_write(UC_X86_REG_DX, (seconds_bcd << 8) | dst_flag)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x03:
            if emu.verbose:
                cx = uc.reg_read(UC_X86_REG_CX)
                dx = uc.reg_read(UC_X86_REG_DX)
                print(f"[INT 0x1A] Set RTC time CX=0x{cx:04X}, DX=0x{dx:04X}")
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x04:
            if emu.verbose:
                print("[INT 0x1A] Get RTC date")
            year_bcd = 0x1990
            month_bcd = 0x01
            day_bcd = 0x15
            uc.reg_write(UC_X86_REG_CX, year_bcd)
            uc.reg_write(UC_X86_REG_DX, (month_bcd << 8) | day_bcd)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x05:
            if emu.verbose:
                cx = uc.reg_read(UC_X86_REG_CX)
                dx = uc.reg_read(UC_X86_REG_DX)
                print(f"[INT 0x1A] Set RTC date CX=0x{cx:04X}, DX=0x{dx:04X}")
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x06:
            if emu.verbose:
                print("[INT 0x1A] Set RTC alarm")
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x07:
            if emu.verbose:
                print("[INT 0x1A] Reset RTC alarm")
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        else:
            if emu.verbose:
                print(f"[INT 0x1A] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()
