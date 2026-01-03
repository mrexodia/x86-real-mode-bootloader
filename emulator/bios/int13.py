"""INT 0x13 - Disk Services handler."""

from __future__ import annotations

import struct

from unicorn import Uc  # type: ignore
from unicorn.x86_const import *  # type: ignore

from .base import BIOSHandler


class Int13Handler(BIOSHandler):
    """Handle INT 0x13 - Disk Services."""

    def handle(self, uc: Uc) -> None:
        """Route to appropriate disk service function."""
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
            ret_ah = self._reset_disk(uc, dl)

        elif ah == 0x01:
            ret_ah, ret_al = self._get_status(uc, dl)

        elif ah == 0x02:
            ret_ah, ret_al, error = self._read_sectors(uc, ch, cl, dh, dl, al, es, bx)

        elif ah == 0x03:
            ret_ah, ret_al, error = self._write_sectors(uc, ch, cl, dh, dl, al, es, bx)

        elif ah == 0x04:
            ret_ah, ret_al, error = self._verify_sectors(uc, ch, cl, dh, dl, al)

        elif ah == 0x08:
            ret_ah, error = self._get_drive_parameters(uc, dl)

        elif ah == 0x0C:
            ret_ah, error = self._seek_to_track(uc, ch, cl, dh, dl)

        elif ah == 0x0D:
            ret_ah = self._reset_hard_disk(uc, dl)

        elif ah == 0x15:
            ret_ah, error = self._get_disk_type(uc, dl)

        elif ah == 0x41:
            ret_ah, error = self._check_extensions(uc, bx, dl)

        elif ah == 0x42:
            ret_ah, error = self._extended_read(uc, ds, si, dl)

        elif ah == 0x48:
            ret_ah = self._get_extended_parameters(uc, ds, si, dl)

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

    def _reset_disk(self, uc: Uc, dl: int) -> int:
        """AH=0x00: Reset disk system."""
        if self.emu.verbose:
            print(f"[INT 0x13] Reset disk system for drive 0x{dl:02X}")
        return 0x00

    def _get_status(self, uc: Uc, dl: int) -> tuple[int, int]:
        """AH=0x01: Get disk status."""
        if self.emu.verbose:
            print(f"[INT 0x13] Get disk status for drive 0x{dl:02X}")
        return 0x00, 0x00  # ret_ah, ret_al

    def _read_sectors(self, uc: Uc, ch: int, cl: int, dh: int, dl: int, 
                      sectors_to_read: int, es: int, bx: int) -> tuple[int, int, bool]:
        """AH=0x02: Read sectors (CHS addressing)."""
        emu = self.emu
        cylinder = ch | ((cl & 0xC0) << 2)
        sector = cl & 0x3F
        head = dh
        buffer_addr = (es << 4) + bx

        if emu.verbose:
            print(f"[INT 0x13] Read sectors (CHS) for drive 0x{dl:02X}")
            print(f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={sectors_to_read}")
            print(f"  - Buffer: 0x{es:04X}:0x{bx:04X} (0x{buffer_addr:05X})")

        # Validate CHS values
        if sector == 0 or sector > emu.sectors_per_track:
            if emu.verbose:
                print(f"  ⚠ Invalid sector: {sector} (valid: 1-{emu.sectors_per_track})")
            return 0x04, 0x00, True  # Sector not found

        if cylinder >= emu.cylinders or head >= emu.heads:
            if emu.verbose:
                print(f"  ⚠ Invalid CHS: C={cylinder} H={head} (max: {emu.cylinders-1}C, {emu.heads-1}H)")
            return 0x04, 0x00, True  # Sector not found

        lba = (cylinder * emu.heads + head) * emu.sectors_per_track + (sector - 1)

        if emu.verbose:
            print(f"  - Converted to LBA: {lba}")

        disk_offset = lba * 512
        bytes_to_read = sectors_to_read * 512

        if disk_offset + bytes_to_read > emu.disk_size:
            if emu.verbose:
                print("  ⚠ Read beyond disk image!")
            return 0x04, 0x00, True  # Sector not found

        for i in range(sectors_to_read):
            sector_data = emu.sector_read(lba + i)
            if emu.verbose:
                print(f"  ✓ Read {bytes_to_read} bytes from LBA {lba} to 0x{buffer_addr:05X}")
                print(f"  - Data (32 bytes): {sector_data[:32].hex(' ')}")
            emu.mem_write(buffer_addr + i * 512, sector_data)

        return 0x00, sectors_to_read, False  # Success

    def _write_sectors(self, uc: Uc, ch: int, cl: int, dh: int, dl: int,
                       sectors_to_write: int, es: int, bx: int) -> tuple[int, int, bool]:
        """AH=0x03: Write sectors (CHS addressing)."""
        emu = self.emu
        cylinder = ch | ((cl & 0xC0) << 2)
        sector = cl & 0x3F
        head = dh
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

        if disk_offset + bytes_to_write > emu.disk_size:
            if emu.verbose:
                print("  ⚠ Write beyond disk image!")
            return 0x04, 0x00, True  # Sector not found

        data = uc.mem_read(buffer_addr, bytes_to_write)
        for i in range(sectors_to_write):
            sector_data = data[i * 512:(i + 1) * 512]
            if emu.verbose:
                print(f"    - Writing sector {i+1}/{sectors_to_write} to LBA {lba + i}")
            emu.sector_write(lba + i, sector_data)

        if emu.verbose:
            print(f"  ✓ Wrote {bytes_to_write} bytes to LBA {lba} from 0x{buffer_addr:05X}")
            print(f"  - Data (32 bytes): {bytes(data[:32]).hex(' ')}")

        return 0x00, sectors_to_write, False  # Success

    def _verify_sectors(self, uc: Uc, ch: int, cl: int, dh: int, dl: int,
                        sectors_to_verify: int) -> tuple[int, int, bool]:
        """AH=0x04: Verify sectors (CHS addressing)."""
        emu = self.emu
        cylinder = ch | ((cl & 0xC0) << 2)
        sector = cl & 0x3F
        head = dh

        if emu.verbose:
            print(f"[INT 0x13] Verify sectors (CHS) for drive 0x{dl:02X}")
            print(f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={sectors_to_verify}")

        lba = (cylinder * emu.heads + head) * emu.sectors_per_track + (sector - 1)
        disk_offset = lba * 512
        bytes_to_verify = sectors_to_verify * 512

        if disk_offset + bytes_to_verify <= emu.disk_size:
            return 0x00, sectors_to_verify, False  # Success
        else:
            return 0x04, 0x00, True  # Sector not found

    def _get_drive_parameters(self, uc: Uc, dl: int) -> tuple[int, bool]:
        """AH=0x08: Get drive parameters - WRITES CX/DX."""
        emu = self.emu
        if emu.verbose:
            print(f"[INT 0x13] Get drive parameters for drive 0x{dl:02X}")

        if dl < 0x80:  # Floppy
            return 0x01, True  # Invalid parameter for now

        max_cylinder = emu.cylinders - 1
        max_head = emu.heads - 1
        sectors = emu.sectors_per_track

        # Build CX register: sectors in low 6 bits, cylinder in upper 10 bits
        cx_value = sectors | ((max_cylinder & 0x300) >> 2) | ((max_cylinder & 0xFF) << 8)
        dx_value = 1 | (max_head << 8)  # DL = number of drives, DH = max head

        uc.reg_write(UC_X86_REG_CX, cx_value)
        uc.reg_write(UC_X86_REG_DX, dx_value)

        if emu.verbose:
            print(f"  - Returning geometry: C={emu.cylinders}, H={emu.heads}, S={emu.sectors_per_track}")
            print(f"  - CX=0x{cx_value:04X}, DX=0x{dx_value:04X}")

        return 0x00, False  # Success

    def _seek_to_track(self, uc: Uc, ch: int, cl: int, dh: int, dl: int) -> tuple[int, bool]:
        """AH=0x0C: Seek to track (CHS addressing)."""
        emu = self.emu
        cylinder = ch | ((cl & 0xC0) << 2)
        head = dh

        if emu.verbose:
            print(f"[INT 0x13] Seek to track for drive 0x{dl:02X}")
            print(f"  - Cylinder={cylinder}, Head={head}")

        if cylinder < emu.cylinders and head < emu.heads:
            return 0x00, False  # Success
        else:
            return 0x40, True  # Seek failure

    def _reset_hard_disk(self, uc: Uc, dl: int) -> int:
        """AH=0x0D: Reset hard disk controller."""
        if self.emu.verbose:
            print(f"[INT 0x13] Reset hard disk controller for drive 0x{dl:02X}")
        return 0x00

    def _get_disk_type(self, uc: Uc, dl: int) -> tuple[int, bool]:
        """AH=0x15: Get disk type - WRITES CX/DX for fixed disks."""
        emu = self.emu
        if emu.verbose:
            print(f"[INT 0x13] Get disk type for drive 0x{dl:02X}")

        if dl < 0x80:
            return 0x00, True  # No disk or unsupported

        # For AH=0x03, return disk size in CX:DX
        total_sectors = emu.disk_size // 512
        uc.reg_write(UC_X86_REG_CX, (total_sectors >> 16) & 0xFFFF)
        uc.reg_write(UC_X86_REG_DX, total_sectors & 0xFFFF)
        return 0x03, False  # Fixed disk installed

    def _check_extensions(self, uc: Uc, bx: int, dl: int) -> tuple[int, bool]:
        """AH=0x41: Check INT 13 extensions present - WRITES BX/CX."""
        emu = self.emu
        if emu.verbose:
            print(f"[INT 0x13] Check extensions present for drive 0x{dl:02X}")

        if bx == 0x55AA:
            uc.reg_write(UC_X86_REG_BX, 0xAA55)  # Reversed signature
            uc.reg_write(UC_X86_REG_CX, 0x0007)  # Support bits
            return 0x30, False  # Version 3.0
        else:
            return 0x01, True  # Invalid function

    def _extended_read(self, uc: Uc, ds: int, si: int, dl: int) -> tuple[int, bool]:
        """AH=0x42: Extended read - LBA."""
        emu = self.emu
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
            return 0x01, True  # Invalid command

        for i in range(sectors):
            sector_data = emu.sector_read(lba + i)
            if emu.verbose:
                print(
                    f"  ✓ Read sector {i+1}/{sectors} from LBA {lba + i} to 0x{buffer_addr + i*512:05X}"
                )
                print(f"    - Data (32 bytes): {sector_data[:32].hex(' ')}")
            emu.mem_write(buffer_addr + i * 512, sector_data)

        return 0x00, False  # Success

    def _get_extended_parameters(self, uc: Uc, ds: int, si: int, dl: int) -> int:
        """AH=0x48: Get extended drive parameters."""
        emu = self.emu
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

        return 0x00  # Success
