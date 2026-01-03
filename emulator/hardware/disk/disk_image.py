"""Disk image access with copy-on-write sector caching.

This class is extracted from the original monolithic emulator implementation.
Behavior is intentionally kept identical (including the QEMU-like CHS geometry
heuristics) because golden-master traces depend on it.
"""

from __future__ import annotations

from pathlib import Path
from collections import OrderedDict


class DiskImage:
    def __init__(
        self,
        path: str | Path,
        *,
        drive_number: int = 0x80,
        manual_geometry=None,
        floppy_type: str | None = None,
    ):
        self.path = Path(path)
        self.drive_number = drive_number
        self.manual_geometry = manual_geometry
        self.floppy_type = floppy_type

        self.fd = None
        self.size = 0
        self.cache: OrderedDict[int, bytes] = OrderedDict()

        # Geometry
        self.cylinders = 0
        self.heads = 0
        self.sectors_per_track = 0
        self.geometry_method = "Unknown"

    def open(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"Disk image not found: {self.path}")

        self.fd = open(self.path, 'rb')
        self.fd.seek(0, 2)
        self.size = self.fd.tell()
        self.cache = OrderedDict()

        if self.size < 512:
            raise ValueError("Disk image too small (must be at least 512 bytes)")

        self.detect_geometry()

    def close(self) -> None:
        if self.fd:
            self.fd.close()
            self.fd = None

    def detect_geometry(self) -> None:
        """Detect disk geometry following QEMU's algorithm."""
        # Standard floppy geometries (size_bytes: (cylinders, heads, sectors, name))
        FLOPPY_TYPES = {
            '360K': (40, 2, 9, 360 * 1024),
            '720K': (80, 2, 9, 720 * 1024),
            '1.2M': (80, 2, 15, 1200 * 1024),
            '1.44M': (80, 2, 18, 1440 * 1024),
            '2.88M': (80, 2, 36, 2880 * 1024),
        }

        total_sectors = self.size // 512

        # Method 1: Manual geometry override
        if self.manual_geometry:
            self.cylinders, self.heads, self.sectors_per_track = self.manual_geometry
            self.geometry_method = "Manual override"
            return

        # Method 2: Floppy type override
        if self.floppy_type:
            c, h, s, _ = FLOPPY_TYPES[self.floppy_type]
            self.cylinders = c
            self.heads = h
            self.sectors_per_track = s
            self.geometry_method = f"Floppy type {self.floppy_type}"
            return

        # Method 3: Floppy auto-detect (if drive is floppy and size matches)
        if self.drive_number < 0x80:
            for floppy_name, (c, h, s, size) in FLOPPY_TYPES.items():
                if self.size == size:
                    self.cylinders = c
                    self.heads = h
                    self.sectors_per_track = s
                    self.geometry_method = f"Auto-detected floppy {floppy_name}"
                    return

        # Method 4: MBR partition table (QEMU's guess_disk_lchs algorithm)
        if self.size >= 512:
            mbr = self.sector_read(0)

            if mbr[510] == 0x55 and mbr[511] == 0xAA:
                for i in range(4):
                    offset = 0x1BE + (i * 16)
                    entry = mbr[offset:offset + 16]

                    part_type = entry[4]
                    if part_type != 0:
                        end_head = entry[5]
                        end_sector = entry[6] & 0x3F

                        heads = end_head + 1
                        sectors = end_sector

                        if sectors > 0 and heads > 0:
                            cylinders = total_sectors // (heads * sectors)
                            if 1 <= cylinders <= 16383:
                                self.cylinders = cylinders
                                self.heads = heads
                                self.sectors_per_track = sectors
                                self.geometry_method = "MBR partition table"
                                return

        # Method 5: Fallback geometry (QEMU's guess_chs_for_size)
        self.heads = 16
        self.sectors_per_track = 63
        self.cylinders = total_sectors // (self.heads * self.sectors_per_track)
        if total_sectors % (self.heads * self.sectors_per_track) != 0:
            self.cylinders += 1
        self.geometry_method = "Fallback (QEMU default: 16H/63S)"

    def sector_read(self, lba: int) -> bytes:
        if lba * 512 >= self.size:
            raise ValueError(f"Disk read out of bounds: LBA={lba}, disk_size={self.size}")
        if lba in self.cache:
            return self.cache[lba]
        assert self.fd is not None
        self.fd.seek(lba * 512)
        sector_data = self.fd.read(512)
        self.cache[lba] = sector_data
        return sector_data

    def sector_write(self, lba: int, data: bytes) -> None:
        if lba * 512 >= self.size:
            raise ValueError(f"Disk write out of bounds: LBA={lba}, disk_size={self.size}")
        if len(data) != 512:
            raise ValueError(f"Sector write data must be exactly 512 bytes, got {len(data)} bytes")
        self.cache[lba] = data
