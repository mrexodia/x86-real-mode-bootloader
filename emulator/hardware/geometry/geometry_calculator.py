"""
Disk geometry detection and calculation for the x86 Real Mode Bootloader Emulator
"""

from pathlib import Path
from typing import Optional, Tuple

from ...types.c_types import c_struct
from ...hardware.memory import MEMORY_SIZE_1MB


def detect_disk_geometry(
    disk_image_path: str,
    floppy_type: Optional[str] = None,
    drive_number: int = 0x80,
    geometry: Optional[Tuple[int, int, int]] = None
) -> Tuple[int, int, int]:
    """
    Detect disk geometry (cylinders, heads, sectors).
    
    Returns:
        Tuple of (cylinders, heads, sectors_per_track)
    """
    # If manual geometry specified, use it
    if geometry:
        return geometry
    
    # If floppy type specified, use standard geometry
    if floppy_type:
        floppy_types = {
            '360K':  (40, 2, 9),
            '720K':  (80, 2, 9),
            '1.2M':  (80, 2, 15),
            '1.44M': (80, 2, 18),
            '2.88M': (80, 2, 36),
        }
        return floppy_types[floppy_type]
    
    # Get disk image size
    disk_size = Path(disk_image_path).stat().st_size
    
    # Determine geometry based on size and drive type
    if drive_number < 0x80:  # Floppy disk
        return _detect_floppy_geometry(disk_size)
    else:  # Hard disk
        return _detect_hard_disk_geometry(disk_size)


def _detect_floppy_geometry(disk_size: int) -> Tuple[int, int, int]:
    """Detect floppy disk geometry based on size."""
    
    # Standard floppy sizes and geometries
    floppy_sizes = [
        (160 * 1024,   (40, 1, 8)),     # 160KB
        (180 * 1024,   (40, 1, 9)),     # 180KB  
        (320 * 1024,   (40, 2, 8)),     # 320KB
        (360 * 1024,   (40, 2, 9)),     # 360KB
        (720 * 1024,   (80, 2, 9)),     # 720KB
        (1200 * 1024,  (80, 2, 15)),    # 1.2MB
        (1440 * 1024,  (80, 2, 18)),    # 1.44MB
        (1680 * 1024,  (80, 2, 21)),    # 1.68MB (DMF)
        (2880 * 1024,  (80, 2, 36)),    # 2.88MB
    ]
    
    # Find closest match
    best_match = None
    min_diff = float('inf')
    
    for size, geo in floppy_sizes:
        diff = abs(disk_size - size)
        if diff < min_diff:
            min_diff = diff
            best_match = geo
    
    if best_match:
        return best_match
    else:
        # Fallback to 1.44MB if no good match
        return (80, 2, 18)


def _detect_hard_disk_geometry(disk_size: int) -> Tuple[int, int, int]:
    """Detect hard disk geometry based on size."""
    
    # Standard CHS geometries by size
    # These are common BIOS-compatible geometries
    
    if disk_size <= (16 * 1024 * 1024):  # <= 16MB
        return (306, 4, 17)  # ~20MB drive
    
    elif disk_size <= (32 * 1024 * 1024):  # <= 32MB
        return (615, 2, 17)  # ~20MB drive, 2 heads
    
    elif disk_size <= (64 * 1024 * 1024):  # <= 64MB
        return (615, 4, 17)  # ~40MB drive
    
    elif disk_size <= (128 * 1024 * 1024):  # <= 128MB
        return (977, 5, 17)  # ~80MB drive
    
    elif disk_size <= (256 * 1024 * 1024):  # <= 256MB
        return (977, 10, 17)  # ~160MB drive
    
    elif disk_size <= (512 * 1024 * 1024):  # <= 512MB
        return (1023, 16, 17)  # ~520MB drive (LBA28 limit)
    
    else:  # > 512MB
        # For larger disks, use maximum CHS values
        # This is what most BIOSes do for large disks
        return (1023, 16, 63)  # ~504MB (max CHS)


def chs_to_lba(cylinder: int, head: int, sector: int, 
              heads_per_cylinder: int, sectors_per_track: int) -> int:
    """Convert CHS (Cylinder/Head/Sector) to LBA (Logical Block Address)."""
    
    # LBA calculation: (cylinder * heads_per_cylinder + head) * sectors_per_track + (sector - 1)
    return (cylinder * heads_per_cylinder + head) * sectors_per_track + (sector - 1)


def lba_to_chs(lba: int, heads_per_cylinder: int, sectors_per_track: int) -> Tuple[int, int, int]:
    """Convert LBA (Logical Block Address) to CHS (Cylinder/Head/Sector)."""
    
    cylinder = lba // (heads_per_cylinder * sectors_per_track)
    head = (lba % (heads_per_cylinder * sectors_per_track)) // sectors_per_track
    sector = (lba % sectors_per_track) + 1
    
    return (cylinder, head, sector)


def validate_geometry(cylinders: int, heads: int, sectors: int) -> bool:
    """Validate that geometry values are reasonable."""
    
    # Check ranges
    if not (1 <= cylinders <= 1023):
        return False
    if not (1 <= heads <= 16):
        return False
    if not (1 <= sectors <= 63):
        return False
    
    # Check total capacity (LBA28 limit is ~8.4GB)
    total_sectors = cylinders * heads * sectors
    if total_sectors > (1024 * 16 * 63):  # Max CHS
        return False
    
    return True