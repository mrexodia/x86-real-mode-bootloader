"""
Disk geometry and parameter tables for the x86 Real Mode Bootloader Emulator
"""

from .disk_structures import DiskParameterTable, FixedDiskParameterTable
from .geometry_calculator import detect_disk_geometry

__all__ = [
    "DiskParameterTable",
    "FixedDiskParameterTable",
    "detect_disk_geometry"
]