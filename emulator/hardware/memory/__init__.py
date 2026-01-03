"""
Memory management for the x86 Real Mode Bootloader Emulator
"""

from .memory_layout import (
    BIOS_DATA_AREA_ADDR,
    INTERRUPT_VECTOR_TABLE_ADDR,
    BOOT_ADDRESS,
    BIOS_ROM_BASE,
    BIOS_ROM_END,
    MEMORY_SIZE_1MB,
    SECTOR_SIZE,
    MEMORY_SIZE_KB
)
from .bda_structures import BIOSDataArea

__all__ = [
    "BIOSDataArea",
    "BIOS_DATA_AREA_ADDR",
    "INTERRUPT_VECTOR_TABLE_ADDR", 
    "BOOT_ADDRESS",
    "BIOS_ROM_BASE",
    "BIOS_ROM_END",
    "MEMORY_SIZE_1MB",
    "SECTOR_SIZE",
    "MEMORY_SIZE_KB"
]