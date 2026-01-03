"""
Memory layout and address constants for the x86 Real Mode Bootloader Emulator
"""

from typing import Optional

# Memory addresses
BIOS_DATA_AREA_ADDR = 0x00400
INTERRUPT_VECTOR_TABLE_ADDR = 0x00000
BOOT_ADDRESS = 0x7C00
BIOS_ROM_BASE = 0xF0000
BIOS_ROM_END = 0xF0400

# Memory sizes
MEMORY_SIZE_1MB = 0x100000
SECTOR_SIZE = 512

# Default values
MEMORY_SIZE_KB = 640

# Memory regions
MEMORY_REGIONS = {
    'IVT':          (0x00000, 0x00400, 'Interrupt Vector Table'),
    'BDA':          (0x00400, 0x00500, 'BIOS Data Area'),
    'USER_RAM':     (0x00500, 0x9FC00, 'User RAM (first 640KB)'),
    'VIDEO_RAM':    (0xA0000, 0xAFFFF, 'Video RAM'),
    'ROM_SHADOW':   (0xC0000, 0xDFFFF, 'ROM Shadow'),
    'BIOS_AREA':    (0xE0000, 0xEFFFF, 'BIOS Extension Area'),
    'SYSTEM_BIOS':  (0xF0000, 0xFFFFF, 'System BIOS'),
}

def get_memory_region(address: int) -> Optional[dict]:
    """Get the memory region for a given address."""
    for name, (start, end, description) in MEMORY_REGIONS.items():
        if start <= address <= end:
            return {
                'name': name,
                'start': start,
                'end': end,
                'size': end - start,
                'description': description
            }
    return None

def is_address_in_range(address: int, start: int, size: int) -> bool:
    """Check if address is within given range."""
    return start <= address < start + size

def is_bda_address(address: int) -> bool:
    """Check if address is in BIOS Data Area."""
    return is_address_in_range(address, BIOS_DATA_AREA_ADDR, 0x100)

def is_ivt_address(address: int) -> bool:
    """Check if address is in Interrupt Vector Table."""
    return is_address_in_range(address, INTERRUPT_VECTOR_TABLE_ADDR, 0x400)

def is_bios_rom_address(address: int) -> bool:
    """Check if address is in BIOS ROM area."""
    return is_address_in_range(address, BIOS_ROM_BASE, BIOS_ROM_END - BIOS_ROM_BASE)