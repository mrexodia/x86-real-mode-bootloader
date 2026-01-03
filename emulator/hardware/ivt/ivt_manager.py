"""
Interrupt Vector Table (IVT) management for the x86 Real Mode Bootloader Emulator
"""

import struct
from typing import Tuple

from ..memory.memory_layout import INTERRUPT_VECTOR_TABLE_ADDR


# Interrupt vector names for logging and debugging
IVT_NAMES = {
    # CPU Exceptions
    0x00: "Divide by Zero",
    0x01: "Single Step / Debug",
    0x02: "Non-Maskable Interrupt (NMI)",
    0x03: "Breakpoint",
    0x04: "Overflow",
    0x05: "BOUND Range Exceeded / Print Screen",
    0x06: "Invalid Opcode (286+)",
    0x07: "Coprocessor Not Available (286+)",
    0x08: "Double Fault (286+) / IRQ0 System Timer (18.2 Hz)",
    0x09: "Coprocessor Segment Overrun (286+) / IRQ1 Keyboard",
    0x0A: "Invalid TSS (286+) / IRQ2 Cascade/Secondary PIC",
    0x0B: "Segment Not Present (286+) / IRQ3 Serial Port 2 (COM2)",
    0x0C: "Stack Fault (286+) / IRQ4 Serial Port 1 (COM1)",
    0x0D: "General Protection Fault (286+) / IRQ5 Parallel Port 2 (LPT2) / Sound",
    0x0E: "Page Fault (386+) / IRQ6 Floppy Disk Controller",
    0x0F: "Reserved / IRQ7 Parallel Port 1 (LPT1)",

    # BIOS Services
    0x10: "Video Services",
    0x11: "Equipment Determination",
    0x12: "Memory Size Determination",
    0x13: "Disk Services (Floppy/Hard Disk)",
    0x14: "Serial Communications Services",
    0x15: "System Services / Cassette (PC/XT)",
    0x16: "Keyboard Services",
    0x17: "Printer Services",
    0x18: "Execute ROM BASIC / Boot Failure",
    0x19: "Bootstrap Loader / System Reboot",
    0x1A: "Real-Time Clock (RTC) Services",
    0x1B: "Ctrl-Break Handler",
    0x1C: "Timer Tick (User Timer Interrupt)",

    # Parameter Tables (Pointers, not callable)
    0x1D: "Video Parameter Table (VPT) Pointer",
    0x1E: "Diskette Parameter Table (DPT) Pointer",
    0x1F: "Video Graphics Character Table Pointer (chars 80h-FFh)",

    # DOS Interrupts
    0x20: "DOS - Program Terminate",
    0x21: "DOS - Function Dispatcher",
    0x22: "DOS - Terminate Address",
    0x23: "DOS - Ctrl-C Handler",
    0x24: "DOS - Critical Error Handler",
    0x25: "DOS - Absolute Disk Read",
    0x26: "DOS - Absolute Disk Write",
    0x27: "DOS - Terminate and Stay Resident (TSR)",
    0x28: "DOS - Idle Interrupt",
    0x29: "DOS - Fast Console Output",
    0x2A: "DOS - Network / Critical Section",
    0x2F: "DOS - Multiplex Interrupt",

    # Software Services
    0x33: "Mouse Driver Services",

    # Extended BIOS
    0x40: "Floppy Disk Handler (Relocated INT 13h)",
    0x41: "Fixed Disk 0 Parameter Table Pointer (Hard Disk 0)",
    0x42: "EGA/VGA Video Handler (Relocated INT 10h)",
    0x43: "EGA/VGA Character Table Pointer (chars 00h-7Fh)",
    0x44: "Novell NetWare",
    0x46: "Fixed Disk 1 Parameter Table Pointer (Hard Disk 1)",
    0x4A: "Real-Time Clock Alarm (AT+)",
    0x4F: "Keyboard Intercept",

    # Extended Services
    0x5C: "NetBIOS Interface",
    0x67: "EMS (Expanded Memory Specification)",
    0x68: "APM (Advanced Power Management)",
    0x6C: "System Resume Vector (APM)",

    # IRQ 8-15 (AT+ via Secondary PIC)
    0x70: "IRQ8 - Real-Time Clock Interrupt",
    0x71: "IRQ9 - Redirected IRQ2 / LAN Adapter",
    0x72: "IRQ10 - Reserved",
    0x73: "IRQ11 - Reserved",
    0x74: "IRQ12 - PS/2 Mouse",
    0x75: "IRQ13 - Math Coprocessor Exception",
    0x76: "IRQ14 - Hard Disk Controller",
    0x77: "IRQ15 - Reserved / Secondary IDE",
}


class IVTManager:
    """Manages the Interrupt Vector Table (IVT)."""
    
    def __init__(self, mu):
        """Initialize IVT manager with Unicorn Engine instance."""
        self.mu = mu
        self.ivt_base = INTERRUPT_VECTOR_TABLE_ADDR
        
    def create_ivt_entry(self, interrupt: int, segment: int, offset: int) -> None:
        """Create an IVT entry pointing to segment:offset."""
        if 0 <= interrupt <= 255:
            # Each IVT entry is 4 bytes: offset (2 bytes) + segment (2 bytes)
            entry_addr = self.ivt_base + (interrupt * 4)
            data = struct.pack('<HH', offset, segment)
            self.mu.mem_write(entry_addr, data)
        else:
            raise ValueError(f"Invalid interrupt number: {interrupt}")
    
    def read_ivt_entry(self, interrupt: int) -> Tuple[int, int]:
        """Read an IVT entry, returns (offset, segment)."""
        if 0 <= interrupt <= 255:
            entry_addr = self.ivt_base + (interrupt * 4)
            data = self.mu.mem_read(entry_addr, 4)
            offset, segment = struct.unpack('<HH', data)
            return offset, segment
        else:
            raise ValueError(f"Invalid interrupt number: {interrupt}")
    
    def create_bios_stubs(self) -> None:
        """Create minimal BIOS stub routines in ROM memory.

        These stubs are meant as safe placeholders (they *return* from the
        interrupt without doing any work) and must not recurse via INT.
        """
        rom_base = 0xF0000

        # Minimal handler: IRET
        stub = b'\xCF'

        # The addresses below are "typical" BIOS locations in the F000: segment.
        # We only provide placeholders; real behavior is implemented via Unicorn
        # interrupt hooks in the main emulator.
        stubs = {
            0x10: 0xF060,  # Video Services
            0x13: 0xF0A0,  # Disk Services
            0x15: 0xF859,  # System Services
            0x16: 0xF84E,  # Keyboard Services
            0x17: 0xF82D,  # Printer Services
            0x1A: 0xFE6E,  # RTC Services
        }

        for intno, offset in stubs.items():
            self.mu.mem_write(rom_base + offset, stub)
            self.create_ivt_entry(intno, 0xF000, offset)
    
    def get_interrupt_name(self, interrupt: int) -> str:
        """Get the descriptive name for an interrupt."""
        return IVT_NAMES.get(interrupt, f"INT {interrupt:02X}h (Unknown)")
    
    def get_vector_address(self, interrupt: int) -> int:
        """Get the memory address of an interrupt vector."""
        return self.ivt_base + (interrupt * 4)