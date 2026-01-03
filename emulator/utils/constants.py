"""
Constants for the x86 Real Mode Bootloader Emulator
"""

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

# Standard floppy geometries (size_bytes: (cylinders, heads, sectors, name))
FLOPPY_TYPES = {
    '360K':  (40, 2, 9,  360 * 1024),
    '720K':  (80, 2, 9,  720 * 1024),
    '1.2M':  (80, 2, 15, 1200 * 1024),
    '1.44M': (80, 2, 18, 1440 * 1024),
    '2.88M': (80, 2, 36, 2880 * 1024),
}

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
DEFAULT_MAX_INSTRUCTIONS = 1000000
DEFAULT_MEMORY_SIZE_KB = 640
DEFAULT_DRIVE_NUMBER_HDD = 0x80
DEFAULT_DRIVE_NUMBER_FLOPPY = 0x00