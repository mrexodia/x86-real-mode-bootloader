import sys
import struct
import ctypes
from ctypes import c_uint8, c_uint16, c_uint32
import re

from typing import (
    Optional,
    Tuple,
    Annotated,
    get_args,
    get_origin,
    Protocol,
    Any,
    List,
    TYPE_CHECKING,
)

# =============================================================================
# Field Marker System for BDA Policies
# =============================================================================


class FieldMarker:
    """Base class for annotation markers"""

    pass


class BDAPolicy:
    """BDA write policy enum"""

    PASSIVE = 0  # Allow writes, just log them
    BIOS_OWNED = 1  # Writes trigger hardware sync (not yet implemented)
    DENY = 2  # Block writes and halt emulation


class BDAPolicyMarker(FieldMarker):
    """Marker that indicates the BDA write policy for a field"""

    def __init__(self, policy: int):
        self.policy = policy


def bios_owned() -> BDAPolicyMarker:
    """Mark a field as BIOS-owned (writes trigger hardware sync)"""
    return BDAPolicyMarker(BDAPolicy.BIOS_OWNED)


def passive() -> BDAPolicyMarker:
    """Mark a field as passive (writes are allowed, just logged)"""
    return BDAPolicyMarker(BDAPolicy.PASSIVE)


def deny() -> BDAPolicyMarker:
    """Mark a field as denied (writes are blocked and halt emulation)"""
    return BDAPolicyMarker(BDAPolicy.DENY)


# =============================================================================
# Type Hints
# =============================================================================


class c_array(Protocol):
    """Type hint for ctypes arrays"""

    def __getitem__(self, index: int) -> int: ...
    def __setitem__(self, index: int, value: int) -> None: ...
    def __len__(self) -> int: ...
    def __iter__(self): ...


class _CStructMeta(type(ctypes.LittleEndianStructure)):
    """Metaclass for ctypes structures with annotation support and comment extraction"""

    def __new__(mcs, name, bases, namespace):
        # Get annotations - support both Python 3.13- (__annotations__) and 3.14+ (__annotate_func__)
        annotations = None
        if "__annotations__" in namespace:
            annotations = namespace["__annotations__"]
        elif "__annotate_func__" in namespace:
            # Python 3.14+ with PEP 649 deferred evaluation
            try:
                import annotationlib  # type: ignore

                annotations = namespace["__annotate_func__"](annotationlib.Format.VALUE)
            except Exception:
                pass

        if annotations:
            fields = []
            comments = {}
            field_annotations = {}  # field_name -> [extra args from Annotated]
            field_offsets = {}  # field_name -> (offset, size)
            current_offset = 0

            # Build fields from annotations
            for field_name, annotation in annotations.items():
                # Handle Annotated types
                origin = get_origin(annotation)
                if origin is Annotated:
                    args = get_args(annotation)
                    ctypes_type = args[1]  # The actual ctypes type
                    extra_args = (
                        list(args[2:]) if len(args) > 2 else []
                    )  # Everything after the ctype

                    field_size = ctypes.sizeof(ctypes_type)
                    fields.append((field_name, ctypes_type))

                    if extra_args:
                        field_annotations[field_name] = extra_args

                    field_offsets[field_name] = (current_offset, field_size)
                    current_offset += field_size
                else:
                    field_size = ctypes.sizeof(annotation)
                    fields.append((field_name, annotation))
                    field_offsets[field_name] = (current_offset, field_size)
                    current_offset += field_size

            # Extract comments from source code
            frame = sys._getframe(1)
            filename = frame.f_code.co_filename
            lineno = frame.f_lineno
            with open(filename, "r") as f:
                lines = f.readlines()
                for i in range(lineno - 1, max(0, lineno - 200), -1):
                    line = lines[i]
                    match = re.match(r"\s*(\w+):\s*[\w\[\]\*,\s]+\s*#\s*(.+)", line)
                    if match:
                        comments[match.group(1)] = match.group(2).strip()

            namespace["_fields_"] = fields
            namespace["_field_comments"] = comments
            namespace["_field_annotations"] = field_annotations
            namespace["_field_offsets"] = field_offsets

        return super().__new__(mcs, name, bases, namespace)


class c_struct(ctypes.LittleEndianStructure, metaclass=_CStructMeta):
    """Base class for ctypes structures with annotation support"""

    _pack_ = 1

    @classmethod
    def get_field_at_offset(cls, offset: int) -> Optional[Tuple[str, str, int]]:
        """Find field at given offset within structure."""
        for field_name, (field_offset, field_size) in cls._field_offsets.items():  # type: ignore
            if field_offset <= offset < field_offset + field_size:
                comment = getattr(cls, "_field_comments", {}).get(field_name, "")
                return (field_name, comment, field_size)
        return None

    @classmethod
    def get_field_markers(cls, field_name: str, marker_type: type) -> List[Any]:
        """Get all markers of a specific type for a field."""
        annotations = getattr(cls, "_field_annotations", {}).get(field_name, [])
        return [a for a in annotations if isinstance(a, marker_type)]

    @classmethod
    def get_field_marker(cls, field_name: str, marker_type: type) -> Optional[Any]:
        """Get first marker of a specific type for a field, or None."""
        markers = cls.get_field_markers(field_name, marker_type)
        return markers[0] if markers else None

    @classmethod
    def get_markers_at_offset(cls, offset: int, marker_type: type) -> List[Any]:
        """Get all markers of a specific type at a byte offset."""
        field_info = cls.get_field_at_offset(offset)
        if field_info:
            return cls.get_field_markers(field_info[0], marker_type)
        return []


class BIOSDataArea(c_struct):
    """BIOS Data Area (BDA) at 0x0040:0x0000 (physical 0x00400)"""

    com1_port: Annotated[int, c_uint16]  # 0x000: Serial port 1 address
    com2_port: Annotated[int, c_uint16]  # 0x002: Serial port 2 address
    com3_port: Annotated[int, c_uint16]  # 0x004: Serial port 3 address
    com4_port: Annotated[int, c_uint16]  # 0x006: Serial port 4 address
    lpt1_port: Annotated[int, c_uint16]  # 0x008: Parallel port 1 address
    lpt2_port: Annotated[int, c_uint16]  # 0x00A: Parallel port 2 address
    lpt3_port: Annotated[int, c_uint16]  # 0x00C: Parallel port 3 address
    ebda_segment: Annotated[int, c_uint16]  # 0x00E: Extended BIOS Data Area segment
    equipment_list: Annotated[
        int, c_uint16
    ]  # 0x010: Equipment word (installed hardware)
    manufacturing_test: Annotated[int, c_uint8]  # 0x012: Manufacturing test status
    memory_size_kb: Annotated[int, c_uint16]  # 0x013: Memory size in KB
    _pad1: Annotated[int, c_uint8]  # 0x015: Padding/unused
    ps2_ctrl_flags: Annotated[int, c_uint8]  # 0x016: PS/2 controller flags
    keyboard_flags: Annotated[
        int, c_uint16, bios_owned()
    ]  # 0x017: Keyboard status flags (combined)
    alt_keypad_entry: Annotated[int, c_uint8]  # 0x019: Alt-keypad numeric entry
    kbd_buffer_head: Annotated[
        int, c_uint16, bios_owned()
    ]  # 0x01A: Keyboard buffer head pointer
    kbd_buffer_tail: Annotated[
        int, c_uint16, bios_owned()
    ]  # 0x01C: Keyboard buffer tail pointer
    kbd_buffer: Annotated[
        c_array, c_uint8 * 32, bios_owned()
    ]  # 0x01E: Keyboard circular buffer
    diskette_calib_status: Annotated[
        int, c_uint8
    ]  # 0x03E: Floppy drive calibration status
    diskette_motor_status: Annotated[int, c_uint8]  # 0x03F: Floppy motor status
    diskette_motor_timeout: Annotated[
        int, c_uint8
    ]  # 0x040: Floppy motor shutoff counter
    diskette_last_status: Annotated[int, c_uint8]  # 0x041: Last floppy operation status
    diskette_controller: Annotated[
        c_array, c_uint8 * 7
    ]  # 0x042: Floppy controller status bytes
    video_mode: Annotated[int, c_uint8, bios_owned()]  # 0x049: Current video mode
    video_columns: Annotated[
        int, c_uint16, bios_owned()
    ]  # 0x04A: Number of text columns
    video_page_size: Annotated[int, c_uint16]  # 0x04C: Video page size in bytes
    video_page_offset: Annotated[
        int, c_uint16
    ]  # 0x04E: Current page offset in video RAM
    cursor_pos: Annotated[
        c_array, c_uint16 * 8, bios_owned()
    ]  # 0x050: Cursor position for 8 pages (row<<8|col)
    cursor_shape: Annotated[
        int, c_uint16, bios_owned()
    ]  # 0x060: Cursor shape (start_line<<8|end_line)
    active_page: Annotated[
        int, c_uint8, bios_owned()
    ]  # 0x062: Active display page number
    video_port: Annotated[
        int, c_uint16
    ]  # 0x063: Video controller I/O port base (3B4h/3D4h)
    video_mode_reg: Annotated[
        int, c_uint8
    ]  # 0x065: Current video mode register setting
    video_palette: Annotated[int, c_uint8]  # 0x066: Current color palette setting
    cassette_data: Annotated[
        c_array, c_uint8 * 5
    ]  # 0x067: Cassette tape data (obsolete)
    timer_counter: Annotated[
        int, c_uint32, bios_owned()
    ]  # 0x06C: Timer ticks since midnight
    timer_overflow: Annotated[
        int, c_uint8, bios_owned()
    ]  # 0x070: Timer 24-hour rollover flag
    break_flag: Annotated[int, c_uint8]  # 0x071: Ctrl+Break flag
    reset_flag: Annotated[int, c_uint16]  # 0x072: Soft reset flag (0x1234=warm boot)
    hard_disk_status: Annotated[int, c_uint8]  # 0x074: Last hard disk operation status
    num_hard_disks: Annotated[int, c_uint8]  # 0x075: Number of hard disks
    hard_disk_control: Annotated[int, c_uint8]  # 0x076: Hard disk control byte
    hard_disk_offset: Annotated[int, c_uint8]  # 0x077: Hard disk I/O port offset
    lpt1_timeout: Annotated[int, c_uint8]  # 0x078: LPT1 timeout value
    lpt2_timeout: Annotated[int, c_uint8]  # 0x079: LPT2 timeout value
    lpt3_timeout: Annotated[int, c_uint8]  # 0x07A: LPT3 timeout value
    lpt4_timeout: Annotated[int, c_uint8]  # 0x07B: LPT4 timeout value (rarely used)
    com1_timeout: Annotated[int, c_uint8]  # 0x07C: COM1 timeout value
    com2_timeout: Annotated[int, c_uint8]  # 0x07D: COM2 timeout value
    com3_timeout: Annotated[int, c_uint8]  # 0x07E: COM3 timeout value
    com4_timeout: Annotated[int, c_uint8]  # 0x07F: COM4 timeout value
    kbd_buffer_start: Annotated[int, c_uint16]  # 0x080: Keyboard buffer start offset
    kbd_buffer_end: Annotated[int, c_uint16]  # 0x082: Keyboard buffer end offset
    video_rows: Annotated[int, c_uint8]  # 0x084: Number of text rows minus 1
    char_height: Annotated[int, c_uint16]  # 0x085: Character height in scan lines
    video_control: Annotated[int, c_uint8]  # 0x087: Video display control flags
    video_switches: Annotated[int, c_uint8]  # 0x088: Video display switch settings

    # Extended BDA fields (PC/AT and later)
    video_modeset_ctrl: Annotated[int, c_uint8]  # 0x089: Video mode set control options
    video_dcc_index: Annotated[int, c_uint8]  # 0x08A: Display Combination Code index
    floppy_data_rate: Annotated[int, c_uint8]  # 0x08B: Last floppy data rate selected
    hard_disk_status_reg: Annotated[int, c_uint8]  # 0x08C: Hard disk status register
    hard_disk_error: Annotated[int, c_uint8]  # 0x08D: Hard disk error register
    hard_disk_int_control: Annotated[
        int, c_uint8
    ]  # 0x08E: Hard disk interrupt control flag
    floppy_disk_info: Annotated[int, c_uint8]  # 0x08F: Floppy/hard disk card info
    floppy_media_state: Annotated[
        c_array, c_uint8 * 4
    ]  # 0x090: Media state for drives 0-3
    floppy_track: Annotated[c_array, c_uint8 * 2]  # 0x094: Current track for drives 0-1
    kbd_mode_flags: Annotated[int, c_uint8]  # 0x096: Keyboard mode flags and type
    kbd_led_flags: Annotated[int, c_uint8]  # 0x097: Keyboard LED flags
    user_wait_flag_ptr: Annotated[
        int, c_uint32
    ]  # 0x098: Pointer to user wait complete flag (seg:off)
    user_wait_count: Annotated[
        int, c_uint32
    ]  # 0x09C: User wait timeout in microseconds
    wait_active_flag: Annotated[int, c_uint8]  # 0x0A0: RTC wait function active flag
    _reserved1: Annotated[c_array, c_uint8 * 7]  # 0x0A1: Reserved
    video_save_ptr_table: Annotated[
        int, c_uint32
    ]  # 0x0A8: Pointer to video save pointer table (seg:off)
    _reserved2: Annotated[
        c_array, c_uint8 * (256 - 0xAC)
    ]  # 0x0AC: Reserved/BIOS-specific area

    @classmethod
    def get_policy_at_offset(cls, offset: int) -> int:
        """Get write policy for a byte offset in the BDA."""
        markers = cls.get_markers_at_offset(offset, BDAPolicyMarker)
        if markers:
            return markers[0].policy
        return BDAPolicy.PASSIVE


class DiskParameterTable(c_struct):
    """Diskette Parameter Table (INT 0x1E)"""

    step_rate_head_unload: Annotated[int, c_uint8]
    head_load_dma: Annotated[int, c_uint8]
    motor_off_delay: Annotated[int, c_uint8]
    bytes_per_sector: Annotated[int, c_uint8]
    sectors_per_track: Annotated[int, c_uint8]
    gap_length: Annotated[int, c_uint8]
    data_length: Annotated[int, c_uint8]
    format_gap: Annotated[int, c_uint8]
    format_fill: Annotated[int, c_uint8]
    head_settle: Annotated[int, c_uint8]
    motor_start: Annotated[int, c_uint8]


class FixedDiskParameterTable(c_struct):
    """Fixed Disk Parameter Table (INT 0x41)"""

    cylinders: Annotated[int, c_uint16]
    heads: Annotated[int, c_uint8]
    reduced_write_current: Annotated[int, c_uint16]
    write_precomp: Annotated[int, c_uint16]
    ecc_burst: Annotated[int, c_uint8]
    control_byte: Annotated[int, c_uint8]
    timeout_1: Annotated[int, c_uint8]
    timeout_2: Annotated[int, c_uint8]
    timeout_3: Annotated[int, c_uint8]
    landing_zone: Annotated[int, c_uint16]
    sectors_per_track: Annotated[int, c_uint8]
    reserved: Annotated[int, c_uint8]


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

if TYPE_CHECKING:
    from bootemu.emulator import BootloaderEmulator


def handle_int10(emu: "BootloaderEmulator"):
    """Handle INT 0x10 - Video Services"""
    ah = (emu.regs.ax >> 8) & 0xFF

    if ah == 0x00:
        # Set video mode
        al = emu.regs.ax & 0xFF
        emu.log.interrupt(f"[INT 0x10] Set video mode: 0x{al:02x}")

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
        bh = (emu.regs.bx >> 8) & 0xFF  # Page number
        dh = (emu.regs.dx >> 8) & 0xFF  # Row
        dl = emu.regs.dx & 0xFF  # Column

        emu.log.interrupt(
            f"[INT 0x10] Set cursor position: page={bh}, row={dh}, col={dl}"
        )

        # Update cursor position in BDA (0x0450 + page*2)
        if emu.bda and bh < 8:  # Only 8 pages
            # Cursor position is stored as (row << 8) | col
            emu.bda.cursor_pos[bh] = (dh << 8) | dl
            # Write updated BDA to memory
            emu.write_bda_to_memory()

    elif ah == 0x03:
        # Get cursor position and shape
        bh = (emu.regs.bx >> 8) & 0xFF  # Page number

        emu.log.interrupt(f"[INT 0x10] Get cursor position: page={bh}")

        # Read cursor position from BDA
        if emu.bda and bh < 8:
            cursor_pos = emu.bda.cursor_pos[bh]
            row = (cursor_pos >> 8) & 0xFF
            col = cursor_pos & 0xFF
            cursor_shape = emu.bda.cursor_shape

            # Return in DX (DH=row, DL=column) and CX (cursor shape)
            emu.regs.dx = row << 8 | col
            emu.regs.cx = cursor_shape

            emu.log.interrupt(
                f"  - Returning: row={row}, col={col}, shape=0x{cursor_shape:04x}"
            )
        else:
            # Default if BDA not available
            emu.regs.dx = 0x0000
            emu.regs.cx = 0x0607  # Default cursor shape

    elif ah == 0x0E:
        # Teletype output
        al = emu.regs.ax & 0xFF
        if al == 0x0D:
            char = "\r"
        elif al == 0x0A:
            char = "\n"
        else:
            char = chr(al) if 32 <= al < 127 else f"\\x{al:02x}"
        emu.log.interrupt(f"[INT 0x10] Teletype output: {repr(char)}")
        emu.screen_output += char

    elif ah == 0x0F:
        # Get current video mode
        emu.log.interrupt("[INT 0x10] Get current video mode")

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
        emu.regs.ax = video_columns << 8 | video_mode
        emu.regs.bx = (emu.regs.bx & 0x00FF) | (active_page << 8)

        emu.log.interrupt(
            f"  - Returning: mode=0x{video_mode:02x}, columns={video_columns}, page={active_page}"
        )

    elif ah == 0x1A:
        # Get Display Combination Code
        al = emu.regs.ax & 0xFF
        emu.log.interrupt(f"[INT 0x10] Get Display Combination Code: al=0x{al:02x}")

        # Return: AL=0x1A (function supported), BL=display combination code
        # Display combination code 0x08 = VGA with color display
        emu.regs.ax = 0x1A00
        emu.regs.bx = emu.regs.bx & 0xFF00 | 0x08

        # Clear CF (success)
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

        emu.log.interrupt("  - Returning: AL=0x1A, BL=0x08 (VGA color)")

    elif ah == 0x1B:
        # Get Functionality/State Information
        al = emu.regs.ax & 0xFF
        bx = emu.regs.bx & 0xFF
        emu.log.interrupt(
            f"[INT 0x10] Get Functionality/State Information: AL=0x{al:02x}, BL=0x{bx:02x}"
        )

        if bx == 0x00:
            # Return functionality state information
            # ES:DI = buffer for returning state information
            # For simplicity, return unsupported
            flags = emu.regs.flags
            emu.regs.flags = flags | 0x0001  # Set CF (error)
        else:
            # Other BL values - return error
            flags = emu.regs.flags
            emu.regs.flags = flags | 0x0001  # Set CF (error)

    else:
        emu.log.interrupt(f"[INT 0x10] Unhandled function AH=0x{ah:02x}")
        emu.stop()


def handle_int13(emu: "BootloaderEmulator"):
    """Handle INT 0x13 - Disk Services"""
    # Read all registers at the beginning
    ax = emu.regs.ax
    ah = (ax >> 8) & 0xFF
    al = ax & 0xFF

    bx = emu.regs.bx
    cx = emu.regs.cx
    ch = (cx >> 8) & 0xFF
    cl = cx & 0xFF

    dx = emu.regs.dx
    dh = (dx >> 8) & 0xFF
    dl = dx & 0xFF

    si = emu.regs.si
    es = emu.regs.es
    ds = emu.regs.ds
    flags = emu.regs.flags

    # Default return values
    ret_ah = 0x00  # Success by default
    ret_al = al  # Preserve AL by default
    error = False  # Clear carry by default (success)

    # Validate drive number for most operations
    if ah not in [0x00, 0x08, 0x15, 0x41, 0x42, 0x48] and dl != emu.drive_number:
        emu.log.interrupt(
            f"[INT 0x13] Function AH=0x{ah:02x} for drive 0x{dl:02x} - drive not found"
        )
        ret_ah = 0x80  # Drive not ready/timeout
        error = True

    elif ah == 0x00:
        # Reset disk system
        emu.log.interrupt(f"[INT 0x13] Reset disk system for drive 0x{dl:02x}")
        ret_ah = 0x00

    elif ah == 0x01:
        # Get disk status
        emu.log.interrupt(f"[INT 0x13] Get disk status for drive 0x{dl:02x}")
        ret_ah = 0x00
        ret_al = 0x00  # Last operation status (no error)

    elif ah == 0x02:
        # Read sectors (CHS addressing)
        cylinder = ch | ((cl & 0xC0) << 2)
        sector = cl & 0x3F
        head = dh
        sectors_to_read = al
        buffer_addr = (es << 4) + bx

        emu.log.interrupt(f"[INT 0x13] Read sectors (CHS) for drive 0x{dl:02x}")
        emu.log.interrupt(
            f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={sectors_to_read}"
        )
        emu.log.interrupt(f"  - Buffer: 0x{es:04x}:0x{bx:04x} (0x{buffer_addr:05x})")

        # Validate CHS values
        if sector == 0 or sector > emu.sectors_per_track:
            emu.log.interrupt(
                f"  ⚠ Invalid sector: {sector} (valid: 1-{emu.sectors_per_track})"
            )
            ret_ah = 0x04  # Sector not found
            ret_al = 0x00
            error = True
        elif cylinder >= emu.cylinders or head >= emu.heads:
            emu.log.interrupt(
                f"  ⚠ Invalid CHS: C={cylinder} H={head} (max: {emu.cylinders - 1}C, {emu.heads - 1}H)"
            )
            ret_ah = 0x04  # Sector not found
            ret_al = 0x00
            error = True
        else:
            lba = (cylinder * emu.heads + head) * emu.sectors_per_track + (sector - 1)

            emu.log.interrupt(f"  - Converted to LBA: {lba}")

            disk_offset = lba * 512
            bytes_to_read = sectors_to_read * 512

            if disk_offset + bytes_to_read > emu.disk_size:
                emu.log.interrupt("  ⚠ Read beyond disk image!")
                ret_ah = 0x04  # Sector not found
                ret_al = 0x00
                error = True
            else:
                for i in range(sectors_to_read):
                    sector_data = emu.sector_read(lba + i)
                    emu.log.interrupt(
                        f"  ✓ Read {bytes_to_read} bytes from LBA {lba} to 0x{buffer_addr:05x}"
                    )
                    emu.log.interrupt(
                        f"  - Data (32 bytes): {sector_data[:32].hex(' ')}"
                    )
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

        emu.log.interrupt(f"[INT 0x13] Write sectors (CHS) for drive 0x{dl:02x}")
        emu.log.interrupt(
            f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={sectors_to_write}"
        )
        emu.log.interrupt(f"  - Buffer: 0x{es:04x}:0x{bx:04x} (0x{buffer_addr:05x})")

        lba = (cylinder * emu.heads + head) * emu.sectors_per_track + (sector - 1)

        emu.log.interrupt(f"  - Converted to LBA: {lba}")

        disk_offset = lba * 512
        bytes_to_write = sectors_to_write * 512

        if disk_offset + bytes_to_write <= emu.disk_size:
            data = emu.mem_read(buffer_addr, bytes_to_write)
            for i in range(sectors_to_write):
                sector_data = data[i * 512 : (i + 1) * 512]
                emu.log.interrupt(
                    f"    - Writing sector {i + 1}/{sectors_to_write} to LBA {lba + i}"
                )
                emu.sector_write(lba + i, sector_data)

            emu.log.interrupt(
                f"  ✓ Wrote {bytes_to_write} bytes to LBA {lba} from 0x{buffer_addr:05x}"
            )
            emu.log.interrupt(f"  - Data (32 bytes): {bytes(data[:32]).hex(' ')}")

            ret_ah = 0x00
            ret_al = sectors_to_write  # Sectors actually written
        else:
            emu.log.interrupt("  ⚠ Write beyond disk image!")
            ret_ah = 0x04  # Sector not found
            ret_al = 0x00
            error = True

    elif ah == 0x04:
        # Verify sectors (CHS addressing)
        cylinder = ch | ((cl & 0xC0) << 2)
        sector = cl & 0x3F
        head = dh
        sectors_to_verify = al

        emu.log.interrupt(f"[INT 0x13] Verify sectors (CHS) for drive 0x{dl:02x}")
        emu.log.interrupt(
            f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={sectors_to_verify}"
        )

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
        emu.log.interrupt(f"[INT 0x13] Get drive parameters for drive 0x{dl:02x}")

        if dl < 0x80:  # Floppy
            ret_ah = 0x01  # Invalid parameter for now
            error = True
        else:
            max_cylinder = emu.cylinders - 1
            max_head = emu.heads - 1
            sectors = emu.sectors_per_track

            # Build CX register: sectors in low 6 bits, cylinder in upper 10 bits
            cx_value = (
                sectors | ((max_cylinder & 0x300) >> 2) | ((max_cylinder & 0xFF) << 8)
            )
            dx_value = 1 | (max_head << 8)  # DL = number of drives, DH = max head

            emu.regs.cx = cx_value
            emu.regs.dx = dx_value

            ret_ah = 0x00

            emu.log.interrupt(
                f"  - Returning geometry: C={emu.cylinders}, H={emu.heads}, S={emu.sectors_per_track}"
            )
            emu.log.interrupt(f"  - CX=0x{cx_value:04x}, DX=0x{dx_value:04x}")

    elif ah == 0x0C:
        # Seek to track (CHS addressing)
        cylinder = ch | ((cl & 0xC0) << 2)
        head = dh

        emu.log.interrupt(f"[INT 0x13] Seek to track for drive 0x{dl:02x}")
        emu.log.interrupt(f"  - Cylinder={cylinder}, Head={head}")

        if cylinder < emu.cylinders and head < emu.heads:
            ret_ah = 0x00
        else:
            ret_ah = 0x40  # Seek failure
            error = True

    elif ah == 0x0D:
        # Reset hard disk controller
        emu.log.interrupt(f"[INT 0x13] Reset hard disk controller for drive 0x{dl:02x}")
        ret_ah = 0x00

    elif ah == 0x15:
        # Get disk type - WRITES CX/DX for fixed disks
        emu.log.interrupt(f"[INT 0x13] Get disk type for drive 0x{dl:02x}")

        if dl < 0x80:
            ret_ah = 0x00  # No disk or unsupported
            error = True
        else:
            ret_ah = 0x03  # Fixed disk installed
            # For AH=0x03, return disk size in CX:DX
            total_sectors = emu.disk_size // 512
            emu.regs.cx = total_sectors >> 16 & 0xFFFF
            emu.regs.dx = total_sectors & 0xFFFF

    elif ah == 0x41:
        # Check INT 13 extensions present - WRITES BX/CX
        emu.log.interrupt(f"[INT 0x13] Check extensions present for drive 0x{dl:02x}")

        if bx == 0x55AA:
            ret_ah = 0x30  # Version 3.0
            emu.regs.bx = 0xAA55  # Reversed signature
            emu.regs.cx = 0x0007  # Support bits
        else:
            ret_ah = 0x01  # Invalid function
            error = True

    elif ah == 0x42:
        # Extended read - LBA
        emu.log.interrupt(f"[INT 0x13] Extended read for drive 0x{dl:02x}")

        packet_addr = (ds << 4) + si
        packet = emu.mem_read(packet_addr, 16)

        packet_size = packet[0]
        # Validate packet size (must be at least 16 bytes)
        if packet_size < 16:
            emu.log.interrupt(f"  ⚠ Invalid DAP size: {packet_size} (must be >= 16)")
            ret_ah = 0x01  # Invalid command
            error = True
        else:
            sectors = struct.unpack("<H", packet[2:4])[0]
            offset = struct.unpack("<H", packet[4:6])[0]
            segment = struct.unpack("<H", packet[6:8])[0]
            lba = struct.unpack("<Q", packet[8:16])[0]

            emu.log.interrupt(
                f"  - LBA: {lba}, Sectors: {sectors}, Buffer: 0x{segment:04x}:0x{offset:04x}"
            )

            disk_offset = lba * 512
            buffer_addr = (segment << 4) + offset
            bytes_to_read = sectors * 512

            if disk_offset + bytes_to_read > emu.disk_size:
                emu.log.interrupt("  ⚠ Read beyond disk image!")
                ret_ah = 0x01  # Invalid command
                error = True
            else:
                for i in range(sectors):
                    sector_data = emu.sector_read(lba + i)
                    emu.log.interrupt(
                        f"  ✓ Read sector {i + 1}/{sectors} from LBA {lba + i} to 0x{buffer_addr + i * 512:05x}"
                    )
                    emu.log.interrupt(
                        f"    - Data (32 bytes): {sector_data[:32].hex(' ')}"
                    )
                    emu.mem_write(buffer_addr + i * 512, sector_data)
                ret_ah = 0x00

    elif ah == 0x48:
        # Get extended drive parameters
        emu.log.interrupt(
            f"[INT 0x13] Get extended drive parameters for drive 0x{dl:02x}"
        )

        buffer_addr = (ds << 4) + si
        buffer_header = emu.mem_read(buffer_addr, 2)
        buffer_size = struct.unpack("<H", buffer_header)[0]

        emu.log.interrupt(f"  - Buffer size requested: {buffer_size} bytes")

        total_sectors = emu.disk_size // 512

        params = bytearray(26)
        struct.pack_into("<H", params, 0, 26)
        struct.pack_into("<H", params, 2, 0x0002)
        struct.pack_into("<I", params, 4, emu.cylinders)
        struct.pack_into("<I", params, 8, emu.heads)
        struct.pack_into("<I", params, 12, emu.sectors_per_track)
        struct.pack_into("<Q", params, 16, total_sectors)
        struct.pack_into("<H", params, 24, 512)

        bytes_to_write = min(buffer_size, 26)
        emu.mem_write(buffer_addr, bytes(params[:bytes_to_write]))

        emu.log.interrupt(f"  - Returned {bytes_to_write} bytes")
        emu.log.interrupt(f"  - Total sectors: {total_sectors}")

        ret_ah = 0x00

    else:
        emu.log.interrupt(f"[INT 0x13] Unhandled function AH=0x{ah:02x}")
        emu.stop()
        return

    # Write AH/AL at the end (always needed)
    emu.regs.ax = ret_ah << 8 | ret_al

    # Set or clear carry flag
    if error:
        emu.regs.flags = flags | 0x0001
    else:
        emu.regs.flags = flags & ~0x0001


def handle_int11(emu: "BootloaderEmulator"):
    """Handle INT 0x11 - Get Equipment List"""
    emu.log.interrupt("[INT 0x11] Get equipment list")
    # AX = equipment list word

    # Read from BDA if enabled, otherwise use default
    equipment = emu.bda.equipment_list
    emu.log.interrupt(f"  - Equipment from BDA: 0x{equipment:04x}")

    emu.regs.ax = equipment


def handle_int12(emu: "BootloaderEmulator"):
    """Handle INT 0x12 - Get Memory Size"""
    emu.log.interrupt("[INT 0x12] Get memory size")
    # AX = memory size in KB (conventional memory, typically 640KB)

    memory_size_kb = emu.bda.memory_size_kb
    emu.log.interrupt(f"  - Memory size from BDA: {memory_size_kb} KB")

    emu.regs.ax = memory_size_kb


def handle_int15(emu: "BootloaderEmulator"):
    """Handle INT 0x15 - System Services"""
    ah = (emu.regs.ax >> 8) & 0xFF

    if ah == 0x88:
        # Get extended memory size
        emu.log.interrupt("[INT 0x15] Get extended memory size")
        # AX = extended memory in KB (above 1MB)
        emu.regs.ax = 0  # No extended memory
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0xC0:
        # Get system configuration
        emu.log.interrupt("[INT 0x15] Get system configuration")
        # ES:BX = pointer to configuration table
        # For now, return error
        flags = emu.regs.flags
        emu.regs.flags = flags | 0x0001

    elif ah == 0xE8:
        # E820h - Query System Address Map
        al = emu.regs.ax & 0xFF
        if al == 0x20:
            edx = emu.regs.edx
            ebx = emu.regs.ebx
            ecx = emu.regs.ecx  # Buffer size caller can accept
            es = emu.regs.es
            di = emu.regs.di

            # Check buffer size (need at least 20 bytes for standard entry)
            if ecx < 20:
                emu.log.interrupt(
                    f"[INT 0x15, E820] Buffer too small: {ecx} bytes (need 20)"
                )
                flags = emu.regs.flags
                emu.regs.flags = flags | 0x0001  # Set CF
                return

            # Check for SMAP signature
            if edx != 0x534D4150:  # 'SMAP'
                emu.log.interrupt(f"[INT 0x15, E820] Invalid signature: 0x{edx:08x}")
                flags = emu.regs.flags
                emu.regs.flags = flags | 0x0001  # Set CF
                return

            # Memory map entries
            # Entry format: base_low(4), base_high(4), length_low(4), length_high(4), type(4) = 20 bytes
            memory_map = [
                # Entry 0: 0x00000000 - 0x0009FC00 (639 KB) - Available RAM
                (0x00000000, 0x00000000, 0x0009FC00, 0x00000000, 1),
                # Entry 1: 0x0009FC00 - 0x000A0000 (1 KB) - Reserved (EBDA)
                (0x0009FC00, 0x00000000, 0x00000400, 0x00000000, 2),
                # Entry 2: 0x000A0000 - 0x00100000 (384 KB) - Reserved (VGA/ROM)
                (0x000A0000, 0x00000000, 0x00060000, 0x00000000, 2),
                # Entry 3: 0x00100000 - 0x01000000 (15 MB) - Available RAM
                (0x00100000, 0x00000000, 0x00F00000, 0x00000000, 1),
            ]

            # EBX is the continuation value (entry index)
            entry_index = ebx & 0xFFFF

            if entry_index >= len(memory_map):
                # No more entries
                emu.log.interrupt(
                    f"[INT 0x15, E820] No more entries (index={entry_index})"
                )
                flags = emu.regs.flags
                emu.regs.flags = flags | 0x0001  # Set CF
                return

            # Get the entry
            base_low, base_high, length_low, length_high, mem_type = memory_map[
                entry_index
            ]

            emu.log.interrupt(
                f"[INT 0x15, E820] Entry {entry_index}: base=0x{base_high:08x}{base_low:08x}, "
                f"length=0x{length_high:08x}{length_low:08x}, type={mem_type}"
            )

            # Write entry to ES:DI
            addr = (es << 4) + di
            entry_data = struct.pack(
                "<IIIII", base_low, base_high, length_low, length_high, mem_type
            )
            emu.mem_write(addr, entry_data)

            # Set return values
            emu.regs.eax = 0x534D4150  # 'SMAP' signature
            emu.regs.ecx = 20  # Bytes written

            # Set EBX for next entry (0 if this was the last)
            next_index = entry_index + 1
            if next_index >= len(memory_map):
                emu.regs.ebx = 0  # Last entry
            else:
                emu.regs.ebx = next_index

            # Clear CF to indicate success
            flags = emu.regs.flags
            emu.regs.flags = flags & ~0x0001
        else:
            emu.log.interrupt(f"[INT 0x15] Unhandled E8h subfunction AL=0x{al:02x}")
            flags = emu.regs.flags
            emu.regs.flags = flags | 0x0001

    elif ah == 0x41:
        # Wait on External Event (PC Convertible) - obsolete
        # Also used by some code to probe for non-standard BIOS extensions
        emu.log.interrupt("[INT 0x15] Wait on external event (unsupported)")
        # Return error (set CF)
        flags = emu.regs.flags
        emu.regs.flags = flags | 0x0001

    elif ah == 0x53:
        # APM BIOS functions
        emu.log.interrupt(f"[INT 0x15] APM BIOS function AH=0x{ah:02x}")
        # Return error (unsupported)
        flags = emu.regs.flags
        emu.regs.flags = flags | 0x0001

    else:
        emu.log.interrupt(f"[INT 0x15] Unhandled function AH=0x{ah:02x}")
        emu.stop()


def handle_int16(emu: "BootloaderEmulator"):
    """Handle INT 0x16 - Keyboard Services"""
    ah = (emu.regs.ax >> 8) & 0xFF

    if ah == 0x00:
        # Read keystroke
        emu.log.interrupt("[INT 0x16] Read keystroke")
        # For emulation, simulate pressing Enter (0x1C)
        emu.regs.ax = 0x1C0D  # AL=0x0D (CR), AH=0x1C (scancode)

    elif ah == 0x01:
        # Check for keystroke
        emu.log.interrupt("[INT 0x16] Check for keystroke")
        # ZF=1 if no key available (set ZF)
        flags = emu.regs.flags
        emu.regs.flags = flags | 0x0040  # Set ZF

    elif ah == 0x02:
        # Get shift flags
        emu.log.interrupt("[INT 0x16] Get shift flags")
        emu.regs.ax = 0  # No modifiers

    else:
        emu.log.interrupt(f"[INT 0x16] Unhandled function AH=0x{ah:02x}")
        emu.stop()


def handle_int14(emu: "BootloaderEmulator"):
    """Handle INT 0x14 - Serial Port Services"""
    ah = (emu.regs.ax >> 8) & 0xFF
    dx = emu.regs.dx & 0xFF  # DL = port number

    if ah == 0x00:
        # Initialize serial port
        emu.log.interrupt(f"[INT 0x14] Initialize serial port DL=0x{dx:02x}")
        # Return success: AH = 0 (initialized), AL = line status
        # BIT 7: DCD (Data Carrier Detect), BIT 5: TX Buffer Empty
        emu.regs.ax = emu.regs.ax & 0xFF | 0x2000
        # Clear CF (success)
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x01:
        # Write character to serial port
        al = emu.regs.ax & 0xFF
        emu.log.interrupt(
            f"[INT 0x14] Write character to serial port: 0x{al:02x} ({chr(al) if 32 <= al < 127 else '?'})"
        )
        if al == 0x0D:
            char = "\r"
        elif al == 0x0A:
            char = "\n"
        else:
            char = chr(al) if 32 <= al < 127 else f"\\x{al:02x}"
        emu.serial_output += char
        # Return success in AH = 0 (ready), CF = 0
        emu.regs.ax = emu.regs.ax & 0xFF | 0x0000
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x02:
        # Read character from serial port
        emu.log.interrupt("[INT 0x14] Read character from serial port")
        # Return timeout (AH bit 7 set for error)
        emu.regs.ax = emu.regs.ax & 0xFF | 0x8000
        # Set CF (error/timeout)
        flags = emu.regs.flags
        emu.regs.flags = flags | 0x0001

    elif ah == 0x03:
        # Get serial port status
        emu.log.interrupt("[INT 0x14] Get serial port status")
        # AH = line status (TX buffer empty, etc.)
        # AL = modem status
        emu.regs.ax = 0x6000  # TX buffer empty, ready
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    else:
        emu.log.interrupt(f"[INT 0x14] Unhandled function AH=0x{ah:02x}")
        emu.stop()


def handle_int17(emu: "BootloaderEmulator"):
    """Handle INT 0x17 - Printer Services (return offline status)"""
    ah = (emu.regs.ax >> 8) & 0xFF
    dx = emu.regs.dx & 0xFF  # DL = printer number

    # Printer status byte format:
    # Bit 0: Time out
    # Bit 1: Unused
    # Bit 2: End of paper
    # Bit 3: Selected (1=online, 0=offline)
    # Bit 4: I/O error
    # Bit 5: Unused
    # Bit 6: Unused
    # Bit 7: Not busy (1=ready, 0=busy)
    #
    # Offline status: bits 3 and 7 = 0 (not selected, not ready)
    offline_status = 0x00  # Offline/not ready/not selected

    if ah == 0x00:
        # Print character
        al = emu.regs.ax & 0xFF
        emu.log.interrupt(
            f"[INT 0x17] Print character 0x{al:02x} to printer {dx} (OFFLINE)"
        )
        # Return offline status in AH
        emu.regs.ax = (emu.regs.ax & 0xFF) | (offline_status << 8)
        # Set CF (error - printer offline)
        flags = emu.regs.flags
        emu.regs.flags = flags | 0x0001

    elif ah == 0x01:
        # Initialize printer
        emu.log.interrupt(f"[INT 0x17] Initialize printer {dx} (OFFLINE)")
        # Return offline status in AH
        emu.regs.ax = (emu.regs.ax & 0xFF) | (offline_status << 8)
        # Set CF (error - printer offline)
        flags = emu.regs.flags
        emu.regs.flags = flags | 0x0001

    elif ah == 0x02:
        # Get printer status
        emu.log.interrupt(f"[INT 0x17] Get printer status for printer {dx} (OFFLINE)")
        # Return offline status in AH
        emu.regs.ax = (emu.regs.ax & 0xFF) | (offline_status << 8)
        # Set CF (error - printer offline)
        flags = emu.regs.flags
        emu.regs.flags = flags | 0x0001

    else:
        emu.log.interrupt(f"[INT 0x17] Unhandled function AH=0x{ah:02x}")
        emu.stop()


def handle_int1a(emu: "BootloaderEmulator"):
    """Handle INT 0x1A - Timer/Clock Services"""
    ah = (emu.regs.ax >> 8) & 0xFF

    if ah == 0x00:
        # Get system time (clock ticks since midnight)
        # Returns: CX:DX = number of ticks (1 tick = 1/18.2 seconds)
        emu.log.interrupt("[INT 0x1A] Get system time")
        # Simulate a time value: 65536 ticks = ~1 hour at 18.2 ticks/sec
        # Return a reasonable time like 2 hours into the day
        ticks = 65536 * 2  # ~2 hours worth of ticks
        cx = (ticks >> 16) & 0xFFFF
        dx = ticks & 0xFFFF
        ax = emu.regs.ax & 0xFF
        emu.regs.ax = ax
        emu.regs.cx = cx
        emu.regs.dx = dx
        # Clear CF
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x01:
        # Set system time
        cx = emu.regs.cx
        dx = emu.regs.dx
        emu.log.interrupt(f"[INT 0x1A] Set system time CX:DX=0x{cx:04x}:0x{dx:04x}")
        # Just acknowledge, no real action needed
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x02:
        # Get RTC time (hours, minutes, seconds in BCD)
        # Returns: CH=hours, CL=minutes, DH=seconds, DL=daylight saving (0=standard)
        emu.log.interrupt("[INT 0x1A] Get RTC time")
        # Return a reasonable time: 08:30:45
        hours_bcd = 0x08  # 8 in BCD
        minutes_bcd = 0x30  # 30 in BCD
        seconds_bcd = 0x45  # 45 in BCD
        dst_flag = 0x00  # 0 = standard time
        emu.regs.cx = hours_bcd << 8 | minutes_bcd
        emu.regs.dx = seconds_bcd << 8 | dst_flag
        # Clear CF
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x03:
        # Set RTC time
        cx = emu.regs.cx
        dx = emu.regs.dx
        emu.log.interrupt(f"[INT 0x1A] Set RTC time CX=0x{cx:04x}, DX=0x{dx:04x}")
        # Just acknowledge
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x04:
        # Get RTC date (year, month, day of month in BCD)
        # Returns: CX=year, DH=month, DL=day
        emu.log.interrupt("[INT 0x1A] Get RTC date")
        # Return a reasonable date: 1990-01-15
        year_bcd = 0x1990  # 1990 in BCD format
        month_bcd = 0x01  # January in BCD
        day_bcd = 0x15  # 15th in BCD
        emu.regs.cx = year_bcd
        emu.regs.dx = month_bcd << 8 | day_bcd
        # Clear CF
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x05:
        # Set RTC date
        cx = emu.regs.cx
        dx = emu.regs.dx
        emu.log.interrupt(f"[INT 0x1A] Set RTC date CX=0x{cx:04x}, DX=0x{dx:04x}")
        # Just acknowledge
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x06:
        # Set RTC alarm
        emu.log.interrupt("[INT 0x1A] Set RTC alarm")
        # Just acknowledge
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    elif ah == 0x07:
        # Reset RTC alarm
        emu.log.interrupt("[INT 0x1A] Reset RTC alarm")
        # Just acknowledge
        flags = emu.regs.flags
        emu.regs.flags = flags & ~0x0001

    else:
        emu.log.interrupt(f"[INT 0x1A] Unhandled function AH=0x{ah:02x}")
        emu.stop()
