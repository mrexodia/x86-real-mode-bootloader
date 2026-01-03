"""
BIOS Data Area (BDA) structure definitions
"""

import sys
import ctypes
from ctypes import c_uint8, c_uint16, c_uint32
from typing import Annotated

from ...types.c_types import c_struct, c_array
from .field_markers import bios_owned

class BIOSDataArea(c_struct):
    """BIOS Data Area (BDA) at 0x0040:0x0000 (physical 0x00400)"""
    com1_port: Annotated[int, c_uint16]                   # 0x000: Serial port 1 address
    com2_port: Annotated[int, c_uint16]                   # 0x002: Serial port 2 address
    com3_port: Annotated[int, c_uint16]                   # 0x004: Serial port 3 address
    com4_port: Annotated[int, c_uint16]                   # 0x006: Serial port 4 address
    lpt1_port: Annotated[int, c_uint16]                   # 0x008: Parallel port 1 address
    lpt2_port: Annotated[int, c_uint16]                   # 0x00A: Parallel port 2 address
    lpt3_port: Annotated[int, c_uint16]                   # 0x00C: Parallel port 3 address
    ebda_segment: Annotated[int, c_uint16]                # 0x00E: Extended BIOS Data Area segment
    equipment_list: Annotated[int, c_uint16]              # 0x010: Equipment word (installed hardware)
    manufacturing_test: Annotated[int, c_uint8]           # 0x012: Manufacturing test status
    memory_size_kb: Annotated[int, c_uint16]              # 0x013: Memory size in KB
    _pad1: Annotated[int, c_uint8]                        # 0x015: Padding/unused
    ps2_ctrl_flags: Annotated[int, c_uint8]               # 0x016: PS/2 controller flags
    keyboard_flags: Annotated[int, c_uint16, bios_owned()] # 0x017: Keyboard status flags (combined)
    alt_keypad_entry: Annotated[int, c_uint8]             # 0x019: Alt-keypad numeric entry
    kbd_buffer_head: Annotated[int, c_uint16, bios_owned()] # 0x01A: Keyboard buffer head pointer
    kbd_buffer_tail: Annotated[int, c_uint16, bios_owned()] # 0x01C: Keyboard buffer tail pointer
    kbd_buffer: Annotated[c_array, c_uint8 * 32, bios_owned()] # 0x01E: Keyboard circular buffer
    diskette_calib_status: Annotated[int, c_uint8]        # 0x03E: Floppy drive calibration status
    diskette_motor_status: Annotated[int, c_uint8]        # 0x03F: Floppy motor status
    diskette_motor_timeout: Annotated[int, c_uint8]       # 0x040: Floppy motor shutoff counter
    diskette_last_status: Annotated[int, c_uint8]         # 0x041: Last floppy operation status
    diskette_controller: Annotated[c_array, c_uint8 * 7]  # 0x042: Floppy controller status bytes
    video_mode: Annotated[int, c_uint8, bios_owned()]     # 0x049: Current video mode
    video_columns: Annotated[int, c_uint16, bios_owned()]  # 0x04A: Number of text columns
    video_page_size: Annotated[int, c_uint16]             # 0x04C: Video page size in bytes
    video_page_offset: Annotated[int, c_uint16]           # 0x04E: Current page offset in video RAM
    cursor_pos: Annotated[c_array, c_uint16 * 8, bios_owned()] # 0x050: Cursor position for 8 pages (row<<8|col)
    cursor_shape: Annotated[int, c_uint16, bios_owned()]  # 0x060: Cursor shape (start_line<<8|end_line)
    active_page: Annotated[int, c_uint8, bios_owned()]    # 0x062: Active display page number
    video_port: Annotated[int, c_uint16]                  # 0x063: Video controller I/O port base (3B4h/3D4h)
    video_mode_reg: Annotated[int, c_uint8]               # 0x065: Current video mode register setting
    video_palette: Annotated[int, c_uint8]                # 0x066: Current color palette setting
    cassette_data: Annotated[c_array, c_uint8 * 5]        # 0x067: Cassette tape data (obsolete)
    timer_counter: Annotated[int, c_uint32, bios_owned()] # 0x06C: Timer ticks since midnight
    timer_overflow: Annotated[int, c_uint8, bios_owned()] # 0x070: Timer 24-hour rollover flag
    break_flag: Annotated[int, c_uint8]                   # 0x071: Ctrl+Break flag
    reset_flag: Annotated[int, c_uint16]                  # 0x072: Soft reset flag (0x1234=warm boot)
    hard_disk_status: Annotated[int, c_uint8]             # 0x074: Last hard disk operation status
    num_hard_disks: Annotated[int, c_uint8]               # 0x075: Number of hard disks
    hard_disk_control: Annotated[int, c_uint8]            # 0x076: Hard disk control byte
    hard_disk_offset: Annotated[int, c_uint8]             # 0x077: Hard disk I/O port offset
    lpt1_timeout: Annotated[int, c_uint8]                 # 0x078: LPT1 timeout value
    lpt2_timeout: Annotated[int, c_uint8]                 # 0x079: LPT2 timeout value
    lpt3_timeout: Annotated[int, c_uint8]                 # 0x07A: LPT3 timeout value
    lpt4_timeout: Annotated[int, c_uint8]                 # 0x07B: LPT4 timeout value (rarely used)
    com1_timeout: Annotated[int, c_uint8]                 # 0x07C: COM1 timeout value
    com2_timeout: Annotated[int, c_uint8]                 # 0x07D: COM2 timeout value
    com3_timeout: Annotated[int, c_uint8]                 # 0x07E: COM3 timeout value
    com4_timeout: Annotated[int, c_uint8]                 # 0x07F: COM4 timeout value
    kbd_buffer_start: Annotated[int, c_uint16]            # 0x080: Keyboard buffer start offset
    kbd_buffer_end: Annotated[int, c_uint16]              # 0x082: Keyboard buffer end offset
    video_rows: Annotated[int, c_uint8]                   # 0x084: Number of text rows minus 1
    char_height: Annotated[int, c_uint16]                 # 0x085: Character height in scan lines
    video_control: Annotated[int, c_uint8]                # 0x087: Video display control flags
    video_switches: Annotated[int, c_uint8]               # 0x088: Video display switch settings

    # Extended BDA fields (PC/AT and later)
    video_modeset_ctrl: Annotated[int, c_uint8]           # 0x089: Video mode set control options
    video_dcc_index: Annotated[int, c_uint8]              # 0x08A: Display Combination Code index
    floppy_data_rate: Annotated[int, c_uint8]             # 0x08B: Last floppy data rate selected
    hard_disk_status_reg: Annotated[int, c_uint8]         # 0x08C: Hard disk status register
    hard_disk_error: Annotated[int, c_uint8]              # 0x08D: Hard disk error register
    hard_disk_int_control: Annotated[int, c_uint8]        # 0x08E: Hard disk interrupt control flag
    floppy_disk_info: Annotated[int, c_uint8]             # 0x08F: Floppy/hard disk card info
    floppy_media_state: Annotated[c_array, c_uint8 * 4]   # 0x090: Media state for drives 0-3
    floppy_track: Annotated[c_array, c_uint8 * 2]         # 0x094: Current track for drives 0-1
    kbd_mode_flags: Annotated[int, c_uint8]               # 0x096: Keyboard mode flags and type
    kbd_led_flags: Annotated[int, c_uint8]                # 0x097: Keyboard LED flags
    user_wait_flag_ptr: Annotated[int, c_uint32]          # 0x098: Pointer to user wait complete flag (seg:off)
    user_wait_count: Annotated[int, c_uint32]             # 0x09C: User wait timeout in microseconds
    wait_active_flag: Annotated[int, c_uint8]             # 0x0A0: RTC wait function active flag
    _reserved1: Annotated[c_array, c_uint8 * 7]           # 0x0A1: Reserved
    video_save_ptr_table: Annotated[int, c_uint32]        # 0x0A8: Pointer to video save pointer table (seg:off)
    _reserved2: Annotated[c_array, c_uint8 * (256 - 0xAC)] # 0x0AC: Reserved/BIOS-specific area

    @classmethod
    def get_policy_at_offset(cls, offset: int) -> int:
        """Get write policy for a byte offset in the BDA."""
        from .field_markers import BDAPolicyMarker, BDAPolicy
        markers = cls.get_markers_at_offset(offset, BDAPolicyMarker)
        if markers:
            return markers[0].policy
        return BDAPolicy.PASSIVE