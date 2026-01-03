"""
Disk parameter table structures for the x86 Real Mode Bootloader Emulator
"""

import ctypes
from ctypes import c_uint8, c_uint16
from typing import Annotated

from ...types.c_types import c_struct, c_array

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