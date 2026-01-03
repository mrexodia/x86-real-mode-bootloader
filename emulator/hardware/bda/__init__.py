"""
BIOS Data Area (BDA) management for the x86 Real Mode Bootloader Emulator
"""

from .field_markers import (
    FieldMarker,
    BDAPolicy,
    BDAPolicyMarker,
    bios_owned,
    passive,
    deny
)
from .bda_structures import BIOSDataArea

__all__ = [
    "FieldMarker",
    "BDAPolicy",
    "BDAPolicyMarker",
    "bios_owned",
    "passive",
    "deny",
    "BIOSDataArea"
]