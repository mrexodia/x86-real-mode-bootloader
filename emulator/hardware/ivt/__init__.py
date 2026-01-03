"""
Interrupt Vector Table (IVT) management for the x86 Real Mode Bootloader Emulator
"""

from .ivt_manager import IVTManager, IVT_NAMES

__all__ = ["IVTManager", "IVT_NAMES"]