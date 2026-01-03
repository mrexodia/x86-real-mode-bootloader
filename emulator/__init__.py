"""
x86 Real Mode Bootloader Emulator

A modular emulator for x86 real mode bootloaders using Unicorn Engine and Capstone.
"""

from .core.emulator import BootloaderEmulator

__version__ = "1.0.0"
__all__ = ["BootloaderEmulator"]