"""
Simple hierarchical logger for the x86 Real Mode Bootloader Emulator.

Message routing:
- console(): stdout only (setup info, summary, errors)
- interrupt(): interrupts.log + instructions.log
- instruction(): instructions.log only
"""

from pathlib import Path
from typing import Optional, TextIO


class EmulatorLogger:
    """Dumb message router: console < interrupts.log < instructions.log"""

    def __init__(self, image_path: str, verbose: bool = True):
        """Initialize logger with output files based on image basename.
        
        Args:
            image_path: Path to disk image (used to derive log filenames)
            verbose: If False, suppress console output except errors
        """
        self.verbose = verbose
        
        # Derive log filenames from image basename
        basename = Path(image_path).stem
        self.instr_path = f"{basename}.instructions.log"
        self.int_path = f"{basename}.interrupts.log"
        
        # File handles (opened lazily or on open())
        self._instr_file: Optional[TextIO] = None
        self._int_file: Optional[TextIO] = None
        self._is_open = False

    def open(self) -> None:
        """Open log files for writing."""
        if self._is_open:
            return
        self._instr_file = open(self.instr_path, 'w', buffering=1)
        self._int_file = open(self.int_path, 'w', buffering=1)
        self._is_open = True

    def console(self, msg: str) -> None:
        """Write to console only (respects verbose setting)."""
        if self.verbose:
            print(msg)

    def console_always(self, msg: str) -> None:
        """Write to console always (ignores verbose setting)."""
        print(msg)

    def interrupt(self, msg: str) -> None:
        """Write to interrupts.log + instructions.log."""
        if self._int_file:
            self._int_file.write(msg + "\n")
        if self._instr_file:
            self._instr_file.write(msg + "\n")

    def instruction(self, msg: str) -> None:
        """Write to instructions.log only."""
        if self._instr_file:
            self._instr_file.write(msg + "\n")

    def close(self) -> None:
        """Close log files."""
        if self._instr_file:
            self._instr_file.close()
            self._instr_file = None
        if self._int_file:
            self._int_file.close()
            self._int_file = None
        self._is_open = False

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
