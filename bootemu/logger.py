"""
Simple hierarchical logger for the x86 Real Mode Bootloader Emulator.

Message routing:
- console(): stdout only (setup info, summary, errors)
- interrupt(): interrupts.log + instructions.log
- instruction(): instructions.log only
"""

from pathlib import Path


class EmulatorLogger:
    """Dumb message router: console | interrupts.log | instructions.log"""

    def __init__(self, image_path: str):
        """Initialize logger with output files based on image basename.

        Args:
            image_path: Path to disk image (used to derive log filenames)
        """
        # Derive log filenames from image basename
        basename = Path(image_path).stem
        self.instr_path = f"{basename}.instructions.log"
        self.int_path = f"{basename}.interrupts.log"

        # File handles
        self._instr_file = open(self.instr_path, "w", buffering=1)
        self._int_file = open(self.int_path, "w", buffering=1)

    def console(self, msg: str) -> None:
        """Write to console only."""
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
        self._instr_file.close()
        self._int_file.close()
