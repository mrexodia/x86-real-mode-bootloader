"""
Trace output management for the x86 Real Mode Bootloader Emulator
"""

import sys
from pathlib import Path
from typing import TextIO, Optional
from datetime import datetime


class TraceOutputManager:
    """Manages trace output to files and console."""
    
    def __init__(self, trace_file: Optional[str] = None, 
                 verbose: bool = True):
        """Initialize trace output manager."""
        self.trace_file = trace_file
        self.verbose = verbose
        self.file_handle: Optional[TextIO] = None
        self.console_output = sys.stdout
        
        # Statistics
        self.instruction_count = 0
        self.memory_read_count = 0
        self.memory_write_count = 0
        self.interrupt_count = 0
        
        # Open trace file if specified
        if trace_file:
            self.open_trace_file()
    
    def open_trace_file(self) -> None:
        """Open trace file for writing."""
        if self.file_handle:
            return
            
        try:
            # Create directory if it doesn't exist
            trace_path = Path(self.trace_file)
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Open file
            self.file_handle = open(trace_path, 'w', buffering=1)
            
            # Write header
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.write_line(f"# x86 Real Mode Bootloader Emulator Trace")
            self.write_line(f"# Generated: {timestamp}")
            self.write_line("")
            
        except IOError as e:
            print(f"Warning: Cannot open trace file '{self.trace_file}': {e}")
            self.file_handle = None
    
    def write_line(self, line: str, console: bool = True) -> None:
        """Write a line to trace outputs."""
        # Write to file if open
        if self.file_handle:
            self.file_handle.write(line + "\n")
        
        # Write to console if enabled
        if console and self.verbose:
            self.console_output.write(line + "\n")
    
    def write_instruction(self, insn_line: str, console: bool = True) -> None:
        """Write an instruction trace."""
        self.write_line(insn_line, console)
        self.instruction_count += 1
    
    def write_memory_access(self, access_line: str, console: bool = True) -> None:
        """Write a memory access trace."""
        self.write_line(access_line, console)
        if "READ" in access_line:
            self.memory_read_count += 1
        elif "WRITE" in access_line:
            self.memory_write_count += 1
    
    def write_interrupt(self, interrupt_line: str, console: bool = True) -> None:
        """Write an interrupt trace."""
        self.write_line(interrupt_line, console)
        self.interrupt_count += 1
    
    def write_memory_content(self, content_lines: str, console: bool = True) -> None:
        """Write memory content (multiple lines)."""
        for line in content_lines.split('\n'):
            if line.strip():
                self.write_line(line, console)
    
    def write_separator(self, char: str = "-", length: int = 60, 
                       console: bool = True) -> None:
        """Write a separator line."""
        separator = char * length
        self.write_line(separator, console)
    
    def write_header(self, title: str, console: bool = True) -> None:
        """Write a section header."""
        self.write_separator("=", console)
        self.write_line(f"{title}", console)
        self.write_separator("=", console)
    
    def write_section_header(self, title: str, console: bool = True) -> None:
        """Write a subsection header."""
        self.write_separator("-", console)
        self.write_line(title, console)
        self.write_separator("-", console)
    
    def write_statistics(self, console: bool = True) -> None:
        """Write execution statistics."""
        self.write_section_header("Emulation Statistics", console)
        
        stats = [
            f"Instructions executed: {self.instruction_count:,}",
            f"Memory reads: {self.memory_read_count:,}",
            f"Memory writes: {self.memory_write_count:,}",
            f"Interrupts handled: {self.interrupt_count:,}",
            f"Total operations: {self.instruction_count + self.memory_read_count + self.memory_write_count + self.interrupt_count:,}"
        ]
        
        for stat in stats:
            self.write_line(f"    {stat}", console)
    
    def close(self) -> None:
        """Close trace file."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
            
            # Print summary to console
            if self.verbose:
                print(f"[*] Trace written to {self.trace_file}")
                print(f"    Total instructions: {self.instruction_count:,}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()