"""
Main tracer for the x86 Real Mode Bootloader Emulator
"""

from typing import Optional, Dict, Any
from unicorn import *
from unicorn.x86_const import *

from .formatters import TraceFormatter
from .output import TraceOutputManager
from .hooks import TracingHooks


class EmulatorTracer:
    """Main tracer that coordinates all tracing activities."""
    
    def __init__(self, mu: Uc, trace_file: Optional[str] = None, 
                 max_instructions: int = 1000000, verbose: bool = True):
        """Initialize emulator tracer."""
        self.mu = mu
        self.max_instructions = max_instructions
        
        # Initialize components
        self.output_manager = TraceOutputManager(trace_file, verbose)
        self.formatter = TraceFormatter(verbose)
        self.hooks = TracingHooks(mu, self.output_manager, self.formatter, max_instructions)
        
        # Tracing state
        self.enabled = True
        self.debug_enabled = False
        
    def start_tracing(self) -> None:
        """Start instruction tracing."""
        if not self.enabled:
            return
            
        self.output_manager.write_header("Instruction Trace Started")
        self.hooks.install_hooks()
        
    def stop_tracing(self) -> None:
        """Stop instruction tracing."""
        self.hooks.remove_hooks()
        self.output_manager.write_section_header("Instruction Trace Completed")
        
    def write_header(self, title: str) -> None:
        """Write a section header to the trace."""
        self.output_manager.write_header(title)
    
    def write_section_header(self, title: str) -> None:
        """Write a subsection header to the trace."""
        self.output_manager.write_section_header(title)
    
    def write_line(self, line: str, console: bool = True) -> None:
        """Write a line to the trace."""
        self.output_manager.write_line(line, console)
    
    def write_separator(self, char: str = "-", length: int = 60) -> None:
        """Write a separator line."""
        self.output_manager.write_separator(char, length)
    
    def write_memory_content(self, address: int, data: bytes, 
                          region_name: str = "", start_offset: int = 0) -> None:
        """Write memory content to the trace."""
        if not self.enabled:
            return
            
        self.output_manager.write_section_header(f"Memory Content: {region_name or f'0x{address:04X}h'}")
        
        # Write memory region info
        self.output_manager.write_line(f"    Address: 0x{address:04X}h")
        self.output_manager.write_line(f"    Size: {len(data)} bytes")
        
        # Write hex dump
        content_lines = self.formatter.format_memory_content(address, data, start_offset)
        self.output_manager.write_memory_content(content_lines, False)  # Never to console
    
    def write_registers(self, regs: Dict[str, int], title: str = "Register State") -> None:
        """Write register state to the trace."""
        if not self.enabled:
            return
            
        self.output_manager.write_section_header(title)
        
        # Format register display
        register_groups = [
            ("General Registers", ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp']),
            ("Segment Registers", ['cs', 'ds', 'es', 'ss']),
            ("Flags", ['flags'])
        ]
        
        for group_name, reg_names in register_groups:
            self.output_manager.write_line(f"  {group_name}:")
            
            reg_line = "    "
            for reg_name in reg_names:
                if reg_name in regs:
                    if reg_name == 'flags':
                        # Format flags with common bits
                        flags = regs['flags']
                        cf = "CF" if (flags & 0x0001) else "cf"
                        pf = "PF" if (flags & 0x0004) else "pf"  
                        af = "AF" if (flags & 0x0010) else "af"
                        zf = "ZF" if (flags & 0x0040) else "zf"
                        sf = "SF" if (flags & 0x0080) else "sf"
                        of = "OF" if (flags & 0x0800) else "of"
                        
                        reg_line += f"{reg_name.upper()}={regs[reg_name]:04X}h ({cf} {pf} {af} {zf} {sf} {of})"
                    else:
                        reg_line += f"{reg_name.upper()}={regs[reg_name]:04X}h "
            
            self.output_manager.write_line(reg_line)
    
    def write_memory_regions(self) -> None:
        """Write memory region information."""
        if not self.enabled:
            return
            
        self.output_manager.write_section_header("Memory Regions")
        
        from ..hardware.memory.memory_layout import MEMORY_REGIONS
        
        for name, (start, end, description) in MEMORY_REGIONS.items():
            size = end - start
            region_line = self.formatter.format_memory_region(start, name, start, size)
            self.output_manager.write_line(region_line)
            self.output_manager.write_line(f"    Description: {description}")
            self.output_manager.write_separator("-", 60)
    
    def write_final_statistics(self) -> None:
        """Write final execution statistics."""
        if not self.enabled:
            return
            
        self.output_manager.write_statistics()
    
    def write_bootloader_info(self, disk_image_path: str, 
                             geometry: tuple, drive_number: int) -> None:
        """Write bootloader information."""
        if not self.enabled:
            return
            
        self.output_manager.write_header("Bootloader Information")
        
        cylinders, heads, sectors = geometry
        self.output_manager.write_line(f"  Disk Image: {disk_image_path}")
        self.output_manager.write_line(f"  Drive Number: 0x{drive_number:02X}h")
        self.output_manager.write_line(f"  Geometry: {cylinders} cylinders, {heads} heads, {sectors} sectors/track")
        self.output_manager.write_line(f"  Total Sectors: {cylinders * heads * sectors}")
        
        if drive_number < 0x80:
            self.output_manager.write_line(f"  Type: Floppy Disk")
        else:
            self.output_manager.write_line(f"  Type: Hard Disk")
    
    def write_screen_output(self, screen_output: str) -> None:
        """Write screen output (if any)."""
        if not self.enabled or not screen_output.strip():
            return
            
        self.output_manager.write_section_header("Screen Output")
        self.output_manager.write_line(f"\n{screen_output}")
    
    def write_error(self, error_msg: str) -> None:
        """Write an error message."""
        self.output_manager.write_line(f"[!] Error: {error_msg}", console=True)
    
    def write_warning(self, warning_msg: str) -> None:
        """Write a warning message."""
        self.output_manager.write_line(f"[!] Warning: {warning_msg}", console=True)
    
    def write_debug(self, debug_msg: str) -> None:
        """Write a debug message."""
        if self.debug_enabled:
            self.output_manager.write_line(f"[DEBUG] {debug_msg}", console=False)
    
    def enable_debug_output(self) -> None:
        """Enable debug output."""
        self.debug_enabled = True
    
    def disable_debug_output(self) -> None:
        """Disable debug output."""
        self.debug_enabled = False
    
    def enable_tracing(self) -> None:
        """Enable tracing."""
        self.enabled = True
        self.hooks.enable_tracing()
    
    def disable_tracing(self) -> None:
        """Disable tracing."""
        self.enabled = False
        self.hooks.disable_tracing()
    
    def get_instruction_count(self) -> int:
        """Get the number of instructions traced."""
        return self.hooks.get_instruction_count()
    
    def close(self) -> None:
        """Close tracer and clean up."""
        self.stop_tracing()
        self.output_manager.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()