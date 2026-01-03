"""
Trace formatting utilities for the x86 Real Mode Bootloader Emulator
"""

import struct
from typing import Dict, List, Optional, Any
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86_const import *

from ..hardware.ivt import IVT_NAMES


class TraceFormatter:
    """Formats instruction traces with registers and memory access."""
    
    def __init__(self, verbose: bool = True):
        """Initialize trace formatter."""
        self.verbose = verbose
        self.cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self.cs.detail = True
        
    def format_instruction(self, address: int, bytes_data: bytes, 
                          regs: Dict[str, int]) -> str:
        """Format a single instruction with its registers."""
        # Disassemble instruction
        for insn in self.cs.disasm(bytes_data, address):
            return self._format_insn_with_regs(insn, regs)
        return "???"
    
    def _format_insn_with_regs(self, insn: CsInsn, regs: Dict[str, int]) -> str:
        """Format instruction with register state."""
        # Format the basic instruction
        insn_str = f"{insn.address:04X}:{insn.mnemonic} {insn.op_str}"
        
        # Add register state if verbose
        if self.verbose:
            reg_str = self._format_registers(regs)
            return f"{insn_str} | {reg_str}"
        else:
            return insn_str
    
    def _format_registers(self, regs: Dict[str, int]) -> str:
        """Format register state for tracing."""
        # Format in order: AX, BX, CX, DX, SI, DI, BP, SP
        reg_names = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp']
        seg_names = ['cs', 'ds', 'es', 'ss']
        
        reg_parts = []
        seg_parts = []
        
        # General registers
        for reg in reg_names:
            if reg in regs:
                reg_parts.append(f"{reg.upper()}={regs[reg]:04X}")
        
        # Segment registers  
        for reg in seg_names:
            if reg in regs:
                seg_parts.append(f"{reg.upper()}={regs[reg]:04X}")
        
        result = ""
        if reg_parts:
            result += " ".join(reg_parts)
        if seg_parts:
            if result:
                result += " "
            result += " ".join(seg_parts)
            
        return result
    
    def format_memory_access(self, access_type: str, address: int, 
                            size: int, value: Optional[int] = None) -> str:
        """Format a memory access."""
        if value is not None:
            return f"[{access_type}] {address:04X}h [{size} bytes] = {value:04X}h"
        else:
            return f"[{access_type}] {address:04X}h [{size} bytes]"
    
    def format_interrupt(self, interrupt_num: int, regs: Dict[str, int]) -> str:
        """Format an interrupt call."""
        name = IVT_NAMES.get(interrupt_num, f"INT {interrupt_num:02X}h")
        return f"[*] Handling BIOS interrupt {interrupt_num:02X}h -> {name}"
    
    def format_memory_region(self, address: int, region_name: str, 
                           start: int, size: int) -> str:
        """Format memory region information."""
        return f"    Region: {region_name} (0x{start:04X}-0x{start+size:04X}, {size} bytes)"
    
    def format_memory_content(self, address: int, data: bytes, 
                             start_offset: int = 0) -> str:
        """Format memory content in hex dump format."""
        lines = []
        data_len = len(data)
        
        for i in range(0, data_len, 16):
            # Hex bytes
            hex_bytes = []
            for j in range(16):
                if i + j < data_len:
                    hex_bytes.append(f"{data[i+j]:02X}")
                else:
                    hex_bytes.append("  ")
            
            # ASCII representation
            ascii_chars = []
            for j in range(16):
                if i + j < data_len:
                    b = data[i+j]
                    if 32 <= b <= 126:
                        ascii_chars.append(chr(b))
                    else:
                        ascii_chars.append(".")
                else:
                    ascii_chars.append(" ")
            
            # Format the line
            hex_part = " ".join(hex_bytes[:8]) + "  " + " ".join(hex_bytes[8:])
            ascii_part = "".join(ascii_chars)
            line_addr = address + i + start_offset
            
            lines.append(f"    0x{line_addr:06X}: {hex_part}  |{ascii_part}|")
        
        return "\n".join(lines)