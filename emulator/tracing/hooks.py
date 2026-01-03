"""
Tracing hooks for Unicorn Engine instruction tracing
"""

from typing import Dict, Any, Optional
from unicorn import *
from unicorn.x86_const import *

from .formatters import TraceFormatter
from .output import TraceOutputManager


class TracingHooks:
    """Manages tracing hooks for Unicorn Engine."""
    
    def __init__(self, mu, output_manager: TraceOutputManager, 
                 formatter: TraceFormatter, max_instructions: int = 1000000):
        """Initialize tracing hooks."""
        self.mu = mu
        self.output_manager = output_manager
        self.formatter = formatter
        self.max_instructions = max_instructions
        self.instruction_count = 0
        
        # Hook for instruction tracing
        self.instruction_hook = None
        
        # Hooks for memory access
        self.mem_read_hook = None
        self.mem_write_hook = None
        
        # Hook for interrupts
        self.interrupt_hook = None
        
        # Tracing state
        self.tracing_enabled = True
        self.first_instructions = 50  # Show first 50 instructions in detail
        
    def install_hooks(self) -> None:
        """Install all tracing hooks."""
        # Instruction tracing hook
        self.instruction_hook = self.mu.hook_add(
            UC_HOOK_CODE, 
            self._trace_instruction,
            begin=1, 
            end=0xFFFFFF
        )
        
        # Memory access hooks
        self.mem_read_hook = self.mu.hook_add(
            UC_HOOK_MEM_READ,
            self._trace_mem_read
        )
        
        self.mem_write_hook = self.mu.hook_add(
            UC_HOOK_MEM_WRITE,
            self._trace_mem_write
        )
        
        # Interrupt hook
        self.interrupt_hook = self.mu.hook_add(
            UC_HOOK_INTR,
            self._trace_interrupt
        )
    
    def remove_hooks(self) -> None:
        """Remove all tracing hooks."""
        if self.instruction_hook:
            self.mu.hook_del(self.instruction_hook)
            self.instruction_hook = None
            
        if self.mem_read_hook:
            self.mu.hook_del(self.mem_read_hook)
            self.mem_read_hook = None
            
        if self.mem_write_hook:
            self.mu.hook_del(self.mem_write_hook)
            self.mem_write_hook = None
            
        if self.interrupt_hook:
            self.mu.hook_del(self.interrupt_hook)
            self.interrupt_hook = None
    
    def _trace_instruction(self, uc: Uc, address: int, size: int, user_data: Any) -> None:
        """Trace instruction execution."""
        if not self.tracing_enabled:
            return
            
        # Get instruction bytes
        try:
            bytes_data = uc.mem_read(address, size)
        except UcError:
            return
            
        # Get current registers
        regs = self._get_registers()
        
        # Format instruction
        insn_line = self.formatter.format_instruction(address, bytes_data, regs)
        
        # Determine console output (first 50 instructions always shown)
        console_output = (self.instruction_count < self.first_instructions)
        
        # Write instruction trace
        self.output_manager.write_instruction(insn_line, console_output)
        
        # Check instruction limit
        self.instruction_count += 1
        if self.instruction_count >= self.max_instructions:
            self.output_manager.write_line("[!] Maximum instruction limit reached!")
            self.output_manager.write_section_header("Infinite loop detection summary")
            uc.emu_stop()
    
    def _trace_mem_read(self, uc: Uc, access: int, address: int, size: int, value: int, user_data: Any) -> None:
        """Trace memory read access."""
        if not self.tracing_enabled:
            return
            
        # Get memory value
        try:
            data = uc.mem_read(address, size)
            value = int.from_bytes(data, 'little')
        except UcError:
            return
            
        # Format memory access
        access_line = self.formatter.format_memory_access("READ", address, size, value)
        
        # Write memory trace (never show on console unless first instructions)
        console_output = (self.instruction_count < self.first_instructions)
        self.output_manager.write_memory_access(access_line, console_output)
    
    def _trace_mem_write(self, uc: Uc, access: int, address: int, size: int, value: int, user_data: Any) -> None:
        """Trace memory write access."""
        if not self.tracing_enabled:
            return
            
        # Format memory access
        access_line = self.formatter.format_memory_access("WRITE", address, size, value)
        
        # Write memory trace (never show on console unless first instructions)
        console_output = (self.instruction_count < self.first_instructions)
        self.output_manager.write_memory_access(access_line, console_output)
    
    def _trace_interrupt(self, uc: Uc, intno: int, user_data: Any) -> None:
        """Trace interrupt execution."""
        if not self.tracing_enabled:
            return
            
        # Get current registers
        regs = self._get_registers()
        
        # Format interrupt
        interrupt_line = self.formatter.format_interrupt(intno, regs)
        
        # Write interrupt trace (always show on console)
        self.output_manager.write_interrupt(interrupt_line, True)
    
    def _get_registers(self) -> Dict[str, int]:
        """Get current register state."""
        regs = {}
        
        try:
            # General registers
            regs['ax'] = self.mu.reg_read(UC_X86_REG_AX)
            regs['bx'] = self.mu.reg_read(UC_X86_REG_BX)
            regs['cx'] = self.mu.reg_read(UC_X86_REG_CX)
            regs['dx'] = self.mu.reg_read(UC_X86_REG_DX)
            
            regs['si'] = self.mu.reg_read(UC_X86_REG_SI)
            regs['di'] = self.mu.reg_read(UC_X86_REG_DI)
            regs['bp'] = self.mu.reg_read(UC_X86_REG_BP)
            regs['sp'] = self.mu.reg_read(UC_X86_REG_SP)
            
            # Segment registers
            regs['cs'] = self.mu.reg_read(UC_X86_REG_CS)
            regs['ds'] = self.mu.reg_read(UC_X86_REG_DS)
            regs['es'] = self.mu.reg_read(UC_X86_REG_ES)
            regs['ss'] = self.mu.reg_read(UC_X86_REG_SS)
            
            # Flags
            flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
            regs['flags'] = flags & 0xFFFF  # 16-bit flags
            
        except UcError:
            pass
            
        return regs
    
    def enable_tracing(self) -> None:
        """Enable tracing."""
        self.tracing_enabled = True
    
    def disable_tracing(self) -> None:
        """Disable tracing."""
        self.tracing_enabled = False
    
    def get_instruction_count(self) -> int:
        """Get the number of instructions traced."""
        return self.instruction_count