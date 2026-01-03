"""
BIOS interrupt handlers for the x86 Real Mode Bootloader Emulator
"""

from typing import Any, Optional
from unicorn import *
from unicorn.x86_const import *

from ..memory.bda_structures import BIOSDataArea
from ..ivt import IVT_NAMES


class BIOSInterruptHandler:
    """Base class for BIOS interrupt handlers."""
    
    def __init__(self, mu, bda: BIOSDataArea, verbose: bool = False):
        """Initialize BIOS interrupt handler."""
        self.mu = mu
        self.bda = bda
        self.verbose = verbose
        
        # Individual simulation components will be set later
        self.disk_simulator = None
        self.video_simulator = None
        self.keyboard_simulator = None
    
    def set_simulation_components(self, disk_simulator, video_simulator, keyboard_simulator):
        """Set the individual simulation components."""
        self.disk_simulator = disk_simulator
        self.video_simulator = video_simulator
        self.keyboard_simulator = keyboard_simulator
        
    def handle_interrupt(self, intno: int) -> None:
        """Handle a BIOS interrupt by routing to appropriate handler."""
        handler_name = self._get_handler_name(intno)
        if self.verbose:
            print(f"[*] Handling BIOS interrupt 0x{intno:02X} -> {handler_name}")
        
        if intno == 0x10:
            self.handle_int10()
        elif intno == 0x11:
            self.handle_int11()
        elif intno == 0x12:
            self.handle_int12()
        elif intno == 0x13:
            self.handle_int13()
        elif intno == 0x14:
            self.handle_int14()
        elif intno == 0x15:
            self.handle_int15()
        elif intno == 0x16:
            self.handle_int16()
        elif intno == 0x17:
            self.handle_int17()
        elif intno == 0x1A:
            self.handle_int1a()
        else:
            self.handle_unknown(intno)
    
    def _get_handler_name(self, intno: int) -> str:
        """Get the descriptive name for an interrupt."""
        return IVT_NAMES.get(intno, f"INT {intno:02X}h (Unknown)")
    
    def _dump_registers(self, intno: int, label: str) -> None:
        """Dump register state for debugging."""
        try:
            ax = self.mu.reg_read(UC_X86_REG_AX)
            bx = self.mu.reg_read(UC_X86_REG_BX)
            cx = self.mu.reg_read(UC_X86_REG_CX)
            dx = self.mu.reg_read(UC_X86_REG_DX)
            si = self.mu.reg_read(UC_X86_REG_SI)
            di = self.mu.reg_read(UC_X86_REG_DI)
            bp = self.mu.reg_read(UC_X86_REG_BP)
            sp = self.mu.reg_read(UC_X86_REG_SP)
            cs = self.mu.reg_read(UC_X86_REG_CS)
            ds = self.mu.reg_read(UC_X86_REG_DS)
            es = self.mu.reg_read(UC_X86_REG_ES)
            ss = self.mu.reg_read(UC_X86_REG_SS)
            flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
            cf = (flags >> 0) & 1
            zf = (flags >> 6) & 1
            print(f"[DEBUG] INT 0x{intno:02X} {label}: ax={ax:04x} bx={bx:04x} cx={cx:04x} dx={dx:04x} si={si:04x} di={di:04x} bp={bp:04x} sp={sp:04x} cs={cs:04x} ds={ds:04x} ss={ss:04x} es={es:04x} flags={flags:04x} cf={cf} zf={zf}")
        except UcError:
            pass
    
    def handle_int10(self) -> None:
        """Handle INT 0x10 - Video Services."""
        ah = (self.mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        
        if self.verbose:
            print(f"[INT 0x10] Video Services function AH=0x{ah:02X}")
        
        # Use video simulator if available
        if self.video_simulator:
            if ah == 0x00:
                # Set video mode
                al = self.mu.reg_read(UC_X86_REG_AX) & 0xFF
                self.video_simulator.set_video_mode(al)
                flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
                self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
            elif ah == 0x01:
                # Set cursor shape
                ch = self.mu.reg_read(UC_X86_REG_CX) & 0xFF
                cl = (self.mu.reg_read(UC_X86_REG_CX) >> 8) & 0xFF
                self.video_simulator.set_cursor_shape(cl, ch)
                flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
                self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
            elif ah == 0x02:
                # Set cursor position
                bh = self.mu.reg_read(UC_X86_REG_BX) & 0xFF
                dh = self.mu.reg_read(UC_X86_REG_DX) & 0xFF
                dl = self.mu.reg_read(UC_X86_REG_DX) >> 8 & 0xFF
                self.video_simulator.set_cursor_position(bh, dh, dl)
                flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
                self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
            elif ah == 0x03:
                # Get cursor position
                bh = self.mu.reg_read(UC_X86_REG_BX) & 0xFF
                row, col, start, end = self.video_simulator.get_cursor_position(bh)
                self.mu.reg_write(UC_X86_REG_CX, (start << 8) | end)
                self.mu.reg_write(UC_X86_REG_DX, (row << 8) | col)
                flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
                self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
            elif ah == 0x0E:
                # Write teletype character
                al = self.mu.reg_read(UC_X86_REG_AX) & 0xFF
                bh = self.mu.reg_read(UC_X86_REG_BX) & 0xFF
                bl = (self.mu.reg_read(UC_X86_REG_BX) >> 8) & 0xFF
                self.video_simulator.write_tty_character(al, bl, bh)
                flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
                self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
            else:
                # Unhandled function - fall back to basic implementation
                if self.verbose:
                    print(f"[INT 0x10] Unhandled function AH=0x{ah:02X}")
                self._video_set_mode()  # Fallback to basic video mode
        else:
            # Fallback to basic implementation
            self._video_set_mode()
    
    def handle_int11(self) -> None:
        """Handle INT 0x11 - Get Equipment List."""
        if self.verbose:
            print(f"[INT 0x11] Get Equipment List")
        
        # Return equipment word from BDA (0x0410)
        if self.bda:
            equipment = self.bda.equipment_list
            self.mu.reg_write(UC_X86_REG_AX, equipment)
        
        # Clear carry flag
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
    
    def handle_int12(self) -> None:
        """Handle INT 0x12 - Get Memory Size."""
        if self.verbose:
            print(f"[INT 0x12] Get Memory Size")
        
        # Return memory size in KB from BDA (0x0413)
        if self.bda:
            memory_size = self.bda.memory_size_kb
            self.mu.reg_write(UC_X86_REG_AX, memory_size)
        
        # Clear carry flag
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
    
    def handle_int13(self) -> None:
        """Handle INT 0x13 - Disk Services."""
        ah = (self.mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dl = self.mu.reg_read(UC_X86_REG_DX) & 0xFF
        
        if self.verbose:
            drive_type = "Floppy" if dl < 0x80 else "Hard Disk"
            print(f"[INT 0x13] Disk Services function AH=0x{ah:02X}, DL=0x{dl:02X} ({drive_type})")
        
        # Use disk simulator if available
        if self.disk_simulator:
            if ah == 0x00:
                # Reset disk system
                result = self.disk_simulator.reset_disk_system()
                self._set_disk_result(result)
            elif ah == 0x02:
                # Read disk sectors
                result = self.disk_simulator.read_sectors()
                self._set_disk_result(result)
            elif ah == 0x03:
                # Write disk sectors
                result = self.disk_simulator.write_sectors()
                self._set_disk_result(result)
            elif ah == 0x08:
                # Get disk drive parameters
                result = self.disk_simulator.get_disk_parameters()
                self._set_disk_result(result)
            else:
                # Unhandled function
                if self.verbose:
                    print(f"[INT 0x13] Unhandled function AH=0x{ah:02X}")
                self._set_disk_result(0x8001)  # Error
        else:
            # Fallback to basic implementation
            if ah == 0x00:
                self._disk_reset()
            else:
                self._set_disk_result(0x8001)  # Error
    
    def _set_disk_result(self, result: int) -> None:
        """Set disk operation result in registers."""
        if result == 0x0000:
            # Success - clear carry flag
            flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
            self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
            self.mu.reg_write(UC_X86_REG_AX, 0x0000)
        else:
            # Error - set carry flag
            flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
            self.mu.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)
            self.mu.reg_write(UC_X86_REG_AX, result)
    
    def handle_int14(self) -> None:
        """Handle INT 0x14 - Serial Communications Services."""
        ah = (self.mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dx = self.mu.reg_read(UC_X86_REG_DX) & 0xFF
        
        if self.verbose:
            print(f"[INT 0x14] Serial port {dx}, function AH=0x{ah:02X}")
        
        # For now, just acknowledge
        self.mu.reg_write(UC_X86_REG_AX, 0x0000)  # Success
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
    
    def handle_int15(self) -> None:
        """Handle INT 0x15 - System Services."""
        ah = (self.mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        
        if self.verbose:
            print(f"[INT 0x15] System Services function AH=0x{ah:02X}")
        
        if ah == 0x86:
            # Wait for clock event (CX:DX microseconds)
            self._system_wait()
        elif ah == 0x88:
            # Get extended memory size
            self._system_get_extended_memory()
        else:
            if self.verbose:
                print(f"[INT 0x15] Unhandled function AH=0x{ah:02X}")
            self.mu.emu_stop()
    
    def handle_int16(self) -> None:
        """Handle INT 0x16 - Keyboard Services."""
        ah = (self.mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        
        if self.verbose:
            print(f"[INT 0x16] Keyboard Services function AH=0x{ah:02X}")
        
        if ah == 0x00:
            # Get keystroke
            self._keyboard_get_keystroke()
        elif ah == 0x01:
            # Check for keystroke availability
            self._keyboard_check_keystroke()
        else:
            if self.verbose:
                print(f"[INT 0x16] Unhandled function AH=0x{ah:02X}")
            self.mu.emu_stop()
    
    def handle_int17(self) -> None:
        """Handle INT 0x17 - Printer Services."""
        ah = (self.mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dx = self.mu.reg_read(UC_X86_REG_DX) & 0xFF
        
        if self.verbose:
            print(f"[INT 0x17] Printer {dx}, function AH=0x{ah:02X}")
        
        # For now, just acknowledge success
        self.mu.reg_write(UC_X86_REG_AX, 0x0100)  # Printer ready, no error
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
    
    def handle_int1a(self) -> None:
        """Handle INT 0x1A - Timer/Clock Services."""
        ah = (self.mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        
        if self.verbose:
            print(f"[INT 0x1A] Timer/Clock Services function AH=0x{ah:02X}")
        
        if ah == 0x00:
            # Get system time
            self._timer_get_system_time()
        elif ah == 0x01:
            # Set system time
            self._timer_set_system_time()
        elif ah == 0x04:
            # Get date
            self._timer_get_date()
        elif ah == 0x05:
            # Set date
            self._timer_set_date()
        else:
            if self.verbose:
                print(f"[INT 0x1A] Unhandled function AH=0x{ah:02X}")
            self.mu.emu_stop()
    
    def handle_unknown(self, intno: int) -> None:
        """Handle unknown interrupt."""
        ip = self.mu.reg_read(UC_X86_REG_IP)
        if self.verbose:
            print(f"[INT] Unhandled BIOS interrupt 0x{intno:02X} at 0x{ip:04X}")
        self.mu.emu_stop()
    
    # Helper methods for interrupt handlers
    def _video_set_mode(self) -> None:
        """Set video mode."""
        al = self.mu.reg_read(UC_X86_REG_AX) & 0xFF
        if self.verbose:
            print(f"[INT 0x10] Set video mode: 0x{al:02X}")
        
        # Update BDA video mode field (0x0449)
        if self.bda:
            self.bda.video_mode = al
            # Also update some typical values for text mode
            if al == 0x03:  # 80x25 text mode (most common)
                self.bda.video_columns = 80
                self.bda.video_rows = 24  # rows minus 1
                self.bda.video_page_size = 4000  # 80*25*2 bytes
            elif al == 0x07:  # Monochrome text mode
                self.bda.video_columns = 80
                self.bda.video_rows = 24
                self.bda.video_page_size = 4000
    
    def _disk_reset(self) -> None:
        """Reset disk system."""
        if self.verbose:
            print(f"[INT 0x13] Disk reset")
        
        # Always successful
        self.mu.reg_write(UC_X86_REG_AX, 0x0000)  # Success
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
    
    def _disk_read_sectors(self) -> None:
        """Read disk sectors."""
        if self.verbose:
            print(f"[INT 0x13] Read disk sectors")
        
        # Always fail for now (will implement properly in disk operations)
        self.mu.reg_write(UC_X86_REG_AX, 0x8001)  # Error
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)  # Set carry flag
    
    def _timer_get_system_time(self) -> None:
        """Get system time (ticks since midnight)."""
        if self.bda:
            # Return timer counter from BDA (0x046C)
            timer_count = self.bda.timer_counter
            self.mu.reg_write(UC_X86_REG_CX, (timer_count >> 16) & 0xFFFF)
            self.mu.reg_write(UC_X86_REG_DX, timer_count & 0xFFFF)
        
        # Clear carry flag
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
    
    def _keyboard_get_keystroke(self) -> None:
        """Get keystroke from keyboard buffer."""
        if self.bda:
            # Check if keyboard buffer is empty
            head = self.bda.kbd_buffer_head
            tail = self.bda.kbd_buffer_tail
            
            if head == tail:
                # Buffer empty, wait for key (simulate Ctrl+C to break)
                self.mu.reg_write(UC_X86_REG_AX, 0x0024)  # Ctrl+C
            else:
                # Read from buffer head
                # For now, return Ctrl+C
                self.mu.reg_write(UC_X86_REG_AX, 0x0024)
        
        # Clear carry flag
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
    
    def _keyboard_check_keystroke(self) -> None:
        """Check if keystroke is available."""
        if self.bda:
            # Check if keyboard buffer is empty
            head = self.bda.kbd_buffer_head
            tail = self.bda.kbd_buffer_tail
            
            if head == tail:
                # Buffer empty
                self.mu.reg_write(UC_X86_REG_AX, 0x0100)  # Zero flag set
            else:
                # Key available
                self.mu.reg_write(UC_X86_REG_AX, 0x0000)  # Zero flag clear
        
        # Clear carry flag
        flags = self.mu.reg_read(UC_X86_REG_EFLAGS)
        self.mu.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
    
    # Placeholder methods for unimplemented functions
    def _video_set_cursor_shape(self) -> None:
        """Set cursor shape."""
        pass
    
    def _video_set_cursor_position(self) -> None:
        """Set cursor position."""
        pass
    
    def _video_get_cursor_position(self) -> None:
        """Get cursor position."""
        pass
    
    def _video_set_active_page(self) -> None:
        """Set active display page."""
        pass
    
    def _video_scroll_up(self) -> None:
        """Scroll up window."""
        pass
    
    def _video_scroll_down(self) -> None:
        """Scroll down window."""
        pass
    
    def _video_read_char_attr(self) -> None:
        """Read character and attribute."""
        pass
    
    def _video_write_char_attr(self) -> None:
        """Write character and attribute."""
        pass
    
    def _video_write_char(self) -> None:
        """Write character."""
        pass
    
    def _video_write_tty(self) -> None:
        """Write teletype character."""
        pass
    
    def _disk_write_sectors(self) -> None:
        """Write disk sectors."""
        pass
    
    def _disk_get_parameters(self) -> None:
        """Get disk parameters."""
        pass
    
    def _system_wait(self) -> None:
        """Wait for clock event."""
        pass
    
    def _system_get_extended_memory(self) -> None:
        """Get extended memory size."""
        pass
    
    def _timer_set_system_time(self) -> None:
        """Set system time."""
        pass
    
    def _timer_get_date(self) -> None:
        """Get date."""
        pass
    
    def _timer_set_date(self) -> None:
        """Set date."""
        pass