"""
Video service simulation for the x86 Real Mode Bootloader Emulator
"""

import struct
from unicorn import *
from unicorn.x86_const import *

from ..memory.bda_structures import BIOSDataArea


class VideoServiceSimulator:
    """Simulates video services for BIOS INT 10h."""
    
    def __init__(self, mu, bda: BIOSDataArea, verbose: bool = False):
        """Initialize video service simulator."""
        self.mu = mu
        self.bda = bda
        self.verbose = verbose
        
        # Video memory segment (B800:0000 for color text, B000:0000 for monochrome)
        self.video_segment = 0xB800  # Color text mode
        
        if self.verbose:
            print(f"[*] Video Service Simulator initialized")
            print(f"    Video segment: 0x{self.video_segment:04X}")
    
    def set_video_mode(self, mode: int) -> None:
        """Set video mode (INT 10h, AH=00h)."""
        if self.verbose:
            print(f"[INT 10h] Set video mode: 0x{mode:02X}")
        
        # Update BDA video mode field
        if self.bda:
            self.bda.video_mode = mode
            
            # Set typical values for common modes
            if mode == 0x03:  # 80x25 color text mode
                self.bda.video_columns = 80
                self.bda.video_rows = 24  # 24 rows (0-based)
                self.bda.video_page_size = 4000  # 80*25*2 bytes
                self.bda.active_page = 0
                
                # Set cursor position for page 0 to (0,0)
                self.bda.cursor_pos[0] = 0x0000
                self.bda.cursor_start_line = 6
                self.bda.cursor_end_line = 7
                
                # Clear screen
                self._clear_screen()
                
            elif mode == 0x07:  # 80x25 monochrome text mode
                self.bda.video_columns = 80
                self.bda.video_rows = 24
                self.bda.video_page_size = 4000
                self.bda.active_page = 0
                self.bda.cursor_pos[0] = 0x0000
                
                # Monochrome mode uses different segment
                self.video_segment = 0xB000
                self._clear_screen()
                
        # Set video segment
        if mode in [0x00, 0x01, 0x02, 0x03, 0x07]:
            self.video_segment = 0xB800 if mode != 0x07 else 0xB000
    
    def set_cursor_shape(self, start_line: int, end_line: int) -> None:
        """Set cursor shape (INT 10h, AH=01h)."""
        if self.verbose:
            print(f"[INT 10h] Set cursor shape: start={start_line}, end={end_line}")
        
        if self.bda:
            self.bda.cursor_start_line = start_line
            self.bda.cursor_end_line = end_line
    
    def set_cursor_position(self, page: int, row: int, col: int) -> None:
        """Set cursor position (INT 10h, AH=02h)."""
        if self.verbose:
            print(f"[INT 10h] Set cursor position: page={page}, row={row}, col={col}")
        
        if self.bda:
            # BDA cursor positions are stored as uint16: (row << 8) | col
            cursor_pos = (row << 8) | col
            self.bda.cursor_pos[page] = cursor_pos
    
    def get_cursor_position(self, page: int) -> tuple:
        """Get cursor position (INT 10h, AH=03h)."""
        if self.bda:
            cursor_pos = self.bda.cursor_pos[page]
            row = (cursor_pos >> 8) & 0xFF
            col = cursor_pos & 0xFF
            start_line = self.bda.cursor_start_line
            end_line = self.bda.cursor_end_line
            
            if self.verbose:
                print(f"[INT 10h] Get cursor position: page={page}")
                print(f"    Position: ({row}, {col})")
                print(f"    Shape: {start_line}-{end_line}")
            
            return row, col, start_line, end_line
        
        return 0, 0, 0, 0
    
    def set_active_page(self, page: int) -> None:
        """Set active display page (INT 10h, AH=05h)."""
        if self.verbose:
            print(f"[INT 10h] Set active page: {page}")
        
        if self.bda:
            self.bda.active_page = page
    
    def write_character(self, char: int, attr: int, page: int, 
                       row: int, col: int, count: int) -> None:
        """Write character with attribute (INT 10h, AH=09h)."""
        if self.verbose:
            print(f"[INT 10h] Write character: char='{chr(char)}' (0x{char:02X}), "
                  f"attr=0x{attr:02X}, page={page}, pos=({row},{col}), count={count}")
        
        # Calculate video memory address
        page_offset = page * self.bda.video_page_size if self.bda else 0
        row_offset = row * (self.bda.video_columns if self.bda else 80) * 2
        col_offset = col * 2
        addr = self.video_segment * 16 + page_offset + row_offset + col_offset
        
        # Write characters
        for i in range(count):
            # Write character and attribute
            char_data = struct.pack('<BB', char, attr)
            try:
                self.mu.mem_write(addr + (i * 2), char_data)
            except:
                # Video memory not mapped or error
                if self.verbose:
                    print(f"[!] Error writing to video memory at 0x{addr:04X}")
                return
    
    def write_tty_character(self, char: int, attr: int, page: int) -> None:
        """Write teletype character (INT 10h, AH=0Eh)."""
        if self.verbose:
            print(f"[INT 10h] Write TTY character: '{chr(char)}' (0x{char:02X}), page={page}")
        
        if self.bda:
            # Get current cursor position
            cursor_pos = self.bda.cursor_pos[page]
            row = (cursor_pos >> 8) & 0xFF
            col = cursor_pos & 0xFF
            
            # Handle special characters
            if char == 0x0D:  # Carriage return
                col = 0
            elif char == 0x0A:  # Line feed
                row += 1
            elif char == 0x08:  # Backspace
                if col > 0:
                    col -= 1
            elif char == 0x07:  # Bell
                pass  # No bell sound in emulation
            elif char >= 0x20:  # Printable character
                # Write character
                self.write_character(char, attr, page, row, col, 1)
                col += 1
            
            # Check if we need to scroll
            max_cols = self.bda.video_columns if self.bda else 80
            max_rows = self.bda.video_rows + 1 if self.bda else 25
            
            if col >= max_cols:
                col = 0
                row += 1
            
            if row >= max_rows:
                # Scroll up
                row = max_rows - 1
                self._scroll_up(page)
            
            # Update cursor position
            cursor_pos = (row << 8) | col
            self.bda.cursor_pos[page] = cursor_pos
    
    def _clear_screen(self) -> None:
        """Clear the screen (fill with spaces and normal attribute)."""
        if self.verbose:
            print(f"[*] Clearing screen")
        
        # Clear video memory (first 4 pages for simplicity)
        for page in range(4):
            page_offset = page * 4000  # 80*25*2 = 4000 bytes per page
            for addr in range(page_offset, page_offset + 4000, 2):
                try:
                    # Write space character with normal attribute
                    self.mu.mem_write(self.video_segment * 16 + addr, b' \x07')
                except:
                    # Video memory not mapped
                    if self.verbose:
                        print(f"[!] Error clearing video memory at 0x{self.video_segment:04X}:{addr:04X}")
                    break
    
    def _scroll_up(self, page: int) -> None:
        """Scroll up one line."""
        if self.verbose:
            print(f"[INT 10h] Scroll up page {page}")
        
        # This is a simplified scroll - just move everything up one line
        if self.bda:
            start_addr = self.video_segment * 16 + page * self.bda.video_page_size
            cols = self.bda.video_columns
            rows = self.bda.video_rows + 1  # +1 because rows are 0-based in BDA
            
            # Move each line up by one
            for row in range(1, rows):
                src_addr = start_addr + row * cols * 2
                dst_addr = start_addr + (row - 1) * cols * 2
                
                try:
                    line_data = self.mu.mem_read(src_addr, cols * 2)
                    self.mu.mem_write(dst_addr, line_data)
                except:
                    # Video memory not mapped
                    return
            
            # Clear the last line
            last_line_addr = start_addr + (rows - 1) * cols * 2
            for i in range(cols * 2):
                try:
                    self.mu.mem_write(last_line_addr + i, b' ')
                except:
                    return


class KeyboardServiceSimulator:
    """Simulates keyboard services for BIOS INT 16h."""
    
    def __init__(self, mu, bda: BIOSDataArea, verbose: bool = False):
        """Initialize keyboard service simulator."""
        self.mu = mu
        self.bda = bda
        self.verbose = verbose
        
        # Simulate keyboard buffer
        self.keyboard_buffer = []
        
        if self.verbose:
            print(f"[*] Keyboard Service Simulator initialized")
    
    def get_keystroke(self) -> tuple:
        """Get keystroke from keyboard buffer (INT 16h, AH=00h)."""
        if self.verbose:
            print(f"[INT 16h] Get keystroke")
        
        if self.keyboard_buffer:
            # Return key from buffer
            key = self.keyboard_buffer.pop(0)
            return key
        else:
            # No key in buffer - simulate Ctrl+C to break
            return (0x24, 0x0000)  # Ctrl+C
    
    def check_keystroke(self) -> bool:
        """Check if keystroke is available (INT 16h, AH=01h)."""
        if self.verbose:
            print(f"[INT 16h] Check keystroke")
        
        return len(self.keyboard_buffer) > 0
    
    def add_key(self, scan_code: int, ascii_code: int) -> None:
        """Add key to keyboard buffer."""
        if self.verbose:
            print(f"[*] Adding key: scan=0x{scan_code:02X}, ascii=0x{ascii_code:02X}")
        
        if len(self.keyboard_buffer) < 16:  # Standard keyboard buffer size
            self.keyboard_buffer.append((scan_code, ascii_code))