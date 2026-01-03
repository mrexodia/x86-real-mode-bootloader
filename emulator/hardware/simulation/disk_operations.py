"""
Disk operation simulation for the x86 Real Mode Bootloader Emulator
"""

import struct
from typing import Optional, Tuple
from unicorn import *
from unicorn.x86_const import *

from ..memory.bda_structures import BIOSDataArea


class DiskOperationSimulator:
    """Simulates disk operations for BIOS INT 0x13h."""
    
    def __init__(self, mu, disk_image_path: str, bda: BIOSDataArea, 
                 cylinders: int, heads: int, sectors_per_track: int, 
                 verbose: bool = False):
        """Initialize disk operation simulator."""
        self.mu = mu
        self.disk_image_path = disk_image_path
        self.bda = bda
        self.cylinders = cylinders
        self.heads = heads
        self.sectors_per_track = sectors_per_track
        self.verbose = verbose
        
        # Load disk image
        with open(disk_image_path, 'rb') as f:
            self.disk_data = f.read()
        
        # CHS geometry
        self.total_sectors = cylinders * heads * sectors_per_track
        
        # Drive number (0x80 for first hard disk)
        self.drive_number = 0x80
        
        if self.verbose:
            print(f"[*] Disk Operation Simulator initialized:")
            print(f"    Image: {disk_image_path}")
            print(f"    Size: {len(self.disk_data)} bytes")
            print(f"    Geometry: {cylinders} cyls, {heads} heads, {sectors_per_track} secs")
            print(f"    Total sectors: {self.total_sectors}")
    
    def reset_disk_system(self) -> int:
        """Reset disk system (INT 0x13h, AH=00h)."""
        if self.verbose:
            print(f"[INT 0x13] Reset disk system")
        
        # Always successful
        return 0x0000  # Success, carry flag clear
    
    def read_sectors(self) -> int:
        """Read disk sectors (INT 0x13h, AH=02h)."""
        # Get parameters
        al = self.mu.reg_read(UC_X86_REG_AX) & 0xFF  # Number of sectors to read
        ch = self.mu.reg_read(UC_X86_REG_CX) & 0xFF  # Cylinder low bits
        cl = self.mu.reg_read(UC_X86_REG_CX) & 0xFF  # Sector number (low 6 bits)
        dh = self.mu.reg_read(UC_X86_REG_DX) & 0xFF  # Head number
        dl = self.mu.reg_read(UC_X86_REG_DX) & 0xFF  # Drive number
        es = self.mu.reg_read(UC_X86_REG_ES)        # Buffer segment
        bx = self.mu.reg_read(UC_X86_REG_BX)        # Buffer offset
        
        # Extract cylinder number (bits 7-6 of CL + CH)
        cylinder = ((cl >> 6) & 0x03) | (ch << 2)
        sector = cl & 0x3F  # Sector number (1-based)
        head = dh
        
        if self.verbose:
            print(f"[INT 0x13] Read sectors:")
            print(f"    Drive: 0x{dl:02X}")
            print(f"    CHS: {cylinder}:{head}:{sector}")
            print(f"    Count: {al}")
            print(f"    Buffer: 0x{es:04X}:0x{bx:04X}")
        
        # Validate parameters
        if dl != self.drive_number:
            if self.verbose:
                print(f"[!] Invalid drive number: 0x{dl:02X} (expected 0x{self.drive_number:02X})")
            return 0x8001  # Invalid drive
        
        if cylinder >= self.cylinders or head >= self.heads:
            if self.verbose:
                print(f"[!] Invalid CHS: {cylinder}:{head}:{sector}")
            return 0x8001  # Invalid CHS
        
        if sector == 0 or sector > self.sectors_per_track:
            if self.verbose:
                print(f"[!] Invalid sector number: {sector}")
            return 0x8001  # Invalid sector
        
        if al == 0:
            if self.verbose:
                print(f"[!] Invalid sector count: 0")
            return 0x8001  # Invalid count
        
        # Calculate LBA
        lba = self.chs_to_lba(cylinder, head, sector)
        
        # Read sectors
        try:
            sectors_to_read = al
            buffer_segment = es
            buffer_offset = bx
            
            for i in range(sectors_to_read):
                # Calculate sector LBA
                current_sector = lba + i
                
                # Check if sector exists
                if current_sector * 512 >= len(self.disk_data):
                    if self.verbose:
                        print(f"[!] Sector {current_sector} beyond disk size")
                    return 0x8001  # Sector not found
                
                # Read sector data
                start_addr = current_sector * 512
                sector_data = self.disk_data[start_addr:start_addr + 512]
                
                # Write to memory
                buffer_addr = (buffer_segment << 4) + buffer_offset
                self.mu.mem_write(buffer_addr, sector_data)
                
                if self.verbose and i < 5:  # Log first 5 sectors
                    print(f"    Read sector {current_sector} to 0x{buffer_addr:04X}")
                
                # Update buffer offset for next sector
                buffer_offset += 512
                
                # Check for segment wrap
                if buffer_offset >= 0x10000:
                    buffer_offset = 0
                    buffer_segment += 1
            
            # Success
            if self.verbose:
                print(f"    Successfully read {sectors_to_read} sectors")
            return 0x0000  # Success
            
        except Exception as e:
            if self.verbose:
                print(f"[!] Error reading sectors: {e}")
            return 0x8001  # Error
    
    def write_sectors(self) -> int:
        """Write disk sectors (INT 0x13h, AH=03h)."""
        # Get parameters (same as read)
        al = self.mu.reg_read(UC_X86_REG_AX) & 0xFF  # Number of sectors to write
        ch = self.mu.reg_read(UC_X86_REG_CX) & 0xFF  # Cylinder low bits
        cl = self.mu.reg_read(UC_X86_REG_CX) & 0xFF  # Sector number (low 6 bits)
        dh = self.mu.reg_read(UC_X86_REG_DX) & 0xFF  # Head number
        dl = self.mu.reg_read(UC_X86_REG_DX) & 0xFF  # Drive number
        es = self.mu.reg_read(UC_X86_REG_ES)        # Buffer segment
        bx = self.mu.reg_read(UC_X86_REG_BX)        # Buffer offset
        
        # Extract cylinder number
        cylinder = ((cl >> 6) & 0x03) | (ch << 2)
        sector = cl & 0x3F
        head = dh
        
        if self.verbose:
            print(f"[INT 0x13] Write sectors:")
            print(f"    Drive: 0x{dl:02X}")
            print(f"    CHS: {cylinder}:{head}:{sector}")
            print(f"    Count: {al}")
            print(f"    Buffer: 0x{es:04X}:0x{bx:04X}")
        
        # For safety, we'll not implement writing for now
        if self.verbose:
            print(f"[!] Write operations not implemented")
        return 0x8001  # Error
    
    def get_disk_parameters(self) -> int:
        """Get disk drive parameters (INT 0x13h, AH=08h)."""
        dl = self.mu.reg_read(UC_X86_REG_DX) & 0xFF  # Drive number
        
        if self.verbose:
            print(f"[INT 0x13] Get disk parameters for drive 0x{dl:02X}")
        
        if dl != self.drive_number:
            if self.verbose:
                print(f"[!] Invalid drive number: 0x{dl:02X}")
            return 0x8001  # Invalid drive
        
        # Set parameters
        # CX: cylinders-1 (bits 7-0)
        cylinders_minus_1 = self.cylinders - 1
        cx = cylinders_minus_1 & 0xFF
        
        # DH: heads-1
        heads_minus_1 = self.heads - 1
        
        # Set registers
        self.mu.reg_write(UC_X86_REG_CX, cx)
        self.mu.reg_write(UC_X86_REG_DX, heads_minus_1)
        
        # ES:BI = pointer to disk parameter table
        # For now, point to a dummy location
        self.mu.reg_write(UC_X86_REG_ES, 0x0000)
        self.mu.reg_write(UC_X86_REG_BX, 0x0000)
        
        # DL: drive number (already set)
        
        if self.verbose:
            print(f"    Cylinders-1: 0x{cylinders_minus_1:04X}")
            print(f"    Heads-1: 0x{heads_minus_1:02X}")
            print(f"    Sectors/track: {self.sectors_per_track}")
        
        return 0x0000  # Success
    
    def chs_to_lba(self, cylinder: int, head: int, sector: int) -> int:
        """Convert CHS to LBA (Logical Block Address)."""
        # LBA calculation: (cylinder * heads_per_cylinder + head) * sectors_per_track + (sector - 1)
        lba = (cylinder * self.heads + head) * self.sectors_per_track + (sector - 1)
        return lba
    
    def lba_to_chs(self, lba: int) -> Tuple[int, int, int]:
        """Convert LBA to CHS."""
        # CHS calculation
        cylinder = lba // (self.heads * self.sectors_per_track)
        head = (lba // self.sectors_per_track) % self.heads
        sector = (lba % self.sectors_per_track) + 1  # 1-based
        
        return cylinder, head, sector
    
    def validate_chs(self, cylinder: int, head: int, sector: int) -> bool:
        """Validate CHS values."""
        if cylinder >= self.cylinders:
            return False
        if head >= self.heads:
            return False
        if sector < 1 or sector > self.sectors_per_track:
            return False
        return True
    
    def get_total_sectors(self) -> int:
        """Get total number of sectors."""
        return self.total_sectors
    
    def get_disk_size(self) -> int:
        """Get disk size in bytes."""
        return len(self.disk_data)