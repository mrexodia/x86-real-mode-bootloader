#!/usr/bin/env python3
"""x86 Real Mode Bootloader Emulator using Unicorn Engine and Capstone.

This emulator loads a disk image and emulates the bootloader from the first 512 bytes,
logging every instruction execution with relevant registers and memory accesses.

This file intentionally contains only orchestration and state. BIOS services and the
legacy tracing implementation are split into dedicated modules.
"""

import sys
import struct
import ctypes
from pathlib import Path

from unicorn import Uc, UcError  # type: ignore
from unicorn import *  # type: ignore
from unicorn.x86_const import *  # type: ignore

from capstone import Cs  # type: ignore
from capstone import *  # type: ignore
from capstone.x86_const import *  # type: ignore

from ..bios import BIOSServices
from ..tracing import LegacyInstructionTracer

from ..hardware.memory import BIOSDataArea
from ..hardware.geometry import DiskParameterTable, FixedDiskParameterTable
from ..hardware.ivt import IVT_NAMES
from ..hardware.bda import BDAPolicy
from ..hardware.disk import DiskImage


class BootloaderEmulator:
    """Emulator for x86 real mode bootloaders using Unicorn Engine."""

    def __init__(
        self,
        disk_image_path,
        max_instructions: int = 1000000,
        trace_file: str = "trace.txt",
        verbose: bool = True,
        geometry=None,
        floppy_type=None,
        drive_number: int = 0x80,
    ):
        """Initialize the emulator."""
        self.disk_image_path = Path(disk_image_path)
        self.max_instructions = max_instructions
        self.trace_file = trace_file
        self.verbose = verbose
        self.drive_number = drive_number
        self.manual_geometry = geometry
        self.floppy_type = floppy_type

        # CHS geometry (will be detected later)
        self.cylinders = 0
        self.heads = 0
        self.sectors_per_track = 0
        self.geometry_method = "Unknown"

        # Boot sector is loaded at 0x7C00
        self.boot_address = 0x7C00

        # Memory configuration for real mode (1MB)
        self.memory_base = 0x0000
        self.memory_size = 0x100000  # 1 MB

        # Initialize Unicorn for x86 16-bit real mode
        print("[*] Initializing Unicorn Engine (x86 16-bit real mode)...")
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)

        # Initialize Capstone for disassembly
        self.cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self.cs.detail = True  # Enable detailed instruction info

        # Execution tracking
        self.instruction_count = 0
        self.uninitialized_count = 0
        self.trace_output = None
        self.last_exception = None
        self.screen_output = ""

        # Modular components
        self.tracer = LegacyInstructionTracer(self)
        self.bios = BIOSServices(self)

        # Setup machine state
        self.setup_memory()
        self.load_disk_image()
        self.load_bootloader()
        self.setup_bios_tables()

    def setup_memory(self):
        """Set up memory regions for the emulator."""
        print("[*] Setting up memory...")

        # Map main memory (1 MB for real mode)
        self.uc.mem_map(self.memory_base, self.memory_size, UC_PROT_ALL)

        # Zero out memory
        self.mem_write(self.memory_base, b"\x00" * self.memory_size)

        print(f"  - Mapped {self.memory_size // 1024} KB at 0x{self.memory_base:08X}")

    def detect_geometry(self):
        """Populate geometry fields from the loaded :class:`~DiskImage` instance."""
        if not hasattr(self, "disk") or self.disk is None:
            raise RuntimeError("Disk image not loaded")

        self.cylinders = self.disk.cylinders
        self.heads = self.disk.heads
        self.sectors_per_track = self.disk.sectors_per_track
        self.geometry_method = self.disk.geometry_method

    def sector_read(self, lba: int) -> bytes:
        """Read a sector from the loaded disk image (LBA)."""
        return self.disk.sector_read(lba)

    def sector_write(self, lba: int, data: bytes):
        """Write a sector to the disk cache (COW)."""
        return self.disk.sector_write(lba, data)

    def load_disk_image(self):
        """Load the disk image and detect geometry."""
        print(f"[*] Loading disk image from {self.disk_image_path}...")

        try:
            self.disk = DiskImage(
                self.disk_image_path,
                drive_number=self.drive_number,
                manual_geometry=self.manual_geometry,
                floppy_type=self.floppy_type,
            )
            self.disk.open()
        except FileNotFoundError:
            print(f"Error: Disk image not found: {self.disk_image_path}")
            sys.exit(1)
        except Exception as e:
            print(f"Error: Failed to load disk image: {e}")
            sys.exit(1)

        self.disk_size = self.disk.size
        print(f"  - Disk image size: {self.disk_size} bytes ({self.disk_size // 1024} KB)")

        self.detect_geometry()
        print("[*] Disk geometry:")
        print(f"  - Cylinders: {self.cylinders}")
        print(f"  - Heads: {self.heads}")
        print(f"  - Sectors/Track: {self.sectors_per_track}")
        print(f"  - Total Sectors: {self.disk_size // 512}")
        print(f"  - Method: {self.geometry_method}")

    def mem_write(self, address: int, data: bytes | bytearray):
        self.uc.mem_write(address, bytes(data))
        self.uc.ctl_remove_cache(address, address + len(data))

    def write_bda_to_memory(self):
        """Write BDA structure to Unicorn memory at 0x400."""
        if not self.bda:
            return

        bda_bytes = bytes(self.bda)
        assert len(bda_bytes) == 256, f"Invalid BDA size: {len(bda_bytes)}"
        self.mem_write(0x400, bda_bytes)
        print(f"[*] Initialized BIOS Data Area (BDA) at 0x00400 ({len(bda_bytes)} bytes)")
        print(f"    Equipment: 0x{self.bda.equipment_list:04X}")
        print(f"    Memory: {self.bda.memory_size_kb} KB")
        print(f"    Video: Mode {self.bda.video_mode}, {self.bda.video_columns}x{self.bda.video_rows+1}")

    def _write_ivt_entry(self, interrupt_number: int, segment: int, offset: int):
        """Write a far pointer to an IVT entry."""
        ivt_address = interrupt_number * 4
        data = struct.pack('<HH', offset, segment)
        self.mem_write(ivt_address, data)

    def load_bootloader(self):
        """Load the bootloader from the first 512 bytes of disk image at 0x7C00."""
        print("[*] Loading bootloader from disk image...")

        bootloader_code = self.sector_read(0)
        print("  - Loaded boot sector from disk image (512 bytes)")

        signature = struct.unpack('<H', bootloader_code[510:512])[0]
        if signature == 0xAA55:
            print(f"  ✓ Valid boot signature: 0x{signature:04X}")
        else:
            print(f"  ⚠ Warning: Invalid boot signature: 0x{signature:04X} (expected 0xAA55)")
            sys.exit(1)

        self.mem_write(self.boot_address, bootloader_code)
        print(f"  - Loaded at 0x{self.boot_address:04X}")

    def create_bda(self):
        """Create and initialize BIOS Data Area."""
        self.bda = BIOSDataArea()

        # Zero everything first
        ctypes.memset(ctypes.addressof(self.bda), 0, ctypes.sizeof(self.bda))

        # Essential memory configuration
        self.bda.memory_size_kb = 640

        # Equipment word - minimal configuration
        # Bit 4-5: Video mode (10 = 80x25 color text)
        equipment = 0x0020  # Minimal: video only
        if self.drive_number < 0x80:
            equipment |= 0x0001  # Bit 0: Floppy drive installed

        self.bda.equipment_list = equipment

        # Video configuration (80x25 color text mode)
        self.bda.video_mode = 0x03
        self.bda.video_columns = 80
        self.bda.video_page_size = 4096
        self.bda.video_page_offset = 0
        self.bda.video_port = 0x3D4
        self.bda.active_page = 0
        self.bda.video_rows = 25
        self.bda.char_height = 8

        # Cursor configuration
        self.bda.cursor_pos[0] = 0x0000
        self.bda.cursor_start_line = 6
        self.bda.cursor_end_line = 7

        # Keyboard buffer (empty)
        self.bda.kbd_buffer_head = 0x1E
        self.bda.kbd_buffer_tail = 0x1E
        self.bda.kbd_buffer_start = 0x1E
        self.bda.kbd_buffer_end = 0x3E

        # Hard disk configuration
        self.bda.num_hard_disks = 1 if self.drive_number >= 0x80 else 0

        # Timer: Start at 0
        self.bda.timer_counter = 0

        # Reset flag: Cold boot
        self.bda.reset_flag = 0x0000

        return self.bda

    def create_int_stubs(self):
        """Create INT N; IRET stubs in BIOS ROM area for all 256 interrupts."""
        STUB_BASE = 0xF0000

        for int_num in range(256):
            stub_addr = STUB_BASE + (int_num * 4)
            stub_code = bytes([0xCD, int_num, 0xCF])
            self.mem_write(stub_addr, stub_code)

    def setup_bios_tables(self):
        """Initialize BIOS parameter tables and IVT entries."""
        print("[*] Setting up BIOS parameter tables...")

        self.create_bda()
        self.write_bda_to_memory()

        self.create_int_stubs()

        # Populate ALL 256 IVT entries to point to BIOS stubs
        for int_num in range(256):
            stub_offset = int_num * 4
            self._write_ivt_entry(int_num, 0xF000, stub_offset)

        # Now overwrite specific IVT entries with data structure pointers

        # Create Diskette Parameter Table (DPT)
        dpt = DiskParameterTable()
        dpt.step_rate_head_unload = 0xDF
        dpt.head_load_dma = 0x02
        dpt.motor_off_delay = 0x25
        dpt.bytes_per_sector = 0x02
        dpt.sectors_per_track = 0x12
        dpt.gap_length = 0x1B
        dpt.data_length = 0xFF
        dpt.format_gap = 0x6C
        dpt.format_fill = 0xF6
        dpt.head_settle = 0x0F
        dpt.motor_start = 0x08

        # Determine DPT parameters
        if self.floppy_type or self.drive_number < 0x80:
            dpt_location = "detected floppy"
        else:
            dpt_location = "default 1.44MB"

        if dpt_location == "detected floppy" and self.floppy_type is None:
            dpt.sectors_per_track = self.sectors_per_track

        # Place DPT at 0xF000:0xEFC7
        DPT_ADDR = 0xFEFC7
        self.mem_write(DPT_ADDR, bytes(dpt))
        self._write_ivt_entry(0x1E, 0xF000, 0xEFC7)
        print(f"  - INT 0x1E (DPT): {dpt_location} at 0x{DPT_ADDR:05X}")

        # Handle hard disk parameter table (INT 0x41) if booting from HDD
        if self.drive_number >= 0x80:
            fdpt = FixedDiskParameterTable()
            fdpt.cylinders = self.cylinders
            fdpt.heads = self.heads
            fdpt.reduced_write_current = 0
            fdpt.write_precomp = 0
            fdpt.ecc_burst = 0
            fdpt.control_byte = 0xC0
            fdpt.timeout_1 = 0
            fdpt.timeout_2 = 0
            fdpt.timeout_3 = 0
            fdpt.landing_zone = self.cylinders
            fdpt.sectors_per_track = self.sectors_per_track
            fdpt.reserved = 0

            FDPT_ADDR = 0xFE401
            self.mem_write(FDPT_ADDR, bytes(fdpt))
            self._write_ivt_entry(0x41, 0xF000, 0xE401)
            print(f"  - INT 0x41 (FDPT): Drive 0x{self.drive_number:02X} at 0x{FDPT_ADDR:05X}")
            print(f"    Geometry: {self.cylinders}C x {self.heads}H x {self.sectors_per_track}S")

            self._write_ivt_entry(0x42, 0x0000, 0x0000)
        else:
            self._write_ivt_entry(0x41, 0x0000, 0x0000)
            self._write_ivt_entry(0x42, 0x0000, 0x0000)

        # Video tables (INT 0x1D, 0x1F, 0x43) - leave as NULL
        self._write_ivt_entry(0x1D, 0x0000, 0x0000)
        self._write_ivt_entry(0x1F, 0x0000, 0x0000)
        self._write_ivt_entry(0x43, 0x0000, 0x0000)

    def setup_cpu_state(self):
        """Initialize CPU registers for boot."""
        print("[*] Setting up CPU state...")

        self.uc.reg_write(UC_X86_REG_IP, self.boot_address)

        self.uc.reg_write(UC_X86_REG_CS, 0x0000)
        self.uc.reg_write(UC_X86_REG_DS, 0x0000)
        self.uc.reg_write(UC_X86_REG_ES, 0x0000)
        self.uc.reg_write(UC_X86_REG_SS, 0x0000)

        self.uc.reg_write(UC_X86_REG_SP, self.boot_address)

        # Real mode typically boots with DL = drive number
        self.uc.reg_write(UC_X86_REG_DL, self.drive_number)

        # Clear other registers
        for reg in [UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP]:
            self.uc.reg_write(reg, 0x0000)

        print(f"  - CS:IP: 0x{0x0000:04X}:0x{self.boot_address:04X}")
        print(f"  - SS:SP: 0x{0x0000:04X}:0x{self.boot_address:04X}")
        print(f"  - DL: 0x{self.drive_number:02X} (drive number)")

    def hook_mem_invalid(self, uc: Uc, access, address, size, value, _user_data):
        """Hook called on invalid memory access."""
        access_type = "READ" if access == UC_MEM_READ else "WRITE" if access == UC_MEM_WRITE else "EXEC"
        print(f"\n[!] Invalid memory access: {access_type} at 0x{address:08X} (size: {size})")
        self.last_exception = f"Invalid memory {access_type}"
        return False

    def hook_ivt_access(self, uc: Uc, access, address, size, value, _user_data):
        """Hook called on IVT region (0x0000-0x03FF) memory access."""
        int_num = address // 4
        ip = uc.reg_read(UC_X86_REG_IP)

        access_type = "IVT READ" if access == UC_MEM_READ else "IVT WRITE"

        line = (
            f"[{access_type}] 0x{address:04X} | size={size} | int={int_num:02X} | value=0x{value:X} | ip=0x{ip:04X}"
        )
        if int_num in IVT_NAMES:
            line += f"| name = {IVT_NAMES[int_num]}"
        line += "\n"

        if self.trace_output:
            self.trace_output.write(line)

        if self.verbose:
            print(line.strip())

        return True

    def sync_bda_hardware(self, bda_offset: int, value: int, size: int, field_name: str) -> bool:
        """Sync hardware state when a BIOS_OWNED BDA field is written."""
        if field_name == "cursor_pos":
            page_index = (bda_offset - 0x50) // 2
            row = (value >> 8) & 0xFF
            col = value & 0xFF
            print(f"  -> Hardware sync: cursor_pos[{page_index}] = (row={row}, col={col})")
            return True

        return False

    def hook_bda_access(self, uc: Uc, access, address, size, value, _user_data):
        """Hook called on BDA region (0x0400-0x04FF) memory access."""
        ip = uc.reg_read(UC_X86_REG_IP)

        access_type = "BDA READ" if access == UC_MEM_READ else "BDA WRITE"

        bda_offset = address - 0x0400
        field_info = BIOSDataArea.get_field_at_offset(bda_offset)
        policy = BIOSDataArea.get_policy_at_offset(bda_offset)

        if field_info:
            field_name, field_desc, _field_size = field_info
            policy_name = ["PASSIVE", "BIOS_OWNED", "DENY"][policy]
            line = (
                f"[{access_type}] 0x{address:04X} | size={size} | field={field_name} | desc={field_desc} | "
                f"value=0x{value:X} | ip=0x{ip:04X} | policy={policy_name}"
            )
        else:
            line = f"[{access_type}] 0x{address:04X} | size={size} | value=0x{value:X} | ip=0x{ip:04X} | policy=PASSIVE"

        line += "\n"

        if self.trace_output:
            self.trace_output.write(line)

        if self.verbose:
            print(line.strip())

        if access == UC_MEM_WRITE:
            if policy == BDAPolicy.DENY:
                old = uc.mem_read(address, size)
                uc.mem_write(address, bytes(old))
                if self.verbose:
                    print("  -> DENIED (restored old value)")
                uc.emu_stop()
                return False
            elif policy == BDAPolicy.BIOS_OWNED:
                field_name = field_info[0] if field_info else "unknown"
                if not self.sync_bda_hardware(bda_offset, value, size, field_name):
                    if self.verbose:
                        print(f"  -> BIOS_OWNED '{field_name}' not implemented, stopping")
                    uc.emu_stop()
                    return False

        return True

    def run(self):
        """Run the emulator."""
        print("\n" + "=" * 80)
        print(f"Starting emulation (trace file: {self.trace_file})...")
        print("=" * 80 + "\n")

        try:
            self.trace_output = open(self.trace_file, 'w')
            print(f"[*] Writing trace to {self.trace_file}")
        except Exception as e:
            print(f"[!] Error opening trace file: {e}")
            return

        # Add hooks
        self.uc.hook_add(UC_HOOK_CODE, self.tracer.hook_code)
        self.uc.hook_add(UC_HOOK_INTR, self.bios.hook_interrupt)
        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            self.hook_mem_invalid,
        )

        self.uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self.hook_ivt_access,
            begin=0x0000,
            end=0x03FF,
        )

        self.uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self.hook_bda_access,
            begin=0x0400,
            end=0x04FF,
        )

        try:
            start_address = (self.uc.reg_read(UC_X86_REG_CS) << 4) + self.boot_address
            end_address = 0xFFFFFFFF
            self.uc.emu_start(start_address, end_address)

        except UcError as e:
            error_ip = self.uc.reg_read(UC_X86_REG_IP)
            print(f"\n[!] Emulation error at IP=0x{error_ip:04X}: {e}")

            if e.errno == UC_ERR_INSN_INVALID:
                print("    Invalid instruction")
            elif e.errno == UC_ERR_READ_UNMAPPED:
                print("    Read from unmapped memory")
            elif e.errno == UC_ERR_WRITE_UNMAPPED:
                print("    Write to unmapped memory")
            elif e.errno == UC_ERR_FETCH_UNMAPPED:
                print("    Fetch from unmapped memory")

        finally:
            if self.trace_output:
                self.trace_output.close()
            self.print_summary()

    def print_summary(self):
        """Print execution summary."""
        print("\n" + "=" * 80)
        print("Emulation Summary")
        print("=" * 80)
        print(f"Total instructions executed: {self.instruction_count}")

        ip = self.uc.reg_read(UC_X86_REG_IP)
        cs = self.uc.reg_read(UC_X86_REG_CS)
        print(f"Final CS:IP: {cs:04x}:{ip:04x}")

        print("\nFinal register state:")
        regs = [
            ('AX', UC_X86_REG_AX),
            ('BX', UC_X86_REG_BX),
            ('CX', UC_X86_REG_CX),
            ('DX', UC_X86_REG_DX),
            ('SI', UC_X86_REG_SI),
            ('DI', UC_X86_REG_DI),
            ('BP', UC_X86_REG_BP),
            ('SP', UC_X86_REG_SP),
        ]

        for name, reg in regs:
            value = self.uc.reg_read(reg)
            print(f"  {name}: 0x{value:04X}")

        print("\nSegment registers:")
        segs = [
            ('CS', UC_X86_REG_CS),
            ('DS', UC_X86_REG_DS),
            ('ES', UC_X86_REG_ES),
            ('SS', UC_X86_REG_SS),
        ]
        for name, reg in segs:
            value = self.uc.reg_read(reg)
            print(f"  {name}: 0x{value:04X}")

        print(f"\nMemory at boot sector (0x{self.boot_address:04X}):")
        try:
            mem = self.uc.mem_read(self.boot_address, 64)
            for i in range(0, 64, 16):
                offset = self.boot_address + i
                hex_bytes = ' '.join(f'{b:02X}' for b in mem[i:i + 16])
                ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in mem[i:i + 16])
                print(f"  0x{offset:04X}: {hex_bytes:48s} | {ascii_repr}")
        except Exception as e:
            print(f"  Error reading memory: {e}")

        print(f"\n[*] Trace written to {self.trace_file}")
        print(f"    Total instructions: {self.instruction_count}")
        if self.screen_output.strip():
            print(f"\n[*] Screen output:\n{self.screen_output}")
