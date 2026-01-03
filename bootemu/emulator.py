import sys
import struct
import ctypes
from pathlib import Path
from collections import OrderedDict
from typing import Literal

from .logger import EmulatorLogger
from .bios import (
    handle_int10,
    handle_int13,
    handle_int11,
    handle_int12,
    handle_int15,
    handle_int1a,
    handle_int14,
    handle_int16,
    handle_int17,
    BDAPolicy,
    BIOSDataArea,
    DiskParameterTable,
    IVT_NAMES,
    FixedDiskParameterTable,
)
from .regs import X86Regs

from unicorn import (
    Uc,  # pyright: ignore[reportPrivateImportUsage]
    UcError,  # pyright: ignore[reportPrivateImportUsage]
    UC_ARCH_X86,
    UC_MODE_16,
    UC_PROT_ALL,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_MEM_READ,
    UC_MEM_WRITE,
    UC_ERR_INSN_INVALID,
    UC_ERR_READ_UNMAPPED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_FETCH_UNMAPPED,
)

from capstone import Cs, CsInsn, CS_AC_WRITE, CS_ARCH_X86, CS_MODE_16
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_INS_NOP,
    X86_INS_CALL,
    X86_INS_INT,
    X86_INS_LSS,
    X86_INS_LES,
    X86_INS_LFS,
    X86_INS_LGS,
    X86_INS_LDS,
)


class BootloaderEmulator:
    """Emulator for x86 real mode bootloaders using Unicorn Engine"""

    def __init__(
        self,
        *,
        disk_image_path: str,
        max_instructions: int,
        geometry: None | tuple[int, int, int],
        floppy_type: Literal["360K", "720K", "1.2M", "1.44M", "2.88M"] | None,
        drive_number: int,
    ):
        """
        Initialize the emulator

        Args:
            disk_image_path: Path to disk image file (bootloader loaded from first 512 bytes)
            max_instructions: Maximum number of instructions to execute
            geometry: Manual CHS geometry as (cylinders, heads, sectors_per_track) tuple
            floppy_type: Standard floppy type ('360K', '720K', '1.2M', '1.44M', '2.88M')
            drive_number: BIOS drive number (0x00-0x7F for floppy, 0x80+ for HDD)
        """
        self.disk_image_path = Path(disk_image_path)
        self.max_instructions = max_instructions
        self.drive_number = drive_number
        self.manual_geometry = geometry
        self.floppy_type = floppy_type

        # Initialize logger
        self.log = EmulatorLogger(str(disk_image_path))

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
        self.log.console("[*] Initializing Unicorn Engine (x86 16-bit real mode)...")
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.regs = X86Regs(self.uc)

        # Initialize Capstone for disassembly
        self.cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self.cs.detail = True  # Enable detailed instruction info

        # Execution tracking
        self.instruction_count = 0
        self.uninitialized_count = 0
        self.intterrupt_seq = 0
        self.last_exception = None
        self.screen_output = ""
        self.serial_output = ""

        # Disk emulation
        self.setup_memory()
        self.load_disk_image()
        self.load_bootloader()
        self.setup_bios_tables()

    def stop(self):
        """Stop the Unicorn emulation"""
        self.uc.emu_stop()

    def mem_read(self, address: int, size: int) -> bytearray:
        return self.uc.mem_read(address, size)

    def mem_write(self, address: int, data: bytes | bytearray):
        self.uc.mem_write(address, bytes(data))
        self.uc.ctl_remove_cache(address, address + len(data))

    def setup_memory(self):
        """Set up memory regions for the emulator"""
        self.log.console("[*] Setting up memory...")

        # Map main memory (1 MB for real mode)
        self.uc.mem_map(self.memory_base, self.memory_size, UC_PROT_ALL)

        # Zero out memory
        self.mem_write(self.memory_base, b"\x00" * self.memory_size)

        self.log.console(
            f"  - Mapped {self.memory_size // 1024} KB at 0x{self.memory_base:08x}"
        )

    def detect_geometry(self):
        """
        Detect disk geometry following QEMU's algorithm:
        1. Manual override (if specified)
        2. Floppy type override (if specified)
        3. Floppy auto-detect (if drive < 0x80 and size matches)
        4. MBR partition table (extract from ending CHS)
        5. Fallback: 16 heads, 63 sectors/track (QEMU default)
        """
        # Standard floppy geometries (size_bytes: (cylinders, heads, sectors, name))
        FLOPPY_TYPES = {
            "360K": (40, 2, 9, 360 * 1024),
            "720K": (80, 2, 9, 720 * 1024),
            "1.2M": (80, 2, 15, 1200 * 1024),
            "1.44M": (80, 2, 18, 1440 * 1024),
            "2.88M": (80, 2, 36, 2880 * 1024),
        }

        total_sectors = self.disk_size // 512

        # Method 1: Manual geometry override
        if self.manual_geometry:
            self.cylinders, self.heads, self.sectors_per_track = self.manual_geometry
            self.geometry_method = "Manual override"
            return

        # Method 2: Floppy type override
        if self.floppy_type:
            c, h, s, _ = FLOPPY_TYPES[self.floppy_type]
            self.cylinders = c
            self.heads = h
            self.sectors_per_track = s
            self.geometry_method = f"Floppy type {self.floppy_type}"
            return

        # Method 3: Floppy auto-detect (if drive is floppy and size matches)
        if self.drive_number < 0x80:
            for floppy_name, (c, h, s, size) in FLOPPY_TYPES.items():
                if self.disk_size == size:
                    self.cylinders = c
                    self.heads = h
                    self.sectors_per_track = s
                    self.geometry_method = f"Auto-detected floppy {floppy_name}"
                    return

        # Method 4: MBR partition table (QEMU's guess_disk_lchs algorithm)
        # Read first 512 bytes (MBR)
        if self.disk_size >= 512:
            mbr = self.sector_read(0)

            # Check for valid MBR signature (0x55AA at offset 510-511)
            if mbr[510] == 0x55 and mbr[511] == 0xAA:
                # Examine partition entries (4 entries starting at offset 0x1BE)
                for i in range(4):
                    offset = 0x1BE + (i * 16)
                    entry = mbr[offset : offset + 16]

                    # Check if partition entry has valid data (non-zero partition type)
                    part_type = entry[4]
                    if part_type != 0:
                        # Extract ending CHS values
                        end_head = entry[5]
                        end_sector = entry[6] & 0x3F  # Lower 6 bits
                        end_cyl_high = (entry[6] & 0xC0) << 2
                        end_cyl_low = entry[7]
                        end_cyl = end_cyl_high | end_cyl_low

                        # Calculate geometry from ending CHS
                        # Use end_cyl + 1 as cylinder count (CHS values are 0-based)
                        heads = end_head + 1
                        sectors = end_sector
                        cylinders_from_partition = end_cyl + 1

                        # Validate (QEMU checks: cylinders between 1 and 16383)
                        if sectors > 0 and heads > 0:
                            # Calculate cylinders from total sectors for accuracy
                            cylinders = total_sectors // (heads * sectors)
                            # Use partition table cylinder as upper bound validation
                            if (
                                1 <= cylinders <= 16383
                                and cylinders >= cylinders_from_partition
                            ):
                                self.cylinders = cylinders
                                self.heads = heads
                                self.sectors_per_track = sectors
                                self.geometry_method = "MBR partition table"
                                return

        # Method 5: Fallback geometry (QEMU's guess_chs_for_size)
        # Default: 16 heads, 63 sectors/track
        self.heads = 16
        self.sectors_per_track = 63
        self.cylinders = total_sectors // (self.heads * self.sectors_per_track)
        if total_sectors % (self.heads * self.sectors_per_track) != 0:
            self.cylinders += 1
        self.geometry_method = "Fallback (QEMU default: 16H/63S)"

    def sector_read(self, lba: int) -> bytes:
        """Read sectors from disk image using LBA addressing"""
        if lba * 512 >= self.disk_size:
            raise ValueError(
                f"Disk read out of bounds: LBA={lba}, disk_size={self.disk_size}"
            )
        if lba in self.disk_cache:
            return self.disk_cache[lba]
        self.disk_fd.seek(lba * 512)
        sector_data = self.disk_fd.read(512)
        self.disk_cache[lba] = sector_data
        return sector_data

    def sector_write(self, lba: int, data: bytes | bytearray):
        """Write sectors to disk image using LBA addressing (COW)"""
        if lba * 512 >= self.disk_size:
            raise ValueError(
                f"Disk write out of bounds: LBA={lba}, disk_size={self.disk_size}"
            )
        if len(data) != 512:
            raise ValueError(
                f"Sector write data must be exactly 512 bytes, got {len(data)} bytes"
            )
        self.disk_cache[lba] = bytes(data)

    def load_disk_image(self):
        """Load disk image"""
        self.log.console(f"[*] Loading disk image from {self.disk_image_path}...")

        if not self.disk_image_path.exists():
            self.log.console(f"Error: Disk image not found: {self.disk_image_path}")
            sys.exit(1)

        # Open disk image file
        self.disk_fd = open(self.disk_image_path, "rb")
        self.disk_fd.seek(0, 2)
        self.disk_size = self.disk_fd.tell()
        self.disk_cache: OrderedDict[int, bytes] = OrderedDict()

        self.log.console(
            f"  - Disk image size: {self.disk_size} bytes ({self.disk_size // 1024} KB)"
        )

        # Detect disk geometry
        self.detect_geometry()
        self.log.console("[*] Disk geometry:")
        self.log.console(f"  - Cylinders: {self.cylinders}")
        self.log.console(f"  - Heads: {self.heads}")
        self.log.console(f"  - Sectors/Track: {self.sectors_per_track}")
        self.log.console(f"  - Total Sectors: {self.disk_size // 512}")
        self.log.console(f"  - Method: {self.geometry_method}")

        if self.disk_size < 512:
            self.log.console("Error: Disk image too small (must be at least 512 bytes)")
            sys.exit(1)

    def write_bda_to_memory(self):
        """Write BDA structure to Unicorn memory at 0x400"""
        if not self.bda:
            return

        bda_bytes = bytes(self.bda)
        assert len(bda_bytes) == 256, f"Invalid BDA size: {len(bda_bytes)}"
        self.mem_write(0x400, bda_bytes)
        self.log.console(
            f"[*] Initialized BIOS Data Area (BDA) at 0x00400 ({len(bda_bytes)} bytes)"
        )
        self.log.console(f"    Equipment: 0x{self.bda.equipment_list:04x}")
        self.log.console(f"    Memory: {self.bda.memory_size_kb} KB")
        self.log.console(
            f"    Video: Mode {self.bda.video_mode}, {self.bda.video_columns}x{self.bda.video_rows + 1}"
        )

    def _write_ivt_entry(self, interrupt_number: int, segment: int, offset: int):
        """Write a far pointer to an IVT (Interrupt Vector Table) entry

        Each IVT entry is 4 bytes: 2 bytes offset + 2 bytes segment (little-endian)

        Args:
            interrupt_number: Interrupt number (0x00-0xFF)
            segment: Segment address
            offset: Offset within segment
        """
        ivt_address = interrupt_number * 4
        # Write as little-endian: offset (2 bytes) + segment (2 bytes)
        data = struct.pack("<HH", offset, segment)
        self.mem_write(ivt_address, data)

    def load_bootloader(self):
        """Load the bootloader from the first 512 bytes of disk image at 0x7C00"""
        self.log.console("[*] Loading bootloader from disk image...")

        # Load boot sector from first 512 bytes of disk image
        bootloader_code = self.sector_read(0)
        self.log.console("  - Loaded boot sector from disk image (512 bytes)")

        # Verify boot signature (0xAA55 at offset 510-511)
        signature = struct.unpack("<H", bootloader_code[510:512])[0]
        if signature == 0xAA55:
            self.log.console(f"  ✓ Valid boot signature: 0x{signature:04x}")
        else:
            self.log.console(
                f"  ⚠ Warning: Invalid boot signature: 0x{signature:04x} (expected 0xAA55)"
            )
            sys.exit(1)

        # Load bootloader at 0x7C00
        self.mem_write(self.boot_address, bootloader_code)
        self.log.console(f"  - Loaded at 0x{self.boot_address:04x}")

    def create_bda(self):
        """Create and initialize BIOS Data Area"""
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
        self.bda.video_mode = 0x03  # Mode 3: 80x25 color text
        self.bda.video_columns = 80  # 80 columns
        self.bda.video_page_size = 4096  # 4KB per page
        self.bda.video_page_offset = 0  # Start at page 0
        self.bda.video_port = 0x3D4  # Color card controller port
        self.bda.active_page = 0  # Page 0
        self.bda.video_rows = 25  # 25 rows (actually 24, 0-indexed)
        self.bda.char_height = 8  # 8-pixel character height

        # Cursor configuration
        self.bda.cursor_pos[0] = 0x0000  # Page 0: row 0, col 0
        self.bda.cursor_start_line = 6  # Cursor lines 6-7 (underline)
        self.bda.cursor_end_line = 7

        # Keyboard buffer (empty)
        self.bda.kbd_buffer_head = 0x1E
        self.bda.kbd_buffer_tail = 0x1E
        self.bda.kbd_buffer_start = 0x1E  # Buffer at 0x041E
        self.bda.kbd_buffer_end = 0x3E  # Buffer ends at 0x043E

        # Hard disk configuration
        self.bda.num_hard_disks = 1 if self.drive_number >= 0x80 else 0

        # Timer: Start at 0
        self.bda.timer_counter = 0

        # Reset flag: Cold boot
        self.bda.reset_flag = 0x0000

        return self.bda

    def create_int_stubs(self):
        """Create INT N; IRET stubs in BIOS ROM area for all 256 interrupts"""
        STUB_BASE = 0xF0000

        for int_num in range(256):
            stub_addr = STUB_BASE + (int_num * 4)
            # CD XX = INT XX (2 bytes)
            # CF    = IRET    (1 byte)
            stub_code = bytes([0xCD, int_num, 0xCF])
            self.mem_write(stub_addr, stub_code)

    def setup_bios_tables(self):
        """Initialize BIOS parameter tables and IVT entries"""
        self.log.console("[*] Setting up BIOS parameter tables...")

        # Initialize BDA if enabled
        self.create_bda()
        self.write_bda_to_memory()

        # Create INT N; IRET stubs in BIOS ROM area
        self.create_int_stubs()

        # Populate ALL 256 IVT entries to point to BIOS stubs
        for int_num in range(256):
            stub_offset = int_num * 4
            self._write_ivt_entry(int_num, 0xF000, stub_offset)

        # Now overwrite specific IVT entries with data structure pointers

        # Create Diskette Parameter Table (DPT)
        # Standard 1.44MB floppy parameters
        dpt = DiskParameterTable()
        dpt.step_rate_head_unload = 0xDF  # Step rate 3ms, head unload 240ms
        dpt.head_load_dma = 0x02  # Head load 2ms, DMA mode
        dpt.motor_off_delay = 0x25  # Motor off delay: 37 ticks (~2 seconds)
        dpt.bytes_per_sector = 0x02  # 512 bytes per sector
        dpt.sectors_per_track = 0x12  # 18 sectors per track (1.44MB)
        dpt.gap_length = 0x1B  # Gap length: 27 bytes
        dpt.data_length = 0xFF  # Data length (use bytes/sector field)
        dpt.format_gap = 0x6C  # Format gap: 108 bytes
        dpt.format_fill = 0xF6  # Format fill byte
        dpt.head_settle = 0x0F  # Head settle: 15ms
        dpt.motor_start = 0x08  # Motor start: 1 second

        # Determine DPT parameters
        # If floppy type or drive is floppy, use detected geometry; otherwise default to 1.44MB
        if self.floppy_type or self.drive_number < 0x80:
            # Use detected floppy geometry (will have been set by detect_geometry)
            dpt.sectors_per_track = self.sectors_per_track
            dpt_location = "detected floppy"
        else:
            # Default to 1.44MB when booting from HDD with no floppy specified
            dpt_location = "default 1.44MB"
            # dpt.sectors_per_track already set to 18 (0x12) above

        # Place DPT at 0xF000:0xEFC7 (traditional BIOS location)
        DPT_ADDR = 0xFEFC7
        self.mem_write(DPT_ADDR, bytes(dpt))
        self._write_ivt_entry(0x1E, 0xF000, 0xEFC7)
        self.log.console(f"  - INT 0x1E (DPT): {dpt_location} at 0x{DPT_ADDR:05x}")

        # Handle hard disk parameter table (INT 0x41) if booting from HDD
        if self.drive_number >= 0x80:
            # Create Fixed Disk Parameter Table (FDPT) for first hard drive
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

            # Place FDPT at 0xF000:0xE401 (traditional location)
            FDPT_ADDR = 0xFE401
            self.mem_write(FDPT_ADDR, bytes(fdpt))
            self._write_ivt_entry(0x41, 0xF000, 0xE401)
            self.log.console(
                f"  - INT 0x41 (FDPT): Drive 0x{self.drive_number:02x} at 0x{FDPT_ADDR:05x}"
            )
            self.log.console(
                f"    Geometry: {self.cylinders}C x {self.heads}H x {self.sectors_per_track}S"
            )

            # INT 0x42 (second hard disk) - leave as NULL
            self._write_ivt_entry(0x42, 0x0000, 0x0000)
        else:
            # Booting from floppy - no FDPT needed
            # INT 0x41 and 0x42 left as NULL (zeros)
            self._write_ivt_entry(0x41, 0x0000, 0x0000)
            self._write_ivt_entry(0x42, 0x0000, 0x0000)

        # Video tables (INT 0x1D, 0x1F, 0x43) - leave as NULL
        self._write_ivt_entry(0x1D, 0x0000, 0x0000)
        self._write_ivt_entry(0x1F, 0x0000, 0x0000)
        self._write_ivt_entry(0x43, 0x0000, 0x0000)

    def setup_cpu_state(self):
        """Initialize CPU registers for boot"""
        self.log.console("[*] Setting up CPU state...")

        # Set instruction pointer to boot sector address
        self.regs.ip = self.boot_address

        # Set up segments (all start at 0 in real mode)
        self.regs.cs = 0x0000
        self.regs.ds = 0x0000
        self.regs.es = 0x0000
        self.regs.ss = 0x0000

        # Set up stack at boot sector location
        self.regs.sp = self.boot_address

        # Real mode typically boots with DL = drive number
        self.regs.dl = self.drive_number

        # Clear other registers
        self.regs.ax = 0
        self.regs.bx = 0
        self.regs.cx = 0
        self.regs.si = 0
        self.regs.di = 0
        self.regs.bp = 0

        self.log.console(f"  - CS:IP: 0x{0x0000:04x}:0x{self.boot_address:04x}")
        self.log.console(f"  - SS:SP: 0x{0x0000:04x}:0x{self.boot_address:04x}")
        self.log.console(f"  - DL: 0x{self.drive_number:02x} (drive number)")

    def _get_regs(self, instr: CsInsn, include_write=False):
        """Extract relevant registers from instruction operands using Capstone metadata"""
        regs: OrderedDict[str, None] = OrderedDict()
        operands = instr.operands

        if instr.id != X86_INS_NOP:
            # Check operands using Capstone's access metadata
            for i in range(len(operands)):
                op = operands[i]

                # Register operands - use access metadata to determine read/write
                if op.type == X86_OP_REG:
                    # NOTE: `push ds` has op.access == 0, but it is read, so we exclude
                    # write-only
                    if op.access != CS_AC_WRITE or include_write:
                        regs[self.reg_name(op.value.reg)] = None

                # Memory operands - track base and index registers
                elif op.type == X86_OP_MEM:
                    mem = op.value.mem
                    if mem.segment != 0:
                        regs[self.reg_name(mem.segment)] = None
                    if mem.base != 0:
                        regs[self.reg_name(mem.base)] = None
                    if mem.index != 0:
                        regs[self.reg_name(mem.index)] = None

            # Add implicitly read registers
            for reg in instr.regs_read:
                regs[self.reg_name(reg)] = None

            # Optionally add written registers
            if include_write:
                for reg in instr.regs_write:
                    regs[self.reg_name(reg)] = None

        return regs

    def reg_name(self, reg_id: int) -> str:
        name = self.cs.reg_name(reg_id)
        if name is None:
            raise KeyError(f"Unknown register ID: {reg_id}")
        # HACK: capstone returns 32-bit registers in 16-bit mode sometimes
        if name in ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi", "eip"]:
            name = name[1:]  # Remove 'e' prefix
        return name.lower()

    def compute_memory_address(self, instr):
        """Compute memory address for memory operands"""
        for op in instr.operands:
            if op.type == X86_OP_MEM:
                mem = op.value.mem

                # Get segment (default to DS if not specified)
                segment = 0
                if mem.segment != 0:
                    segment = getattr(self.regs, self.reg_name(mem.segment))
                else:
                    # Default segment is DS for most operations
                    segment = self.regs.ds

                # Get base register
                base = 0
                if mem.base != 0:
                    base = getattr(self.regs, self.reg_name(mem.base))

                # Get index register
                index = 0
                if mem.index != 0:
                    index = getattr(self.regs, self.reg_name(mem.index))

                # Calculate effective address: segment * 16 + base + index + displacement
                effective_addr = (segment << 4) + base + (index * mem.scale) + mem.disp

                return effective_addr, mem.disp

        return None, None

    def hook_code(self, uc: Uc, address: int, size: int, user_data):
        """Hook called before each instruction execution"""
        try:
            self.instruction_count += 1

            cs = self.regs.cs
            ip = self.regs.ip
            physical_addr = (cs << 4) + ip

            if address != physical_addr:
                self.log.console(
                    f"\n[*] Physical address mismatch: {hex(address)} != {hex(physical_addr)} ({cs:04x}:{ip:04x})"
                )
                uc.emu_stop()

            # Read instruction bytes
            try:
                code = uc.mem_read(address, 15)
            except UcError:
                code = b""

            # Disassemble instruction
            try:
                instr = next(Cs.disasm(self.cs, code, ip, 1))
                code = code[: instr.size]
            except StopIteration:
                instr = None  # Unsupported instruction

            if code == b"\x00\x00":  # possibly uninitialized memory
                self.uninitialized_count += 1
            else:
                self.uninitialized_count = 0

            if self.uninitialized_count >= 5:
                self.log.console(
                    "\n[*] Detected possible uninitialized memory usage (5 consecutive 0000 instructions)"
                )
                uc.emu_stop()

            # Build trace line: address|instruction|registers
            line = f"{cs:04x}:{ip:04x}={address: 6x}|{code.hex().ljust(10)}|"

            if instr is not None:
                # Add disassembled instruction
                line += instr.mnemonic
                if instr.op_str:
                    line += " "
                    line += instr.op_str

                # Add ALL relevant register values (before instruction execution)
                for reg in self._get_regs(instr):
                    reg_value = getattr(self.regs, reg)
                    if reg_value is not None:
                        line += f"|{reg}=0x{reg_value:04x}"

                # Add memory address and value if accessing memory
                mem_addr, disp = self.compute_memory_address(instr)
                if mem_addr is not None:
                    try:
                        # Determine size of memory access
                        mem_size = 2  # Default to word (16-bit)
                        for op in instr.operands:
                            if op.type == X86_OP_MEM:
                                mem_size = op.size
                                break

                        # Read memory value
                        if instr.id in [
                            X86_INS_LDS,
                            X86_INS_LES,
                            X86_INS_LFS,
                            X86_INS_LGS,
                            X86_INS_LSS,
                        ]:
                            offset_val = uc.mem_read(mem_addr, 2)
                            segment_val = uc.mem_read(mem_addr + 2, 2)
                            segment = struct.unpack("<H", segment_val)[0]
                            offset = struct.unpack("<H", offset_val)[0]
                            line += f"|mem[0x{mem_addr:x}]={segment:04x}:{offset:04x}"
                        elif mem_size == 1:
                            mem_val = uc.mem_read(mem_addr, 1)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:02x}"
                        elif mem_size == 2:
                            mem_bytes = uc.mem_read(mem_addr, 2)
                            mem_val = struct.unpack("<H", mem_bytes)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:04x}"
                        elif mem_size == 4:
                            mem_bytes = uc.mem_read(mem_addr, 4)
                            mem_val = struct.unpack("<I", mem_bytes)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:08x}"
                    except Exception:
                        # Memory not readable yet
                        pass

                # Special handling for CALL - show return address
                if instr.id == X86_INS_CALL:
                    # TODO: do we need to decode cs:ip from ret_address?
                    ret_address = address + instr.size
                    line += f"|return_address=0x{ret_address:x}"

                # Special handling for interrupts
                elif instr.id == X86_INS_INT:
                    # Get interrupt number from operand
                    if len(instr.operands) > 0 and instr.operands[0].type == X86_OP_IMM:
                        int_num = instr.operands[0].value.imm
                        line += f"|int=0x{int_num:02x}"
            else:
                line += f"??? (code: {code.hex()}, size: 0x{size:x})"

            # Write to instruction log
            self.log.instruction(line.rstrip())

            # Check instruction limit
            if self.instruction_count >= self.max_instructions:
                self.log.console(
                    f"\n[*] Reached maximum instruction limit ({self.max_instructions})"
                )
                uc.emu_stop()

            if code == b"\xeb\xfe":
                self.log.console("\n[*] Infinite loop detected!")
                uc.emu_stop()

        except (KeyboardInterrupt, SystemExit):
            self.log.console("\n[!] Interrupted by user")
            uc.emu_stop()
        except Exception as e:
            self.log.console(f"\n[!] Error in hook_code: {e}")
            import traceback

            traceback.print_exc()
            uc.emu_stop()

    def _dump_registers(self, label: str):
        """Dump register state for debugging"""
        ax = self.regs.ax
        bx = self.regs.bx
        cx = self.regs.cx
        dx = self.regs.dx
        si = self.regs.si
        di = self.regs.di
        bp = self.regs.bp
        sp = self.regs.sp
        cs = self.regs.cs
        ds = self.regs.ds
        es = self.regs.es
        ss = self.regs.ss
        flags = self.regs.flags
        cf = (flags >> 0) & 1
        zf = (flags >> 6) & 1
        self.log.instruction(
            f"[REGS] {label}: ax={ax:04x} bx={bx:04x} cx={cx:04x} dx={dx:04x} si={si:04x} di={di:04x} bp={bp:04x} sp={sp:04x} cs={cs:04x} ds={ds:04x} ss={ss:04x} es={es:04x} flags={flags:04x} cf={cf} zf={zf}"
        )

    def handle_bios_interrupt(self, uc: Uc, intno: int):
        """Route interrupt to appropriate BIOS service handler"""
        self.log.interrupt(
            f"[intseq={self.intterrupt_seq}] Handling BIOS INT 0x{intno:02x} -> {IVT_NAMES.get(intno, 'Unknown')}"
        )
        self.intterrupt_seq += 1

        self._dump_registers(f"INT 0x{intno:02x} BEFORE")
        if intno == 0x10:
            # Video Services
            handle_int10(self)
        elif intno == 0x11:
            # Get Equipment List
            handle_int11(self)
        elif intno == 0x12:
            # Get Memory Size
            handle_int12(self)
        elif intno == 0x13:
            # Disk Services
            handle_int13(self)
        elif intno == 0x14:
            # Serial Port Services
            handle_int14(self)
        elif intno == 0x15:
            # System Services
            handle_int15(self)
        elif intno == 0x16:
            # Keyboard Services
            handle_int16(self)
        elif intno == 0x17:
            # Printer Services
            handle_int17(self)
        elif intno == 0x1A:
            # Timer/Clock Services
            handle_int1a(self)
        else:
            # Unhandled BIOS interrupt
            ip = self.regs.ip
            self.log.interrupt(
                f"[INT] Unhandled BIOS interrupt 0x{intno:02x} at 0x{ip:04x}"
            )
            uc.emu_stop()

        self._dump_registers(f"INT 0x{intno:02x} AFTER")

    def hook_interrupt(self, uc: Uc, intno, user_data):
        """Hook called before INT instruction executes"""
        # Read current CS:IP
        # NOTE: Unicorn has already advanced IP past the INT instruction (2 bytes)
        # So the actual INT location is IP - 2
        cs = self.regs.cs
        ip = self.regs.ip
        int_location_ip = ip - 2  # Where the INT actually is

        # Calculate physical address of INT instruction
        physical_addr = (cs << 4) + int_location_ip

        # BIOS stub range: 0xF0000 - 0xF0400 (256 interrupts * 4 bytes each = 1024 bytes)
        STUB_BASE = 0xF0000
        STUB_END = 0xF0400

        # Read IVT entry for this interrupt
        ivt_addr = intno * 4
        ivt_offset = int.from_bytes(uc.mem_read(ivt_addr, 2), "little")
        ivt_segment = int.from_bytes(uc.mem_read(ivt_addr + 2, 2), "little")

        # Check if we're executing from BIOS stub region
        # If so, always handle in Python regardless of IVT contents
        if STUB_BASE <= physical_addr < STUB_END:
            # Executing from BIOS stub - handle in Python
            self.handle_bios_interrupt(uc, intno)
            # IP is already advanced past the INT, so we're good
        else:
            # Not from stub - manually push interrupt frame and jump to IVT handler
            # NOTE: IP has already been advanced past the INT instruction by Unicorn
            sp = self.regs.sp
            ss = self.regs.ss
            flags = self.regs.flags & 0xFFFF

            # Push FLAGS, CS, IP (return address points AFTER INT instruction)
            # IP is already pointing after the INT, so just push it as-is
            sp -= 2
            self.mem_write(ss * 16 + sp, flags.to_bytes(2, "little"))
            sp -= 2
            self.mem_write(ss * 16 + sp, cs.to_bytes(2, "little"))
            sp -= 2
            self.mem_write(ss * 16 + sp, ip.to_bytes(2, "little"))

            self.regs.sp = sp

            # Jump to IVT handler
            self.regs.cs = ivt_segment
            self.regs.ip = ivt_offset

    def hook_mem_invalid(self, uc: Uc, access, address, size, value, user_data):
        """Hook called on invalid memory access"""
        access_type = (
            "READ"
            if access == UC_MEM_READ
            else "WRITE"
            if access == UC_MEM_WRITE
            else "EXEC"
        )
        self.log.console(
            f"\n[!] Invalid memory access: {access_type} at 0x{address:08x} (size: {size})"
        )
        self.last_exception = f"Invalid memory {access_type}"
        return False

    def hook_ivt_access(self, uc: Uc, access, address, size, value, _user_data):
        """Hook called on IVT region (0x0000-0x03FF) memory access"""
        # Calculate interrupt vector number (each vector is 4 bytes)
        int_num = address // 4

        # Get current IP for context
        ip = self.regs.ip

        # Format access type
        if access == UC_MEM_READ:
            access_type = "IVT READ"
        else:
            access_type = "IVT WRITE"

        # Format the trace line
        line = f"[{access_type}] 0x{address:04x} | size={size} | int={int_num:02x} | value=0x{value:04x} | ip=0x{ip:04x} | intseq={self.intterrupt_seq}"
        self.intterrupt_seq += 1
        if int_num in IVT_NAMES:
            line += f" | name = {IVT_NAMES[int_num]}"

        # Also print to console if verbose
        self.log.interrupt(line)

        return True

    def sync_bda_hardware(
        self, bda_offset: int, value: int, size: int, field_name: str
    ) -> bool:
        """Sync hardware state when a BIOS_OWNED BDA field is written.

        Returns True if the write was handled, False if emulation should stop.
        """
        if field_name == "cursor_pos":
            # cursor_pos is an array of 8 uint16 values (one per page) at 0x050-0x05F
            # Format: row << 8 | col
            page_index = (bda_offset - 0x50) // 2
            row = (value >> 8) & 0xFF
            col = value & 0xFF
            self.log.interrupt(
                f"  -> Hardware sync: cursor_pos[{page_index}] = (row={row}, col={col})"
            )
            return True

        # Other BIOS_OWNED fields are not implemented
        return False

    def hook_bda_access(self, uc: Uc, access, address, size, value, _user_data):
        """Hook called on BDA region (0x0400-0x04FF) memory access"""

        # Get current IP for context
        ip = self.regs.ip

        # Format access type
        if access == UC_MEM_READ:
            access_type = "BDA READ"
        else:
            access_type = "BDA WRITE"

        # Use introspection to find field at this offset within BDA
        bda_offset = address - 0x0400  # Offset from start of BDA
        field_info = BIOSDataArea.get_field_at_offset(bda_offset)
        policy = BIOSDataArea.get_policy_at_offset(bda_offset)

        # Format the trace line
        if field_info:
            field_name, field_desc, field_size = field_info
            policy_name = ["PASSIVE", "BIOS_OWNED", "DENY"][policy]
            line = f"[{access_type}] 0x{address:04x} | size={size} | field={field_name} | desc={field_desc} | field_size={field_size} | value=0x{value:04x} | ip=0x{ip:04x} | policy={policy_name}"
        else:
            line = f"[{access_type}] 0x{address:04x} | size={size} | value=0x{value:04x} | ip=0x{ip:04x} | policy=PASSIVE"
        line += f" | intseq={self.intterrupt_seq}"
        self.intterrupt_seq += 1
        self.log.interrupt(line)

        # Handle writes based on policy
        if access == UC_MEM_WRITE:
            if policy == BDAPolicy.DENY:
                old = uc.mem_read(address, size)
                uc.mem_write(address, bytes(old))
                self.log.interrupt(f"{line}\n  -> DENIED (restored old value)")
                uc.emu_stop()
                return False
            elif policy == BDAPolicy.BIOS_OWNED:
                field_name = field_info[0] if field_info else "unknown"
                if not self.sync_bda_hardware(bda_offset, value, size, field_name):
                    self.log.console(
                        f"{line}\n  -> BIOS_OWNED '{field_name}' not implemented, stopping"
                    )
                    uc.emu_stop()
                    return False
            elif policy == BDAPolicy.PASSIVE:
                # Allow write
                pass

        return True

    def run(self):
        """Run the emulator"""
        self.log.console("\nEmulating...")

        # Add hooks
        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.uc.hook_add(UC_HOOK_INTR, self.hook_interrupt)
        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED
            | UC_HOOK_MEM_WRITE_UNMAPPED
            | UC_HOOK_MEM_FETCH_UNMAPPED,
            self.hook_mem_invalid,
        )

        # Add IVT-range-specific memory hook (0x0000-0x03FF)
        self.uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self.hook_ivt_access,
            begin=0x0000,
            end=0x03FF,
        )

        # Add BDA-range-specific memory hook (0x0400-0x04FF)
        self.uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self.hook_bda_access,
            begin=0x0400,
            end=0x04FF,
        )

        try:
            # Start emulation from boot address
            # In real mode, use CS:IP addressing (CS << 4 + IP)
            start_address = (self.regs.cs << 4) + self.boot_address

            # Run until we hit a HLT or error
            # We'll use a very high end address and rely on instruction limit
            end_address = 0xFFFFFFFF

            self._dump_registers("Initial register state")
            self.uc.emu_start(start_address, end_address)
            self._dump_registers("Final register state")

        except UcError as e:
            error_ip = self.regs.ip
            self.log.console(f"\n[!] Emulation error at IP=0x{error_ip:04x}: {e}")

            # Decode error
            if e.errno == UC_ERR_INSN_INVALID:
                self.log.console("    Invalid instruction")
            elif e.errno == UC_ERR_READ_UNMAPPED:
                self.log.console("    Read from unmapped memory")
            elif e.errno == UC_ERR_WRITE_UNMAPPED:
                self.log.console("    Write to unmapped memory")
            elif e.errno == UC_ERR_FETCH_UNMAPPED:
                self.log.console("    Fetch from unmapped memory")

        except KeyboardInterrupt:
            self.log.console("\n\n[!] Interrupted by user")

        finally:
            self.log.close()
            self.print_summary()

    def print_summary(self):
        """Print execution summary"""
        self.log.console("\n" + "=" * 80)
        self.log.console("Summary")
        self.log.console("=" * 80)
        self.log.console(f"Total instructions executed: {self.instruction_count}")

        # Get final register state
        self.log.console(f"Final CS:IP: {self.regs.cs:04x}:{self.regs.ip:04x}")

        self.log.console("\nFinal register state:")
        self.log.console(f"  AX: 0x{self.regs.ax:04x}")
        self.log.console(f"  BX: 0x{self.regs.bx:04x}")
        self.log.console(f"  CX: 0x{self.regs.cx:04x}")
        self.log.console(f"  DX: 0x{self.regs.dx:04x}")
        self.log.console(f"  SI: 0x{self.regs.si:04x}")
        self.log.console(f"  DI: 0x{self.regs.di:04x}")
        self.log.console(f"  BP: 0x{self.regs.bp:04x}")
        self.log.console(f"  SP: 0x{self.regs.sp:04x}")

        self.log.console("\nSegment registers:")
        self.log.console(f"  CS: 0x{self.regs.cs:04x}")
        self.log.console(f"  DS: 0x{self.regs.ds:04x}")
        self.log.console(f"  ES: 0x{self.regs.es:04x}")
        self.log.console(f"  SS: 0x{self.regs.ss:04x}")

        # Show some memory around the boot sector
        self.log.console(f"\nMemory at boot sector (0x{self.boot_address:04x}):")
        try:
            mem = self.uc.mem_read(self.boot_address, 64)
            for i in range(0, 64, 16):
                offset = self.boot_address + i
                hex_bytes = " ".join(f"{b:02x}" for b in mem[i : i + 16])
                ascii_repr = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in mem[i : i + 16]
                )
                self.log.console(f"  0x{offset:04x}: {hex_bytes:48s} | {ascii_repr}")
        except Exception as e:
            self.log.console(f"  Error reading memory: {e}")

        self.log.console(
            f"\n[*] Logs written to: {self.log.instr_path}, {self.log.int_path}"
        )
        self.log.console(f"\n[*] Screen output:\n{self.screen_output}")
        if self.serial_output:
            self.log.console(f"\n[*] Serial output:\n{self.serial_output}")
