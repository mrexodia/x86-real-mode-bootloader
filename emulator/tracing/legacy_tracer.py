"""Legacy instruction tracer.

The project uses golden-master traces to ensure emulator behavior (including
trace formatting) remains stable. The refactor introduced a new tracing stack,
but the golden masters are based on the original trace format.

This module contains the *exact* legacy tracing implementation extracted from
`BootloaderEmulator`.
"""

from __future__ import annotations

import struct
from collections import OrderedDict
from typing import Any, Optional, Tuple

from unicorn import Uc, UcError  # type: ignore
from unicorn.x86_const import *  # type: ignore

from capstone import Cs, CsInsn, CS_AC_WRITE  # type: ignore
from capstone.x86_const import *  # type: ignore


class LegacyInstructionTracer:
    """Implements the legacy per-instruction trace format."""

    def __init__(self, emulator: Any):
        # We keep a loose type here to avoid circular imports.
        self.emu = emulator

    def get_register_value(self, reg_name) -> int:
        """Get register value by name."""
        reg_map = {
            'ah': UC_X86_REG_AH, 'al': UC_X86_REG_AL, 'ax': UC_X86_REG_AX,
            'bh': UC_X86_REG_BH, 'bl': UC_X86_REG_BL, 'bx': UC_X86_REG_BX,
            'ch': UC_X86_REG_CH, 'cl': UC_X86_REG_CL, 'cx': UC_X86_REG_CX,
            'dh': UC_X86_REG_DH, 'dl': UC_X86_REG_DL, 'dx': UC_X86_REG_DX,
            'si': UC_X86_REG_SI, 'di': UC_X86_REG_DI,
            'bp': UC_X86_REG_BP, 'sp': UC_X86_REG_SP,
            'cs': UC_X86_REG_CS, 'ds': UC_X86_REG_DS,
            'es': UC_X86_REG_ES, 'ss': UC_X86_REG_SS,
            'ip': UC_X86_REG_IP, 'flags': UC_X86_REG_EFLAGS,
        }

        reg_name_lower = reg_name.lower()
        if reg_name_lower in reg_map:
            return self.emu.uc.reg_read(reg_map[reg_name_lower])
        raise KeyError(f"Register not found: '{reg_name_lower}'")

    def reg_name(self, reg_id: int):
        name = self.emu.cs.reg_name(reg_id)
        if name is None:
            return None
        # HACK: capstone returns 32-bit registers in 16-bit mode sometimes
        if name in ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi", "eip"]:
            name = name[1:]  # Remove 'e' prefix
        return name

    def _get_regs(self, instr: CsInsn, include_write: bool = False):
        """Extract relevant registers from instruction operands using Capstone metadata."""
        regs = OrderedDict()
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

    def compute_memory_address(self, instr: CsInsn) -> Tuple[Optional[int], Optional[int]]:
        """Compute memory address for memory operands."""
        for op in instr.operands:
            if op.type == X86_OP_MEM:
                mem = op.value.mem

                # Get segment (default to DS if not specified)
                if mem.segment != 0:
                    segment = self.get_register_value(self.reg_name(mem.segment))
                else:
                    # Default segment is DS for most operations
                    segment = self.get_register_value("DS")

                # Get base register
                base = 0
                if mem.base != 0:
                    base = self.get_register_value(self.reg_name(mem.base))

                # Get index register
                index = 0
                if mem.index != 0:
                    index = self.get_register_value(self.reg_name(mem.index))

                # Calculate effective address: segment * 16 + base + index + displacement
                effective_addr = (segment << 4) + base + (index * mem.scale) + mem.disp

                return effective_addr, mem.disp

        return None, None

    def hook_code(self, uc: Uc, address: int, size: int, _user_data: Any):
        """Hook called before each instruction execution."""
        try:
            self.emu.instruction_count += 1

            cs = uc.reg_read(UC_X86_REG_CS)
            ip = uc.reg_read(UC_X86_REG_IP)
            physical_addr = (cs << 4) + ip

            if address != physical_addr:
                print(f"\n[*] Physical address mismatch: {hex(address)} != {hex(physical_addr)} ({cs:04x}:{ip:04x})")
                uc.emu_stop()

            # Read instruction bytes
            try:
                code = uc.mem_read(address, 15)
            except UcError:
                code = b""

            # Disassemble instruction
            try:
                instr = next(Cs.disasm(self.emu.cs, code, ip, 1))
                code = code[:instr.size]
            except StopIteration:
                instr = None  # Unsupported instruction

            if code == b"\x00\x00":  # possibly uninitialized memory
                self.emu.uninitialized_count += 1
            else:
                self.emu.uninitialized_count = 0

            if self.emu.uninitialized_count >= 5:
                print("\n[*] Detected possible uninitialized memory usage (5 consecutive 0000 instructions)")
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
                    reg_value = self.get_register_value(reg)
                    if reg_value is not None:
                        line += f"|{reg}=0x{reg_value:x}"

                # Add memory address and value if accessing memory
                mem_addr, _disp = self.compute_memory_address(instr)
                if mem_addr is not None:
                    try:
                        # Determine size of memory access
                        mem_size = 2  # Default to word (16-bit)
                        for op in instr.operands:
                            if op.type == X86_OP_MEM:
                                mem_size = op.size
                                break

                        # Read memory value
                        if instr.id in [X86_INS_LDS, X86_INS_LES, X86_INS_LFS, X86_INS_LGS, X86_INS_LSS]:
                            offset_val = uc.mem_read(mem_addr, 2)
                            segment_val = uc.mem_read(mem_addr + 2, 2)
                            segment = struct.unpack('<H', segment_val)[0]
                            offset = struct.unpack('<H', offset_val)[0]
                            line += f"|mem[0x{mem_addr:x}]={segment:04x}:{offset:04x}"
                        elif mem_size == 1:
                            mem_val = uc.mem_read(mem_addr, 1)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:02x}"
                        elif mem_size == 2:
                            mem_bytes = uc.mem_read(mem_addr, 2)
                            mem_val = struct.unpack('<H', mem_bytes)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:04x}"
                        elif mem_size == 4:
                            mem_bytes = uc.mem_read(mem_addr, 4)
                            mem_val = struct.unpack('<I', mem_bytes)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:08x}"
                    except Exception:
                        # Memory not readable yet
                        pass

                # Special handling for CALL - show return address
                if instr.id == X86_INS_CALL:
                    ret_address = address + instr.size
                    line += f"|return_address=0x{ret_address:x}"

                # Special handling for interrupts
                elif instr.id == X86_INS_INT:
                    # Get interrupt number from operand
                    if len(instr.operands) > 0 and instr.operands[0].type == X86_OP_IMM:
                        int_num = instr.operands[0].value.imm
                        line += f"|int=0x{int_num:x}"
            else:
                line += f"??? (code: {code.hex()}, size: 0x{size:x})"

            line += "\n"

            # Write to trace file
            if self.emu.trace_output:
                self.emu.trace_output.write(line)

            # Optionally print to console (all instructions in verbose mode)
            if self.emu.verbose:
                print(line.rstrip())

            # Check instruction limit
            if self.emu.instruction_count >= self.emu.max_instructions:
                print(f"\n[*] Reached maximum instruction limit ({self.emu.max_instructions})")
                uc.emu_stop()

            if code == b"\xeb\xfe":
                print("\n[*] Infinite loop detected!")
                uc.emu_stop()

        except (KeyboardInterrupt, SystemExit):
            print("\n[!] Interrupted by user")
            uc.emu_stop()
        except Exception as e:
            print(f"\n[!] Error in hook_code: {e}")
            import traceback

            traceback.print_exc()
            uc.emu_stop()
