# AGENTS.md - AI Agent Guidelines for x86 Real Mode Bootloader

This document provides guidance for AI agents working with the x86 real mode bootloader emulator.

## Emulator Overview

The `emulator.py` script emulates x86 real mode execution using the Unicorn Engine. It loads a disk image, executes the bootloader from the first 512 bytes, and provides detailed logging at multiple levels.

## Running the Emulator

### Basic Usage

```bash
# Run with default 1 million instructions
./emulator.py <disk_image>

# Run with custom instruction limit
./emulator.py <disk_image> -m 1000000

# Run a floppy image (sets drive number to 0x00)
./emulator.py dos7.img -f 1.44M -m 1000000

# Specify custom CHS geometry
./emulator.py hdd.img -g 120,16,63

# Override drive number
./emulator.py disk.img -d 0x00
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-m, --max-instructions` | Maximum instructions to execute (default: 1,000,000) |
| `-f, --floppy-type` | Floppy type: 360K, 720K, 1.2M, 1.44M, 2.88M |
| `-g, --geometry` | Manual CHS geometry as `C,H,S` (e.g., `120,16,63`) |
| `-d, --drive-number` | BIOS drive number (default: 0x80 for HDD, 0x00 for floppy) |

## Log File Structure (Progressive Disclosure)

The emulator produces output at three levels of detail, enabling progressive disclosure when debugging:

### 1. stdout (Immediate Feedback)

Console output shows:
- Setup information (memory mapping, disk geometry, BIOS tables)
- Emulation summary (instruction count, final registers)
- Screen output (INT 10h teletype characters)
- Serial output (if any)
- Log file paths
- Error messages if the emulator crashes

**Use for:** Quick verification that emulation ran, checking final state.

### 2. `{basename}.interrupts.log` (High-Level Trace)

Contains BIOS-level events:
- Interrupt calls: `[intseq=N] Handling BIOS INT 0x10 -> Video Services`
- Interrupt details: `[INT 0x10] Teletype output: 'H'` (might have multiple lines around it)
- IVT access: `[IVT READ] 0x0040 | size=2 | int=10 | value=0x7C71 | ip=0x7C22 | intseq=5`
- BDA access: `[BDA READ] ...`
- Register dumps before/after interrupts

**Use for:** Understanding what BIOS services the code is calling, tracking IVT modifications.

### 3. `{basename}.instructions.log` (Full Trace)

Contains everything from interrupts.log plus:
- Every executed instruction with format:
  ```
  CS:IP=LINEAR|BYTES|MNEMONIC OPERANDS|CONTEXT
  ```
- Initial and final register states
- Memory access details

Example instruction line:
```
0000:7c11=  7c11|a30005    |mov word ptr [0x500], ax|ax=0x1234|mem[0x500]=0x0000
```

**Use for:** Step-by-step debugging, understanding exact execution flow.

## Debugging Workflow

### Step 1: Check stdout

Run the emulator and observe the summary:
```bash
uv run ./emulator.py dos7.img -m 1000000
```

Look for:
- Did it halt normally or hit the instruction limit?
- What was the final CS:IP?
- Any screen/serial output?

### Step 2: Review Interrupt Log

Examine the high-level trace:
```bash
cat dos7.interrupts.log
```

Look for:
- Sequence of BIOS calls (INT 13h disk reads, INT 10h video, etc.)
- Unexpected interrupt patterns
- IVT modifications (hooking interrupts)
- Error conditions in interrupt handlers

### Step 3: Correlate with Instruction Log

Use the `intseq=N` marker to find instructions around a specific interrupt:

```bash
# Find instructions around interrupt sequence 42
grep -B10 -A10 "intseq=42" dos7.instructions.log

# Find all INT 13h disk reads
grep "INT 0x13" dos7.interrupts.log

# Find the instruction that triggered a specific interrupt
grep -B20 "intseq=42" dos7.instructions.log | head -25
```

### Step 4: Deep Dive

For detailed analysis:
```bash
# Find all memory writes to a specific address
grep "mem\[0x7c00\]" dos7.instructions.log

# Find all unconditional jumps/calls
grep -E "jmp|call|ret" dos7.instructions.log

# Find specific register values
grep "ax=0x1234" dos7.instructions.log
```

## Log File Format Reference

### Instruction Log Format

```
SSSS:OOOO=LINEAR|BYTES|MNEMONIC OPERANDS|CONTEXT...
```

| Field | Description |
|-------|-------------|
| `SSSS:OOOO` | Segment:Offset address |
| `LINEAR` | Linear address (segment * 16 + offset) |
| `BYTES` | Raw instruction bytes in hex |
| `MNEMONIC OPERANDS` | Disassembled instruction |
| `CONTEXT` | Register values, memory accesses |

### Interrupt Log Format

```
[intseq=N] Handling BIOS INT 0xXX -> Service Name
[REGS] INT 0xXX BEFORE: ax=... bx=... ...
[INT 0xXX] Specific operation details
[REGS] INT 0xXX AFTER: ax=... bx=... ...
```

### IVT/BDA Access Format

```
[IVT READ] ADDR | size=N | int=XX | value=0xVVVV | ip=0xAAAA | intseq=N | name = Service
[IVT WRITE] ADDR | size=N | int=XX | value=0xVVVV | ip=0xAAAA | intseq=N | name = Service
[BDA READ] ADDR | size=N | name=FIELD | value=0xVVVV | ip=0xAAAA | intseq=N
```

## Common Debugging Scenarios

### Finding Why a Disk Read Failed

```bash
# Find all INT 13h calls
grep "\[INT 0x13\]" dos7.interrupts.log

# Look for error conditions
grep -i "error\|fail\|beyond" dos7.interrupts.log
```

### Tracing IVT Hook Installation

```bash
# Find all IVT writes
grep "IVT WRITE" dos7.interrupts.log

# See what interrupt was hooked
grep "IVT WRITE.*int=10" dos7.interrupts.log
```

### Finding Infinite Loops

```bash
# Look for repeated instruction addresses
cut -d'|' -f1 dos7.instructions.log | sort | uniq -c | sort -rn | head -20
```

### Checking Boot Signature

```bash
# First instruction should be at 0x7C00
head -5 dos7.instructions.log
```

## Tips for AI Agents

1. **Start with stdout** - Don't jump straight to instruction logs
2. **Use `intseq` for correlation** - It's the key linking interrupts to instructions
3. **grep with context** - `-B` and `-A` flags are essential for log navigation
4. **Large logs** - Use `head`, `tail`, `grep` rather than reading entire files
5. **Track segment registers** - Real mode addressing is segment:offset
6. **Watch for IVT hooks** - DOS and bootloaders often hook interrupts
