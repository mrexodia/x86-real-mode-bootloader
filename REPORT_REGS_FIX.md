# Report: X86Regs Missing Register Fix for NTFS Bootmgr Protected Mode Transition

**Date:** 2026-04-18  
**File Modified:** `bootemu/regs.py` (backup at `bootemu/regs.py.bak`)  
**Test Image:** `MSSYS16NTFS_MBR_BOOT.img`

---

## Problem

After the INT 10h video services were fixed (see `REPORT_INT10_ENHANCEMENTS.md`), the NTFS
bootmgr progressed from 18,204 to 77,129 instructions but then crashed with:

```
[!] Error in hook_code: 'X86Regs' object has no attribute 'fs'
Traceback (most recent call last):
  File "/home/deomsh/x86-real-mode-bootloader/bootemu/emulator.py", line 681, in hook_code
    reg_value = getattr(self.regs, reg)
                ^^^^^^^^^^^^^^^^^^^
AttributeError: 'X86Regs' object has no attribute 'fs'
```

The instruction log showed the last traced line was 81,753, ending at:

```
2000:0212= 20212|6a30      |push 0x30|sp=0x14fc
```

The next instruction (`0fa1` = `pop fs`) was never traced because `X86Regs` had no `fs`
attribute. The same class was also missing `gs` and all control registers (`cr0`–`cr4`),
which the bootmgr uses moments later during the protected mode switch.

---

## Root Cause

The `X86Regs` class in `bootemu/regs.py` only defined these segment registers:

```python
# Segment
cs: int = reg(UC_X86_REG_CS)
ds: int = reg(UC_X86_REG_DS)
es: int = reg(UC_X86_REG_ES)
ss: int = reg(UC_X86_REG_SS)
```

The FS and GS segment registers and CR0–CR4 control registers were absent. The emulator's
`hook_code` method calls `getattr(self.regs, reg_name)` for every register referenced by
each instruction. When Capstone disassembles `pop fs` or `mov eax, cr0`, it returns the
register name `"fs"` or `"cr0"`, and the `getattr` call fails.

The bootmgr's protected mode transition code uses these registers:

```asm
2000:020E  mov gs, ax        ; Clear GS
2000:0214  pop fs             ; Load FS from stack (value 0x30)  ← crash here
2000:0231  mov eax, cr0       ; Read CR0
2000:024B  mov cr0, eax       ; Set PE bit, enter protected mode
```

---

## Fix Applied

### Added Segment Registers

```python
fs: int = reg(UC_X86_REG_FS)
gs: int = reg(UC_X86_REG_GS)
```

### Added Control Registers

```python
# Control registers
cr0: int = reg(UC_X86_REG_CR0)
cr1: int = reg(UC_X86_REG_CR1)
cr2: int = reg(UC_X86_REG_CR2)
cr3: int = reg(UC_X86_REG_CR3)
cr4: int = reg(UC_X86_REG_CR4)
```

### Added Imports

```python
from unicorn.x86_const import (
    ...
    UC_X86_REG_FS,
    UC_X86_REG_GS,
    ...
    UC_X86_REG_CR0,
    UC_X86_REG_CR1,
    UC_X86_REG_CR2,
    UC_X86_REG_CR3,
    UC_X86_REG_CR4,
)
```

---

## Full Diff

```diff
--- bootemu/regs.py.bak
+++ bootemu/regs.py
@@ -21,6 +21,8 @@
     UC_X86_REG_CS,
     UC_X86_REG_DS,
     UC_X86_REG_ES,
+    UC_X86_REG_FS,
+    UC_X86_REG_GS,
     UC_X86_REG_SS,
     UC_X86_REG_IP,
     UC_X86_REG_EFLAGS,
@@ -33,6 +35,11 @@
     UC_X86_REG_EBP,
     UC_X86_REG_ESP,
     UC_X86_REG_EIP,
+    UC_X86_REG_CR0,
+    UC_X86_REG_CR1,
+    UC_X86_REG_CR2,
+    UC_X86_REG_CR3,
+    UC_X86_REG_CR4,
 )
 
@@ -118,8 +125,17 @@
     cs: int = reg(UC_X86_REG_CS)
     ds: int = reg(UC_X86_REG_DS)
     es: int = reg(UC_X86_REG_ES)
+    fs: int = reg(UC_X86_REG_FS)
+    gs: int = reg(UC_X86_REG_GS)
     ss: int = reg(UC_X86_REG_SS)
 
+    # Control registers
+    cr0: int = reg(UC_X86_REG_CR0)
+    cr1: int = reg(UC_X86_REG_CR1)
+    cr2: int = reg(UC_X86_REG_CR2)
+    cr3: int = reg(UC_X86_REG_CR3)
+    cr4: int = reg(UC_X86_REG_CR4)
+
     # Flags
     flags: int = reg(UC_X86_REG_EFLAGS)
```

---

## Test Results

### Before Fix

| Metric | Value |
|--------|-------|
| Instructions executed | 77,129 |
| Log lines (instructions) | 81,753 |
| Last traced instruction | `2000:0212 push 0x30` |
| Error | `AttributeError: 'X86Regs' object has no attribute 'fs'` |
| Fatal? | Yes — unhandled exception killed emulation |

### After Fix

| Metric | Value |
|--------|-------|
| Instructions executed | **77,139** (+10) |
| Log lines (instructions) | **81,764** (+11) |
| Last traced instruction | `0058:0259 mov ax, 0x60` (in protected mode) |
| Termination | `Physical address mismatch` — clean stop (expected) |
| Fatal? | No — emulator detects protected mode boundary and stops gracefully |

### Newly Traced Instructions

These 10 instructions were previously invisible due to the crash:

```asm
2000:0214  pop fs              ; FS = 0x30 (was crashing here)
2000:0216  cli                  ; Disable interrupts
2000:0217  lgdt [0x15a8]       ; Load Global Descriptor Table
2000:021C  lidt [0x15b0]       ; Load Interrupt Descriptor Table
2000:0221  mov si, 0x1d6c      ; GDT entry setup (VGA buffer 0xb800)
2000:0224  mov word ptr [si+2], 0x68
2000:0229  mov si, 0x1d68      ; Another GDT entry
2000:022C  mov word ptr [si+2], 0x68
2000:0231  mov eax, cr0        ; Read CR0 (value 0x0000)
2000:0247  or eax, 1           ; Set PE bit
2000:024B  mov cr0, eax        ; Write CR0 → protected mode ON
2000:024E  xchg bx, bx         ; NOP (debug trap)
2000:0253  push 0x58           ; Push GDT code selector
2000:0255  push 0x259          ; Push offset
2000:0258  retf                 ; Far jump → CS:IP = 0x58:0x0259
0058:0259  mov ax, 0x60        ; First protected-mode instruction
```

---

## Why It Stops at `Physical address mismatch`

The emulator's `hook_code` computes the expected physical address using real-mode
segmentation: `physical = (CS << 4) + IP`. After the bootmgr sets `CR0.PE = 1` and
does `retf` with GDT selector `0x58`, the CPU is in protected mode. The linear address
through the GDT is `0x20000 + 0x259 = 0x20259`, but real-mode math gives `0x58*16 + 0x259 = 0x7D9`.

The mismatch `0x20259 != 0x7D9` is correctly detected and the emulator stops gracefully.
This is the natural endpoint — the NTFS bootmgr has entered 32-bit protected mode, which
is beyond the scope of a 16-bit real mode emulator.
