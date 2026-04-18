# Report: INT 10h Video Services & Register Enhancements for NTFS Bootmgr Support

**Date:** 2026-04-18  
**Files Modified:** `bootemu/bios.py`, `bootemu/regs.py` (backups at `.bak`)  
**Test Image:** `MSSYS16NTFS_MBR_BOOT.img`

---

## Problem

The NTFS bootmgr loaded from `MSSYS16NTFS_MBR_BOOT.img` would halt at 18,204 instructions
for two reasons:

1. The emulator's `handle_int10()` only supported a limited set of INT 10h functions
   (AH=00h, 02h, 03h, 0Eh, 0Fh, 1Ah, 1Bh). Any unhandled AH value caused `emu.stop()`.
2. The `X86Regs` class was missing `fs`, `gs` segment registers and `cr0`–`cr4` control
   registers, causing `AttributeError` when the bootmgr accessed them during protected
   mode setup.

---

## Changes Applied

### New INT 10h Function Handlers Added

| AH  | Function                          | Implementation                                                        |
|-----|-----------------------------------|-----------------------------------------------------------------------|
| 01h | Set Cursor Shape                  | Stores CH/CL scan line values in BDA `cursor_shape` field            |
| 05h | Select Active Display Page        | Updates BDA `active_page` field                                      |
| 06h | Scroll Window Up                  | Logged only (no-op for emulator)                                     |
| 07h | Scroll Window Down                | Logged only (no-op for emulator)                                     |
| 08h | Read Character at Cursor          | Returns AX=0x0720 (space, white-on-black attribute)                  |
| 09h | Write Character + Attribute       | Appends printable chars to screen_output, updates BDA cursor position |
| 0Ah | Write Character Only              | Same as AH=09h but preserves existing attribute                      |
| 11h | Character Generator (EGA/VGA)     | Stub: clears CF (success), no-op                                     |
| 12h | VGA Alternate Select              | Full BL sub-function dispatch (BL=10h..35h + unknown fallback)       |
| 13h | Write String (Teletype)           | Reads string from ES:BP, appends to screen_output, updates cursor    |
| 20h | EGA/VGA Extension                 | Stub: clears CF (success)                                            |
| 21h | EGA/VGA Extension                 | Stub: clears CF (success)                                            |
| 22h | EGA/VGA Extension                 | Stub: clears CF (success)                                            |

### INT 10h AH=12h Sub-function Detail

| BL   | Sub-function                      | Return Values                           |
|------|-----------------------------------|-----------------------------------------|
| 10h  | Return EGA/VGA Information        | BH=0 (color), BL=3 (256K), CX=0        |
| 20h  | Alternate Print Screen            | No register changes                     |
| 30h  | Select Vertical Resolution        | AL=0x12 (supported)                     |
| 31h  | Palette Loading on Mode Set       | AL=0x12 (supported)                     |
| 32h  | Video Addressing                  | AL=0x12 (supported)                     |
| 33h  | Gray-scale Summing                | AL=0x12 (supported)                     |
| 34h  | Cursor Emulation                  | AL=0x12 (supported)                     |
| 35h  | Display Switch                    | AL=0x12 (supported)                     |
| else | Unknown                           | AL=0x12 (supported), CF cleared         |

---

## Change 2: Register Support (`bootemu/regs.py`)

### Added Segment Registers

| Register | Unicorn Constant | Purpose |
|----------|-------------------|---------|
| `fs` | `UC_X86_REG_FS` | Extra segment register (used by bootmgr for BDA access) |
| `gs` | `UC_X86_REG_GS` | Extra segment register |

### Added Control Registers

| Register | Unicorn Constant | Purpose |
|----------|-------------------|---------|
| `cr0` | `UC_X86_REG_CR0` | Control register 0 (PE bit for protected mode) |
| `cr1` | `UC_X86_REG_CR1` | Control register 1 (reserved) |
| `cr2` | `UC_X86_REG_CR2` | Page fault linear address |
| `cr3` | `UC_X86_REG_CR3` | Page directory base |
| `cr4` | `UC_X86_REG_CR4` | Control register 4 (PAE, etc.) |

These are needed because the NTFS bootmgr executes:
- `mov gs, ax` / `pop fs` — sets up segment selectors
- `mov eax, cr0` / `mov cr0, eax` — enables protected mode

Without these register descriptors, the emulator's `hook_code` tracing would crash
with `AttributeError: 'X86Regs' object has no attribute 'fs'` (or 'cr0').

---

## Test Results

### Before Changes

| Metric | Value |
|--------|-------|
| Instructions executed | 18,204 |
| Log lines (instructions) | 22,796 |
| Log lines (interrupts) | 3,568 |
| Total interrupts | 511 (510 × INT 13h, 1 × INT 10h) |
| Last event | `intseq=510` — INT 10h AH=12h Unhandled → `emu.stop()` |
| Final CS:IP | `f000:0042` (stuck in BIOS handler) |

### After All Changes

| Metric | Value |
|--------|-------|
| Instructions executed | **77,139** (+324%) |
| Log lines (instructions) | **81,764** |
| Log lines (interrupts) | 3,585 |
| Total interrupts | 514 (510 × INT 13h, 4 × INT 10h) |
| Last event | Protected mode transition — `retf` to GDT selector 0x58 |
| Final CS:IP | `0058:0259` (in 32-bit protected mode code) |
| Termination | `Physical address mismatch` — expected (real-mode emulator boundary) |

### INT 10h Call Sequence (Successful)

| intseq | AH   | Description | Result |
|--------|------|-------------|--------|
| 510    | 12h  | VGA Alternate Select BL=01h | ✅ Success |
| 511    | 00h  | Set video mode 03h (80×25 text) | ✅ Success |
| 512    | 20h  | EGA/VGA extension | ✅ Success (stub) |
| 513    | 0Ah  | Write char ' ' count=1 | ✅ Success |

---

## Why Booting Still Stops

After successfully passing all INT 10h video initialization, the NTFS bootmgr proceeds to
**switch from real mode to protected mode**:

```
2000:0217  lgdt [0x15a8]        ; Load Global Descriptor Table
2000:021C  lidt [0x15b0]        ; Load Interrupt Descriptor Table
2000:0221  mov si, 0x1d6c       ; Set up GDT entries for VGA buffer at 0xb800
2000:0229  mov si, 0x1d68       ; More GDT setup
2000:0231  mov eax, cr0         ; Read CR0
2000:0247  or eax, 1            ; Set PE (Protection Enable) bit
2000:024B  mov cr0, eax         ; Enter protected mode!
2000:0253  push 0x58 / push 0x259
2000:0258  retf                  ; Far jump to protected-mode code segment
```

The emulator's `hook_code` then detects `Physical address mismatch: 0x20259 != 0x7d9 (0058:0259)`
because it uses real-mode segmentation `(CS << 4) + IP` but CS=0x58 is now a GDT selector
mapping to linear address 0x20000.

This is **expected behavior** — the Windows NTFS bootmgr must transition to protected mode to
load `winload.exe`, which is beyond the scope of a 16-bit real mode emulator.

---

## Files Changed

- `bootemu/bios.py` — Added 12 new INT 10h function handlers (~250 lines of new code)
- `bootemu/regs.py` — Added FS, GS segment registers and CR0–CR4 control registers
- `bootemu/bios.py.bak` — Backup of original `bios.py`
- `bootemu/regs.py.bak` — Backup of original `regs.py`
