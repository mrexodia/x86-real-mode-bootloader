# x86 Real Mode Bootloader Emulator

A modular Python-based emulator for x86 real mode bootloaders using [Unicorn Engine](https://www.unicorn-engine.org/) and [Capstone](https://www.capstone-engine.org/).

## Architecture

The emulator is organized into the following modules:

```
emulator/
├── __init__.py          # Package exports
├── main.py              # CLI entry point
├── bios/                # BIOS interrupt handlers
│   ├── base.py          # BIOSHandler abstract base class
│   ├── int10.py         # INT 0x10 - Video Services
│   ├── int11.py         # INT 0x11 - Equipment List
│   ├── int12.py         # INT 0x12 - Memory Size
│   ├── int13.py         # INT 0x13 - Disk Services
│   ├── int14.py         # INT 0x14 - Serial Port Services
│   ├── int15.py         # INT 0x15 - System Services
│   ├── int16.py         # INT 0x16 - Keyboard Services
│   ├── int17.py         # INT 0x17 - Printer Services
│   ├── int1a.py         # INT 0x1A - Timer/Clock Services
│   └── services.py      # BIOS services router
├── core/                # Core emulation
│   └── emulator.py      # BootloaderEmulator class
├── hardware/            # Hardware emulation
│   ├── bda/             # BIOS Data Area
│   ├── disk/            # Disk image handling
│   ├── geometry/        # Disk geometry detection
│   ├── ivt/             # Interrupt Vector Table
│   ├── memory/          # Memory layout
│   ├── simulation/      # Hardware simulation
│   └── structures/      # Hardware data structures
├── tracing/             # Instruction tracing
│   ├── formatters.py    # Trace output formatting
│   ├── hooks.py         # Unicorn hooks
│   ├── legacy_tracer.py # Legacy compatibility
│   ├── output.py        # Output handling
│   └── tracer.py        # Main tracer
├── types/               # Type definitions
│   └── c_types.py       # ctypes helpers
└── utils/               # Utilities
    ├── constants.py     # Constants and mappings
    └── structs.py       # Structure definitions
```

## Usage

### Basic Usage

```bash
# Run with a disk image
python emulator.py boot.img

# With options
python emulator.py boot.img --max-instructions 50000 --output trace.txt
```

### Command Line Options

```
positional arguments:
  disk_image            Path to disk image file

options:
  -h, --help            show this help message and exit
  -m, --max-instructions MAX
                        Maximum instructions to execute (default: 1000000)
  -o, --output FILE     Output trace file (default: trace.txt)
  -q, --quiet           Reduce verbosity
  -g, --geometry C,H,S  Manual CHS geometry
  -f, --floppy-type TYPE
                        Floppy type: 360K, 720K, 1.2M, 1.44M, 2.88M
  -d, --drive-number N  BIOS drive number (default: 0x80)
```

### Programmatic Usage

```python
from emulator.core import BootloaderEmulator

emu = BootloaderEmulator(
    disk_image_path="boot.img",
    max_instructions=50000,
    verbose=True
)
emu.setup_cpu_state()
emu.run()
```

## Extending BIOS Services

To add a new BIOS interrupt handler:

1. Create a new file `emulator/bios/intXX.py`
2. Inherit from `BIOSHandler`:

```python
from .base import BIOSHandler

class IntXXHandler(BIOSHandler):
    def handle(self, uc):
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        # Handle subfunction based on AH
        if ah == 0x00:
            self._function_00(uc)
        # ...
```

3. Register in `emulator/bios/services.py`
4. Export in `emulator/bios/__init__.py`

## Testing

Golden master regression tests ensure behavioral consistency:

```bash
# Run all regression tests
python tests/golden_master/regression_test.py

# Generate new baseline traces
python tests/golden_master/test_runner.py
```

## Supported BIOS Interrupts

| INT | Name | Functions |
|-----|------|-----------|
| 0x10 | Video | Set mode, cursor, teletype output |
| 0x11 | Equipment | Get equipment list |
| 0x12 | Memory | Get memory size |
| 0x13 | Disk | Read/write sectors, get geometry |
| 0x14 | Serial | Initialize, read/write |
| 0x15 | System | Extended memory, E820 memory map |
| 0x16 | Keyboard | Read keystroke, get shift flags |
| 0x17 | Printer | Print character (offline status) |
| 0x1A | Timer | Get/set time and date |

## License

See LICENSE file in the repository root.
