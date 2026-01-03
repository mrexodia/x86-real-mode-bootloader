# Emulator Refactor Plan

## Overview

This document outlines the plan for refactoring `emulator.py` from a single 2300+ line file into a modular, maintainable architecture while ensuring behavioral consistency through golden master testing.

## Current State

### Issues with Current Architecture
- **Single file**: 2300+ lines of code in `emulator.py`
- **Mixed responsibilities**: CPU emulation, BIOS services, disk I/O, tracing, CLI all in one file
- **Hard to test**: No clear separation of concerns
- **Hard to maintain**: Changes risk breaking unrelated functionality
- **Hard to extend**: Adding new BIOS services requires modifying the monolithic file

### Current Responsibilities in `emulator.py`
1. **CPU Emulation**: Unicorn/Capstone integration, register management
2. **BIOS Services**: INT 10h, 13h, 14h, 15h, 16h, 17h, 1Ah handlers
3. **Disk Emulation**: Geometry detection, sector read/write, caching
4. **Memory Management**: BDA, IVT setup, memory mapping
5. **Tracing**: Instruction logging, memory access logging
6. **CLI**: Argument parsing and main execution flow

### Existing Test Infrastructure
- Multiple `.img` files (boot sectors for testing):
  - `BOOT_CODE_MSDOS70_FAT12_BAD.img`
  - `BOOT_CODE_OEMBOOT70_FAT12_GOOD.img`
  - `HDD_60MB_FAT16_MDOS40_BOOTCODE_MSDOS622_SYSTEM.img`
  - `HDD_MSDOS33_FAT12_BC_331.img`
  - `MSDOS33_FAT12.img`
  - `boot.img`
  - `dostest.img`
- Old trace files exist but aren't used as golden masters

## Refactor Strategy

### Golden Master First Approach

**Principle**: Before any refactoring, establish comprehensive golden master tests to ensure behavioral consistency.

#### Why Golden Master Testing?
1. **Safety Net**: Detect any behavioral changes immediately
2. **Confidence**: Refactor knowing behavior won't change
3. **Validation**: Verify each refactoring step is successful
4. **Documentation**: Traces serve as executable documentation

#### Golden Master Implementation

**Step 1: Create Baseline Traces**
```bash
# Run all test disk images with maximum verbosity
python emulator.py BOOT_CODE_MSDOS70_FAT12_BAD.img --verbose > baseline_BOOT_CODE_MSDOS70_FAT12_BAD.txt
python emulator.py BOOT_CODE_OEMBOOT70_FAT12_GOOD.img --verbose > baseline_BOOT_CODE_OEMBOOT70_FAT12_GOOD.txt
# ... etc for all test images
```

**Step 2: Create Test Framework**
```
tests/golden_master/
├── test_runner.py          # Creates baseline traces
├── compare_traces.py       # Compares traces for differences  
├── regression_test.py      # Runs all regression tests
└── fixtures/
    ├── baseline_BOOT_CODE_MSDOS70_FAT12_BAD.txt
    ├── baseline_BOOT_CODE_OEMBOOT70_FAT12_GOOD.txt
    └── ... # all baseline traces
```

**Step 3: Validate Before Refactoring**
- Run regression tests against current code
- Ensure all tests pass (traces match themselves)
- Establish working baseline

### Modular Architecture

#### Target Structure
```
emulator/
├── __init__.py
├── main.py                 # CLI entry point
├── config.py               # Configuration and constants
├── core/                   # Core emulation
│   ├── __init__.py
│   ├── cpu.py             # CPU emulation and register management
│   ├── memory.py          # Memory management and mapping  
│   └── emulator.py        # Main emulator orchestration
├── bios/                  # BIOS interrupt handlers
│   ├── __init__.py
│   ├── base.py            # Base interrupt handler class
│   ├── int10.py           # Video services
│   ├── int13.py           # Disk services
│   ├── int14.py           # Serial services
│   ├── int15.py           # System services
│   ├── int16.py           # Keyboard services
│   ├── int17.py           # Printer services
│   └── int1a.py           # Timer/RTC services
├── hardware/              # Hardware emulation
│   ├── __init__.py
│   ├── disk.py            # Disk geometry, read/write operations
│   ├── bda.py             # BIOS Data Area management
│   └── ivt.py             # Interrupt Vector Table management
├── tracing/               # Tracing and golden master testing
│   ├── __init__.py
│   ├── tracer.py          # Instruction tracing logic
│   └── goldmaster.py      # Golden master comparison
├── utils/                 # Utilities
│   ├── __init__.py
│   ├── structs.py         # ctypes structures and field markers
│   └── helpers.py         # Helper functions
└── tests/                 # Tests
    ├── __init__.py
    ├── test_goldmaster.py # Golden master regression tests
    └── fixtures/          # Test disk images and traces
```

## Implementation Plan

### Phase 0: Establish Golden Master Foundation ✅ COMPLETE

**Goal**: Create baseline traces and test framework before any refactoring.

**Steps**:
1. ✅ Create `tests/golden_master/test_runner.py` - Generates baseline traces
2. ✅ Create `tests/golden_master/compare_traces.py` - Compares traces  
3. ✅ Create `tests/golden_master/regression_test.py` - Runs all regression tests
4. ✅ Run test runner to generate baseline traces
5. ✅ Verify all disk images work and produce traces
6. ✅ Commit baseline traces to version control

**Validation**: All regression tests pass.

### Phase 1: Safe Structural Changes ✅ COMPLETE

**Goal**: Reorganize code without changing any logic or behavior.

**Files Created**:
- `emulator/main.py` - CLI entry point
- `emulator/utils/__init__.py` - Package structure
- `emulator/utils/structs.py` - Structure definitions
- `emulator/utils/constants.py` - IVT_NAMES, register maps

**Validation**: Regression tests pass with identical traces.

### Phase 2: Extract Pure Data Components ✅ COMPLETE

**Goal**: Extract components that are data-only definitions.

**Files Created**:
- `emulator/types/__init__.py`
- `emulator/types/c_types.py` - c_struct metaclass, c_array
- `emulator/hardware/structures/__init__.py` - DiskParameterTable, FixedDiskParameterTable

**Validation**: Regression tests pass - structures are identical.

### Phase 3: Extract I/O and Tracing ✅ COMPLETE

**Goal**: Separate input/output and tracing functionality.

**Files Created**:
- `emulator/tracing/tracer.py` - Instruction tracing logic
- `emulator/tracing/formatters.py` - Trace formatting
- `emulator/tracing/output.py` - Output handling
- `emulator/tracing/hooks.py` - Hook management
- `emulator/tracing/legacy_tracer.py` - Legacy tracer compatibility

**Validation**: Regression tests pass - traces are bit-identical.

### Phase 4: Extract Hardware Emulation ✅ COMPLETE

**Goal**: Separate disk and memory hardware emulation.

**Files Created**:
- `emulator/hardware/disk/disk_image.py` - Disk image handling, sector read/write
- `emulator/hardware/geometry/` - Geometry detection and calculation
- `emulator/hardware/memory/memory_layout.py` - Memory management
- `emulator/hardware/bda/` - BDA structure and field policies
- `emulator/hardware/ivt/ivt_manager.py` - IVT management
- `emulator/hardware/bios_tables.py` - BIOS table setup
- `emulator/hardware/simulation/` - Hardware simulation

**Validation**: Regression tests pass - hardware behavior identical.

### Phase 5: Extract BIOS Handlers ✅ COMPLETE

**Goal**: Separate each BIOS interrupt into its own class.

**Strategy**: Extract one handler at a time, test after each.

**Files Created**:
- `emulator/bios/base.py` - BIOSHandler abstract base class
- `emulator/bios/int10.py` - Video services (INT 0x10)
- `emulator/bios/int11.py` - Equipment list (INT 0x11)
- `emulator/bios/int12.py` - Memory size (INT 0x12)
- `emulator/bios/int13.py` - Disk services (INT 0x13)
- `emulator/bios/int14.py` - Serial port services (INT 0x14)
- `emulator/bios/int15.py` - System services (INT 0x15)
- `emulator/bios/int16.py` - Keyboard services (INT 0x16)
- `emulator/bios/int17.py` - Printer services (INT 0x17)
- `emulator/bios/int1a.py` - Timer/Clock services (INT 0x1A)

`services.py` reduced from 929 lines to ~130 lines using handler registry.

**Validation**: All regression tests pass after handler extraction.

### Phase 6: Extract Core CPU ⏳ IN PROGRESS

**Goal**: Separate CPU emulation and Unicorn integration.

**Status**: Partially complete. `emulator/core/emulator.py` exists but could be further
modularized by extracting:
- CPU state management
- Hook setup and management
- Memory access helpers

### Phase 7: Final Cleanup and Documentation

**Goal**: Polish the final architecture.

**Tasks**:
1. Update all docstrings and comments
2. Create README.md for the emulator package
3. Add example usage
4. Ensure all imports are clean
5. Run final regression test suite

**Validation**: Full regression test suite passes.

## Risk Assessment

### Risk Levels by Phase

| Phase | Risk Level | Status | Rationale |
|-------|------------|--------|-----------|
| 0 (Golden Master) | ⭐ Critical | ✅ Complete | Foundation for all safety |
| 1 (Structural) | ✅ Zero Risk | ✅ Complete | Only moving code |
| 2 (Data) | ✅ Low Risk | ✅ Complete | Pure data definitions |
| 3 (I/O/Tracing) | ⚠️ Low-Medium | ✅ Complete | Trace format preserved |
| 4 (Hardware) | ⚠️ Medium | ✅ Complete | Hardware behavior identical |
| 5 (BIOS) | ⚠️ Medium | ✅ Complete | Handler registry pattern |
| 6 (CPU) | ⚠️ Medium-High | ⏳ Optional | Core logic in emulator.py |
| 7 (Cleanup) | ✅ Low Risk | ⏳ Next | Documentation and polish |

### Risk Mitigation Strategies

1. **Golden Master Tests**: After every change, run full regression suite
2. **Incremental Changes**: Extract one component at a time
3. **Immediate Testing**: Test after each extraction, don't batch changes
4. **Version Control**: Commit after each successful phase
5. **Rollback Ready**: If any test fails, immediately rollback and investigate

## Success Criteria

### Functional Criteria
- ✅ All existing disk images boot identically
- ✅ All BIOS services behave identically  
- ✅ All traces are bit-identical to baselines
- ✅ No functional regressions

### Architectural Criteria
- ✅ Single responsibility per module
- ✅ Clear separation of concerns
- ✅ Easy to test individual components
- ✅ Easy to extend with new BIOS services
- ✅ Maintainable and readable code

### Testing Criteria
- ✅ Golden master regression tests pass
- ✅ Individual component tests exist
- ✅ Integration tests work
- ✅ Performance is not degraded

## Next Steps

1. ✅ **Phase 0-5 Complete**: Core refactoring done with all tests passing
2. ⏳ **Phase 6 (Optional)**: Further split `emulator/core/emulator.py` if needed
3. ⏳ **Phase 7**: Add package README.md and polish documentation
4. 🎯 **Merge Ready**: Refactor is feature-complete and safe to merge

## Questions for Review

1. **Golden Master Approach**: Do you agree this is the right safety approach?
2. **Module Structure**: Does the proposed directory structure make sense?
3. **Risk Assessment**: Are you comfortable with the risk levels and mitigations?
4. **Implementation Order**: Should we change the order of any phases?
5. **Testing Strategy**: Is the regression testing approach sufficient?

Please review and provide feedback before we begin implementation.