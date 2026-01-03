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

### Phase 0: Establish Golden Master Foundation ⭐ **MUST DO FIRST**

**Goal**: Create baseline traces and test framework before any refactoring.

**Steps**:
1. ✅ Create `tests/golden_master/test_runner.py` - Generates baseline traces
2. ✅ Create `tests/golden_master/compare_traces.py` - Compares traces  
3. ✅ Create `tests/golden_master/regression_test.py` - Runs all regression tests
4. **TODO**: Run test runner to generate baseline traces
5. **TODO**: Verify all disk images work and produce traces
6. **TODO**: Commit baseline traces to version control

**Validation**: All regression tests must pass before proceeding.

### Phase 1: Safe Structural Changes (Zero Risk)

**Goal**: Reorganize code without changing any logic or behavior.

**Files to Create**:
```python
# emulator/main.py - Move main() function here
# emulator/config.py - Extract constants and configuration  
# emulator/utils/__init__.py - Package structure
# emulator/utils/structs.py - Move structure definitions
# emulator/utils/constants.py - Extract IVT_NAMES, register maps
```

**Changes**:
- Move code to new files
- Update imports
- No logic changes
- Purely structural

**Validation**: Run regression tests - must pass with identical traces.

### Phase 2: Extract Pure Data Components (Low Risk)

**Goal**: Extract components that are data-only definitions.

**Files to Create**:
```python
# emulator/types/__init__.py
# emulator/types/c_types.py - Extract c_struct metaclass, c_array
# emulator/hardware/structures.py - Move DiskParameterTable, FixedDiskParameterTable
```

**Validation**: Regression tests must pass - structures are identical.

### Phase 3: Extract I/O and Tracing (Low Risk)

**Goal**: Separate input/output and tracing functionality.

**Files to Create**:
```python
# emulator/tracing/tracer.py - Extract hook_code() tracing logic
# emulator/tracing/formatter.py - Extract trace formatting  
# emulator/io/console.py - Extract console output handling
# emulator/io/files.py - Extract trace file handling
```

**Critical Requirement**: Maintain identical trace format!

**Validation**: Regression tests must pass - traces must be bit-identical.

### Phase 4: Extract Hardware Emulation (Medium Risk)

**Goal**: Separate disk and memory hardware emulation.

**Files to Create**:
```python
# emulator/hardware/disk.py - Extract disk operations
#   - Geometry detection
#   - Sector read/write 
#   - LBA/CHS conversion
#   - Disk caching

# emulator/hardware/memory.py - Extract memory management
#   - Memory mapping
#   - Segment:offset calculations
#   - Memory region management

# emulator/hardware/bda.py - Extract BDA management
#   - BIOS Data Area structure
#   - Field policy management
#   - Hardware synchronization

# emulator/hardware/ivt.py - Extract IVT management
#   - Interrupt Vector Table
#   - BIOS stub creation
#   - IVT entry manipulation
```

**Validation**: Regression tests must pass - hardware behavior identical.

### Phase 5: Extract BIOS Handlers (Medium Risk)

**Goal**: Separate each BIOS interrupt into its own class.

**Strategy**: Extract one handler at a time, test after each.

**Files to Create**:
```python
# emulator/bios/base.py - BIOSHandler base class
class BIOSHandler(ABC):
    def __init__(self, emulator):
        self.emulator = emulator
    
    @abstractmethod
    def handle_interrupt(self, uc: Uc, intno: int):
        pass

# emulator/bios/int10.py - Video services
class INT10Handler(BIOSHandler):
    def handle_interrupt(self, uc: Uc, intno: int):
        # Extracted INT 0x10 logic

# emulator/bios/int13.py - Disk services (largest one)
class INT13Handler(BIOSHandler):
    def handle_interrupt(self, uc: Uc, intno: int):
        # Extracted INT 0x13 logic

# ... similarly for int14.py, int15.py, int16.py, int17.py, int1a.py
```

**Validation**: After each handler extraction, run regression tests.

### Phase 6: Extract Core CPU (Medium Risk)

**Goal**: Separate CPU emulation and Unicorn integration.

**Files to Create**:
```python
# emulator/core/cpu.py - CPU state and Unicorn integration
#   - Register management  
#   - Unicorn engine setup
#   - Hook management
#   - Memory operations

# emulator/core/hooks.py - Hook management
#   - Code execution hook
#   - Interrupt hook  
#   - Memory access hooks
#   - IVT/BDA access hooks

# emulator/core/emulator.py - Main orchestration (much smaller now)
#   - BootloaderEmulator class (coordinator)
#   - Lifecycle management
#   - Integration of all components
```

**Validation**: Regression tests must pass - CPU behavior identical.

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

| Phase | Risk Level | Rationale | Mitigation |
|-------|------------|-----------|------------|
| 0 (Golden Master) | ⭐ Critical | Foundation for all safety | Must complete first |
| 1 (Structural) | ✅ Zero Risk | Only moving code | Golden master tests |
| 2 (Data) | ✅ Low Risk | Pure data definitions | Golden master tests |
| 3 (I/O/Tracing) | ⚠️ Low-Medium | Trace format critical | Preserve format exactly |
| 4 (Hardware) | ⚠️ Medium | Complex logic extraction | Test after each component |
| 5 (BIOS) | ⚠️ Medium | Complex state management | Test after each handler |
| 6 (CPU) | ⚠️ Medium-High | Core emulation logic | Comprehensive testing |
| 7 (Cleanup) | ✅ Low Risk | Documentation only | Final regression test |

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

1. **Review This Plan**: Ensure you agree with the approach
2. **Complete Phase 0**: Run golden master test runner to create baseline traces
3. **Verify Phase 0**: Ensure all disk images work and traces are generated
4. **Begin Phase 1**: Start with safe structural changes
5. **Iterate**: Complete each phase, testing thoroughly before moving to next

## Questions for Review

1. **Golden Master Approach**: Do you agree this is the right safety approach?
2. **Module Structure**: Does the proposed directory structure make sense?
3. **Risk Assessment**: Are you comfortable with the risk levels and mitigations?
4. **Implementation Order**: Should we change the order of any phases?
5. **Testing Strategy**: Is the regression testing approach sufficient?

Please review and provide feedback before we begin implementation.