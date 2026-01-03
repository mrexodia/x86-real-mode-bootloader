#!/usr/bin/env python3
"""
Regression Test Script

This script runs regression tests against all golden master traces
to ensure refactoring doesn't change behavior.
"""

import sys
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Tuple

from compare_traces import read_trace_file, compare_traces

# Test disk images and their corresponding baseline traces
TEST_PAIRS = [
    {
        "disk": "BOOT_CODE_MSDOS70_FAT12_BAD.img",
        "baseline": "tests/golden_master/fixtures/baseline_BOOT_CODE_MSDOS70_FAT12_BAD.img.txt"
    },
    {
        "disk": "BOOT_CODE_OEMBOOT70_FAT12_GOOD.img", 
        "baseline": "tests/golden_master/fixtures/baseline_BOOT_CODE_OEMBOOT70_FAT12_GOOD.img.txt"
    },
    {
        "disk": "HDD_60MB_FAT16_MDOS40_BOOTCODE_MSDOS622_SYSTEM.img",
        "baseline": "tests/golden_master/fixtures/baseline_HDD_60MB_FAT16_MDOS40_BOOTCODE_MSDOS622_SYSTEM.img.txt"
    },
    {
        "disk": "HDD_MSDOS33_FAT12_BC_331.img",
        "baseline": "tests/golden_master/fixtures/baseline_HDD_MSDOS33_FAT12_BC_331.img.txt"
    },
    {
        "disk": "MSDOS33_FAT12.img",
        "baseline": "tests/golden_master/fixtures/baseline_MSDOS33_FAT12.img.txt"
    },
    {
        "disk": "boot.img",
        "baseline": "tests/golden_master/fixtures/baseline_boot.img.txt"
    },
    {
        "disk": "dostest.img", 
        "baseline": "tests/golden_master/fixtures/baseline_dostest.img.txt"
    },
]

def run_regression_test(test_pair: Dict) -> Tuple[bool, str]:
    """Run regression test for one disk image."""
    
    disk_path = test_pair["disk"]
    baseline_path = Path(test_pair["baseline"])
    
    # Check if baseline exists
    if not baseline_path.exists():
        return False, f"Baseline trace not found: {baseline_path}"
    
    # Check if disk image exists
    if not Path(disk_path).exists():
        return False, f"Disk image not found: {disk_path}"
    
    print(f"🔄 Testing: {disk_path}")
    
    # Create temporary file for current trace
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
        temp_trace_path = tmp.name
    
    try:
        # Run emulator to generate current trace
        cmd = [
            sys.executable, "emulator.py",
            disk_path,
            "--max-instructions", "1000000",
            "--output", temp_trace_path,
            "--quiet"  # Reduce console output
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            return False, f"Emulator failed: {result.stderr}"
        
        # Compare traces
        baseline_lines = read_trace_file(baseline_path)
        current_lines = read_trace_file(Path(temp_trace_path))
        
        match, differences = compare_traces(baseline_lines, current_lines)
        
        if match:
            return True, "✅ Pass"
        else:
            # Show first few differences
            diff_summary = differences[:20]  # First 20 lines of diff
            return False, f"❌ Traces differ:\n" + "\n".join(diff_summary)
            
    except subprocess.TimeoutExpired:
        return False, "⏰ Timeout running emulator"
    except Exception as e:
        return False, f"❌ Error: {e}"
    finally:
        # Clean up temporary file
        try:
            Path(temp_trace_path).unlink()
        except:
            pass

def main():
    """Main entry point."""
    
    print("🧪 Regression Test Runner")
    print("=" * 50)
    print("Comparing current emulator behavior against golden master baselines")
    print()
    
    passed = 0
    failed = 0
    
    for i, test_pair in enumerate(TEST_PAIRS, 1):
        print(f"[{i}/{len(TEST_PAIRS)}] ", end="")
        
        success, message = run_regression_test(test_pair)
        
        if success:
            passed += 1
            print(message)
        else:
            failed += 1
            print(f"❌ FAILED: {test_pair['disk']}")
            print(f"     {message}")
        
        print()
    
    print("=" * 50)
    print(f"📊 Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("✅ All regression tests passed!")
        print("   Refactoring is safe - behavior is identical")
        return 0
    else:
        print("❌ Some regression tests failed!")
        print("   Behavior has changed - fix issues before proceeding")
        return 1

if __name__ == "__main__":
    sys.exit(main())