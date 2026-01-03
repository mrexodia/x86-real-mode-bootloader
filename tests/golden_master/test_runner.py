#!/usr/bin/env python3
"""
Golden Master Test Runner

This script runs the emulator against all test disk images and generates
baseline trace files to ensure behavioral consistency during refactoring.
"""

import sys
import subprocess
import os
from pathlib import Path
from typing import List, Tuple

# Test disk images to create golden masters for
TEST_DISKS = [
    "BOOT_CODE_MSDOS70_FAT12_BAD.img",
    "BOOT_CODE_OEMBOOT70_FAT12_GOOD.img", 
    "HDD_60MB_FAT16_MDOS40_BOOTCODE_MSDOS622_SYSTEM.img",
    "HDD_MSDOS33_FAT12_BC_331.img",
    "MSDOS33_FAT12.img",
    "boot.img",
    "dostest.img",
]

def create_golden_master(disk_image: str, output_dir: Path) -> bool:
    """Create golden master trace for a disk image."""
    
    if not Path(disk_image).exists():
        print(f"❌ Disk image not found: {disk_image}")
        return False
    
    # Generate output filename
    baseline_name = f"baseline_{disk_image}.txt"
    output_file = output_dir / baseline_name
    
    print(f"🔄 Creating golden master: {disk_image} -> {baseline_name}")
    
    # Run emulator with maximum verbosity (verbose is default, no -q flag)
    cmd = [
        sys.executable, "emulator.py",
        disk_image,
        "--max-instructions", "1000000",
        "--output", str(output_file),
        # Note: Verbose is default, don't use --quiet flag
    ]
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            print(f"✅ Success: {baseline_name}")
            
            # Verify trace file was created and has content
            if output_file.exists() and output_file.stat().st_size > 0:
                size_kb = output_file.stat().st_size / 1024
                print(f"   📊 Trace size: {size_kb:.1f} KB")
                return True
            else:
                print(f"❌ Trace file empty or missing: {output_file}")
                return False
        else:
            print(f"❌ Emulator failed for {disk_image}")
            print(f"   Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏰ Timeout running emulator for {disk_image}")
        return False
    except Exception as e:
        print(f"❌ Error running emulator for {disk_image}: {e}")
        return False

def main():
    """Main entry point."""
    
    print("🧪 Golden Master Test Runner")
    print("=" * 50)
    
    # Create output directory
    output_dir = Path("tests/golden_master/fixtures")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"📁 Output directory: {output_dir}")
    print()
    
    success_count = 0
    total_count = len(TEST_DISKS)
    
    for disk_image in TEST_DISKS:
        if create_golden_master(disk_image, output_dir):
            success_count += 1
        print()
    
    print("=" * 50)
    print(f"📊 Results: {success_count}/{total_count} golden masters created")
    
    if success_count == total_count:
        print("✅ All golden masters created successfully!")
        print()
        print("📝 Next steps:")
        print("1. Commit these baseline traces to version control")
        print("2. Start refactoring emulator.py into modules")
        print("3. Use these traces as regression tests")
        return 0
    else:
        print("❌ Some golden masters failed!")
        print("   Fix any issues before proceeding with refactoring")
        return 1

if __name__ == "__main__":
    sys.exit(main())