#!/usr/bin/env python3
"""
Golden Master Trace Comparator

This script compares two trace files to ensure identical behavior
before and after refactoring.
"""

import sys
import argparse
from pathlib import Path
from typing import List, Tuple
import difflib

def normalize_trace_line(line: str) -> str:
    """Normalize a trace line for comparison.
    
    Remove minor variations that don't affect behavior:
    - Timestamps if present
    - Whitespace differences
    """
    line = line.strip()
    
    # Remove any timestamp prefixes if they exist
    # Format: "[123.456] " or similar
    if line and line[0] == '[' and ']' in line:
        end_bracket = line.find(']')
        if end_bracket > 0:
            line = line[end_bracket + 1:].strip()
    
    return line

def read_trace_file(trace_path: Path) -> List[str]:
    """Read and normalize trace file."""
    if not trace_path.exists():
        raise FileNotFoundError(f"Trace file not found: {trace_path}")
    
    with open(trace_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Normalize each line and filter empty lines
    normalized = []
    for line in lines:
        normalized_line = normalize_trace_line(line)
        if normalized_line:  # Skip empty lines
            normalized.append(normalized_line)
    
    return normalized

def compare_traces(baseline: List[str], current: List[str]) -> Tuple[bool, List[str]]:
    """Compare two trace lists and return (match, differences)."""
    
    if len(baseline) != len(current):
        return False, [f"Length mismatch: baseline={len(baseline)}, current={len(current)}"]
    
    differences = []
    
    for i, (base_line, curr_line) in enumerate(zip(baseline, current)):
        if base_line != curr_line:
            diff = difflib.unified_diff(
                [base_line + '\n'], 
                [curr_line + '\n'],
                fromfile=f'baseline line {i}',
                tofile=f'current line {i}',
                lineterm=''
            )
            differences.extend(diff)
    
    return len(differences) == 0, differences

def main():
    """Main entry point."""
    
    parser = argparse.ArgumentParser(
        description='Compare emulator trace files for behavioral consistency'
    )
    parser.add_argument(
        'baseline',
        help='Baseline (golden master) trace file'
    )
    parser.add_argument(
        'current', 
        help='Current trace file to compare against baseline'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all differences (not just summary)'
    )
    
    args = parser.parse_args()
    
    baseline_path = Path(args.baseline)
    current_path = Path(args.current)
    
    if not baseline_path.exists():
        print(f"❌ Baseline file not found: {baseline_path}")
        return 1
    
    if not current_path.exists():
        print(f"❌ Current file not found: {current_path}")
        return 1
    
    print("🔍 Comparing traces...")
    print(f"   Baseline: {baseline_path}")
    print(f"   Current:  {current_path}")
    print()
    
    try:
        baseline_lines = read_trace_file(baseline_path)
        current_lines = read_trace_file(current_path)
        
        match, differences = compare_traces(baseline_lines, current_lines)
        
        if match:
            print("✅ Traces are identical!")
            return 0
        else:
            print("❌ Traces differ!")
            print(f"   Number of differences: {len(differences) // 4}")  # difflib outputs 4 lines per diff
            
            if args.verbose:
                print("\n📋 Differences:")
                for diff in differences:
                    print(diff)
            else:
                print("   Use -v to see detailed differences")
            
            return 1
            
    except Exception as e:
        print(f"❌ Error comparing traces: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())