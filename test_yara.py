"""
Test script to verify YARA rules are loading and working
Run this before launching the GUI to troubleshoot
"""

import os
import yara
from pathlib import Path

def test_yara_rules():
    print("="*60)
    print("YARA Rules Test Script")
    print("="*60)
    
    # Test different possible paths
    possible_paths = [
        r"C:\Users\REM\Desktop\MAD\YDAMN",
        os.path.join(os.path.expanduser("~"), "Desktop", "MAD", "YDAMN"),
        os.path.join(os.getcwd(), "MAD", "YDAMN"),
        "MAD/YDAMN"
    ]
    
    yara_path = None
    for path in possible_paths:
        print(f"\nChecking: {path}")
        if os.path.exists(path):
            print(f"  ✓ Path exists!")
            yara_path = path
            break
        else:
            print(f"  ✗ Path not found")
    
    if not yara_path:
        print("\n❌ ERROR: Could not find YARA rules directory!")
        print("\nPlease ensure your YARA rules are in one of these locations:")
        for path in possible_paths:
            print(f"  - {path}")
        return False
    
    print(f"\n{'='*60}")
    print(f"Using YARA rules path: {yara_path}")
    print(f"{'='*60}")
    
    # Find YARA files
    yara_files = list(Path(yara_path).glob("*.yara")) + \
                 list(Path(yara_path).glob("*.yar"))
    
    if not yara_files:
        print("\n❌ ERROR: No .yara or .yar files found!")
        print(f"\nFiles in directory:")
        for item in os.listdir(yara_path):
            print(f"  - {item}")
        return False
    
    print(f"\n✓ Found {len(yara_files)} YARA rule files:")
    for yf in yara_files:
        print(f"  - {yf.name}")
    
    # Try to compile rules
    print(f"\n{'='*60}")
    print("Attempting to compile YARA rules...")
    print(f"{'='*60}")
    
    try:
        rules_dict = {}
        for idx, yara_file in enumerate(yara_files):
            namespace = f"rule_{idx}_{yara_file.stem}"
            rules_dict[namespace] = str(yara_file)
            print(f"  Loading: {yara_file.name}")
        
        compiled_rules = yara.compile(filepaths=rules_dict)
        print(f"\n✓ SUCCESS! All {len(yara_files)} YARA rules compiled successfully!")
        
        # Test scan on a sample file if provided
        import sys
        if len(sys.argv) > 1:
            test_file = sys.argv[1]
            if os.path.exists(test_file):
                print(f"\n{'='*60}")
                print(f"Testing scan on: {test_file}")
                print(f"{'='*60}")
                matches = compiled_rules.match(test_file)
                if matches:
                    print(f"\n✓ MATCHES FOUND:")
                    for match in matches:
                        print(f"  - Rule: {match.rule}")
                        print(f"    Namespace: {match.namespace}")
                else:
                    print("\n- No matches found (file is clean)")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR compiling YARA rules:")
        print(f"  {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("\nUsage: python test_yara.py [optional: path_to_test_file]")
    print()
    success = test_yara_rules()
    
    if success:
        print("\n" + "="*60)
        print("✓ YARA rules are working correctly!")
        print("You can now run the main GUI application")
        print("="*60)
    else:
        print("\n" + "="*60)
        print("❌ YARA rules setup has issues")
        print("Please fix the errors above before running the GUI")
        print("="*60)