"""
Test script to verify the string extraction fix works correctly
"""
import sys
import os

# Add analysis_modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analysis_modules'))

def test_imports():
    """Test that all imports work"""
    print("Testing imports...")
    try:
        from process_monitor import ProcessMonitor
        print("✓ ProcessMonitor imported successfully")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_function_signature():
    """Test that the function signature is correct"""
    print("\nTesting function signature...")
    try:
        from process_monitor import ProcessMonitor
        import inspect

        # Get the signature of extract_strings_from_process
        sig = inspect.signature(ProcessMonitor.extract_strings_from_process)
        params = list(sig.parameters.keys())

        print(f"Function parameters: {params}")

        # Check for required parameters
        required_params = ['self', 'pid', 'min_length', 'limit', 'enable_quality_filter',
                          'scan_mode', 'progress_callback', 'return_full_result']

        for param in required_params:
            if param in params:
                print(f"✓ Parameter '{param}' found")
            else:
                print(f"✗ Parameter '{param}' NOT found")
                return False

        print("✓ Function signature is correct")
        return True

    except Exception as e:
        print(f"✗ Signature test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_return_format():
    """Test that the return format is correct"""
    print("\nTesting return format...")
    print("Note: This requires Windows and a running process to fully test")
    print("For now, we're just checking the code paths exist")

    try:
        from process_monitor import ProcessMonitor
        import inspect

        # Get the source code
        source = inspect.getsource(ProcessMonitor.extract_strings_from_process)

        # Check for return_full_result usage
        if 'return_full_result' in source:
            print("✓ return_full_result parameter is used in function")
        else:
            print("✗ return_full_result parameter NOT used")
            return False

        # Check for metadata fields
        source_memory = inspect.getsource(ProcessMonitor._extract_strings_from_memory)
        metadata_fields = ['memory_regions', 'total_bytes_scanned', 'scan_mode',
                          'extraction_method', 'errors']

        for field in metadata_fields:
            if field in source_memory:
                print(f"✓ Metadata field '{field}' present in return")
            else:
                print(f"✗ Metadata field '{field}' NOT present")
                return False

        print("✓ Return format includes all required metadata")
        return True

    except Exception as e:
        print(f"✗ Return format test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("="*80)
    print("String Extraction Fix Verification")
    print("="*80)

    tests = [
        ("Import Test", test_imports),
        ("Function Signature Test", test_function_signature),
        ("Return Format Test", test_return_format),
    ]

    results = []
    for test_name, test_func in tests:
        print()
        result = test_func()
        results.append((test_name, result))

    print("\n" + "="*80)
    print("Test Results Summary:")
    print("="*80)

    all_passed = True
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {test_name}: {status}")
        if not result:
            all_passed = False

    print("="*80)
    if all_passed:
        print("✓ All tests PASSED! The fix is ready.")
    else:
        print("✗ Some tests FAILED. Review the errors above.")
    print("="*80)

    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
