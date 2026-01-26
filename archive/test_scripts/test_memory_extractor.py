"""
Test script for Memory String Extractor
Tests the enhanced memory string extraction functionality
"""

import os
import sys
import psutil

# Add the analysis_modules to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analysis_modules.memory_string_extractor import MemoryStringExtractor


def test_on_pid(pid: int):
    """Test memory extraction on a specific PID"""
    print("=" * 80)
    print(f"Testing Memory String Extractor on PID {pid}")
    print("=" * 80)

    try:
        # Get process info
        proc = psutil.Process(pid)
        print(f"Process: {proc.name()}")
        print(f"Executable: {proc.exe() if proc.exe() else 'N/A'}")
        print()

        # Create extractor with verbose mode
        extractor = MemoryStringExtractor(verbose=True)

        # Extract strings
        print("\nStarting string extraction...")
        print("-" * 80)

        results = extractor.extract_strings_from_memory(
            pid=pid,
            min_length=10,
            max_strings=20000,
            include_unicode=True,
            filter_regions=['private', 'image', 'mapped']
        )

        print("-" * 80)
        print("\nExtraction Results:")
        print(f"  Total bytes scanned: {results['total_bytes_scanned']:,}")
        print(f"  Memory regions found: {len(results['memory_regions'])}")
        print()

        # Show string counts
        print("String counts by type:")
        for str_type, strings in results['strings'].items():
            print(f"  {str_type.capitalize()}: {len(strings)}")
        print()

        # Show sample strings
        print("Sample strings (first 20 from each category):")
        for str_type, strings in results['strings'].items():
            if strings and str_type in ['urls', 'paths', 'ips', 'registry']:
                print(f"\n  {str_type.upper()}:")
                for s in list(strings)[:20]:
                    print(f"    {s}")

        # Show errors
        if results['errors']:
            print("\nErrors encountered:")
            for error in results['errors']:
                print(f"  - {error}")

        # Get interesting strings
        print("\n" + "=" * 80)
        print("Interesting Strings Analysis:")
        print("=" * 80)
        interesting = extractor.get_interesting_strings(results)

        for category, strings in interesting.items():
            if strings:
                print(f"\n{category.upper()} ({len(strings)}):")
                for s in strings[:10]:
                    print(f"  - {s}")

        print("\n" + "=" * 80)
        print("Test completed!")
        print("=" * 80)

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()


def list_processes():
    """List running processes to help choose a PID"""
    print("\nRunning processes (first 20):")
    print("-" * 80)
    print(f"{'PID':<8} {'Name':<30} {'Status':<15}")
    print("-" * 80)

    count = 0
    for proc in psutil.process_iter(['pid', 'name', 'status']):
        try:
            print(f"{proc.info['pid']:<8} {proc.info['name']:<30} {proc.info['status']:<15}")
            count += 1
            if count >= 20:
                break
        except:
            pass

    print("-" * 80)
    print(f"(Showing {count} processes. Use psutil to see all processes)")
    print()


if __name__ == "__main__":
    import platform

    if platform.system() != 'Windows':
        print("ERROR: This script requires Windows platform")
        print(f"Current platform: {platform.system()}")
        sys.exit(1)

    print("Memory String Extractor Test Script")
    print("=" * 80)

    if len(sys.argv) > 1:
        # Test on specified PID
        try:
            pid = int(sys.argv[1])
            test_on_pid(pid)
        except ValueError:
            print(f"ERROR: Invalid PID '{sys.argv[1]}'. Must be an integer.")
            sys.exit(1)
        except psutil.NoSuchProcess:
            print(f"ERROR: Process with PID {sys.argv[1]} not found.")
            sys.exit(1)
        except psutil.AccessDenied:
            print(f"ERROR: Access denied to process {sys.argv[1]}. Try running as Administrator.")
            sys.exit(1)
    else:
        # Show help
        print("Usage: python test_memory_extractor.py <PID>")
        print()
        print("Example:")
        print("  python test_memory_extractor.py 1234")
        print()
        print("To test on current process:")
        print(f"  python test_memory_extractor.py {os.getpid()}")
        print()

        list_processes()

        print("\nNote: You may need to run as Administrator to access some processes.")
