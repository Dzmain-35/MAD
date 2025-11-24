"""
Test script to demonstrate memory string extractor quality filtering
"""

import sys
import importlib.util

# Load the memory_string_extractor module directly
spec = importlib.util.spec_from_file_location(
    "memory_string_extractor",
    "/home/user/Malware-Analysis-Dashboard-MAD-/analysis_modules/memory_string_extractor.py"
)
memory_string_extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(memory_string_extractor)

MemoryStringExtractor = memory_string_extractor.MemoryStringExtractor

def test_quality_filters():
    """Test individual quality filter functions"""
    # Note: This requires Windows, so we'll just demonstrate the logic

    print("=" * 80)
    print("Testing Quality Filtering Functions")
    print("=" * 80)

    test_strings = [
        # Good strings (should pass)
        ("C:\\Users\\REM\\Desktop\\new 1.txt", "Complete file path"),
        ("C:\\Windows\\SYSTEM32\\kernelbase.dll", "Complete system path"),
        ("192.168.1.100", "Valid IP address"),
        ("https://example.com/api/endpoint", "Valid URL"),
        ("HKEY_LOCAL_MACHINE\\Software\\Microsoft", "Registry key"),
        ("This is a normal text string", "Regular text"),

        # Bad strings (should be filtered)
        ("C:\\Windo", "Truncated path"),
        ("\\REGISH", "Truncated registry"),
        ("OXE~", "Too short/junk"),
        ("QWE~", "Too short/junk"),
        ("XXXXXXXXXXXXXXX", "Excessive repetition"),
        ("999.999.999.999", "Invalid IP"),
        ("advapi32.dllapi-ms-win-base-util-l1-1-0", "Concatenated strings"),
        ("!@#$%^&*()!@#$%^&*()", "Mostly special chars"),
        ("zxcvbnmqwrtyplkjhgfdsa", "No vowels/high entropy"),
    ]

    # Create extractor instance
    try:
        extractor = MemoryStringExtractor()

        print("\nQuality Filter Results:")
        print("-" * 80)
        print(f"{'String':<50} {'Pass/Fail':<12} {'Reason':<20}")
        print("-" * 80)

        for test_string, description in test_strings:
            passes = extractor._is_quality_string(test_string, min_length=10)
            status = "✓ PASS" if passes else "✗ FAIL"
            print(f"{test_string[:47]:<50} {status:<12} {description}")

        print("\n" + "=" * 80)
        print("Entropy Analysis Examples:")
        print("-" * 80)

        entropy_tests = [
            "This is a normal sentence with words",
            "C:\\Windows\\System32\\kernel32.dll",
            "AAAAAAAAAAAAAAAAAAAAAA",
            "xK9mQ2vP8nL4jW7cR5tY",
            "192.168.1.100",
        ]

        for test_str in entropy_tests:
            entropy = extractor._calculate_entropy(test_str)
            vowel_ratio = extractor._get_vowel_ratio(test_str)
            repetitive = extractor._has_excessive_repetition(test_str)

            print(f"\nString: {test_str[:40]}")
            print(f"  Entropy: {entropy:.2f} (>4.5 is too random)")
            print(f"  Vowel Ratio: {vowel_ratio:.2f} (<0.15 is suspicious)")
            print(f"  Repetitive: {repetitive}")

    except RuntimeError as e:
        print(f"\n⚠ Note: {e}")
        print("This is expected on non-Windows platforms.")
        print("\nThe quality filtering functions would work as follows:")
        print("\nGood strings (would PASS):")
        for test_string, description in test_strings[:6]:
            print(f"  ✓ {test_string} - {description}")

        print("\nBad strings (would FAIL):")
        for test_string, description in test_strings[6:]:
            print(f"  ✗ {test_string} - {description}")

    print("\n" + "=" * 80)
    print("Quality Filtering Features:")
    print("=" * 80)
    print("""
1. Entropy Filtering
   - Detects random/encrypted strings (high entropy)
   - Threshold: >4.5 entropy rejected

2. Vowel Ratio Analysis
   - Real words have ~30-50% vowels
   - Rejects strings with <15% vowels (unless technical paths)

3. Repetition Detection
   - Filters excessive character repetition (>60%)
   - Detects repeating patterns (ABABAB...)

4. Truncation Detection
   - Identifies partial paths (C:\\Win instead of C:\\Windows)
   - Filters incomplete registry paths (\\REGIS...)

5. IP Validation
   - Validates octets are 0-255 range
   - Rejects invalid IPs (999.999.999.999)

6. Special Character Filtering
   - Rejects strings with >40% special characters
   - Keeps technical strings (paths, URLs, IPs)
    """)

if __name__ == "__main__":
    test_quality_filters()
