# Archived Files

This directory contains code that has been archived during codebase cleanup.
These files are preserved for reference but are not actively used in the project.

## unused_modules/

Monitor modules that were not being used in the main application:

- `process_activity_monitor.py` - Per-process activity monitoring (347 lines, never imported)
- `process_memory_tree_filtered.py` - Process memory filtering (484 lines, never imported)

## test_scripts/

Standalone test scripts that were in the root directory:

- `test_memory_extractor.py` - Memory string extractor tests
- `test_quality_filtering.py` - Quality filtering logic tests
- `test_string_extraction_fix.py` - String extraction API tests
- `test_yara.py` - YARA rule compilation tests

**Note:** These test scripts have hardcoded paths and are not integrated with a test framework.
Consider migrating to pytest if formal testing is needed.

---
*Archived on: 2026-01-26*
