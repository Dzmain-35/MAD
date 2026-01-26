"""
Enhanced Process Monitor with Procmon-Style Memory Tree View
PROCMON-FILTERED: Shows only files relevant to the selected process
Filters out Windows system DLL noise like Process Monitor does

Filtering Strategy (inspired by Procmon):
- ALWAYS show: Main executable
- ALWAYS show: Files in same directory as executable
- ALWAYS show: Files in user locations (AppData, ProgramData, Temp, etc.)
- ALWAYS show: Non-standard paths (not C:\Windows\System32\)
- OPTIONALLY show: Windows system files (toggle with show_system_files flag)
"""

import os
import psutil
from typing import Dict, List, Optional, Set
from collections import defaultdict


def is_process_relevant_file(file_path: str, process_exe_path: str, show_system_files: bool = False) -> bool:
    """
    Determine if a file is relevant to the process (Procmon-style filtering)
    
    Args:
        file_path: Path to the memory-mapped file
        process_exe_path: Path to the main process executable
        show_system_files: If True, include Windows system files
        
    Returns:
        True if file should be shown
    """
    if not file_path or not file_path.strip():
        return False
    
    file_path_lower = file_path.lower()
    exe_dir = os.path.dirname(process_exe_path).lower() if process_exe_path else ""
    
    # RULE 1: Always show the main executable
    if file_path_lower == process_exe_path.lower():
        return True
    
    # RULE 2: Always show files in the same directory as the executable
    if exe_dir and file_path_lower.startswith(exe_dir):
        return True
    
    # RULE 3: Always show files in user/app directories (not system directories)
    user_paths = [
        os.environ.get('USERPROFILE', '').lower(),
        os.environ.get('APPDATA', '').lower(),
        os.environ.get('LOCALAPPDATA', '').lower(),
        os.environ.get('PROGRAMDATA', '').lower(),
        os.environ.get('TEMP', '').lower(),
        os.environ.get('TMP', '').lower(),
    ]
    
    for user_path in user_paths:
        if user_path and file_path_lower.startswith(user_path):
            return True
    
    # RULE 4: Show Program Files paths (applications installed by user)
    if 'program files' in file_path_lower or 'programfiles' in file_path_lower:
        return True
    
    # RULE 5: Filter Windows system directories unless show_system_files is True
    windows_system_paths = [
        'c:\\windows\\system32',
        'c:\\windows\\syswow64',
        'c:\\windows\\winsxs',
    ]
    
    for sys_path in windows_system_paths:
        if file_path_lower.startswith(sys_path):
            return show_system_files  # Only show if explicitly requested
    
    # RULE 6: Show anything else in C:\Windows\ (might be relevant)
    # But be conservative - most stuff here is system noise
    if file_path_lower.startswith('c:\\windows\\'):
        # Show if it's a known app-specific file
        app_indicators = ['.config', '.ini', '.xml', '.json', 'appdata', 'app data']
        if any(indicator in file_path_lower for indicator in app_indicators):
            return True
        return show_system_files
    
    # RULE 7: Show anything not in a standard Windows location
    # (likely application-specific)
    return True


def get_process_memory_tree(pid: int, show_system_files: bool = False) -> Dict:
    """
    Get process memory in a Procmon-style hierarchical tree structure
    FILTERED to show only process-relevant files
    
    Args:
        pid: Process ID
        show_system_files: If True, include Windows system DLLs (default: False)
        
    Returns:
        Dictionary with hierarchical memory information
    """
    try:
        proc = psutil.Process(pid)
        
        # Get process executable path for filtering
        try:
            process_exe_path = proc.exe()
        except:
            process_exe_path = ""
        
        memory_tree = {
            'pid': pid,
            'name': proc.name(),
            'exe_path': process_exe_path,
            'modules': [],  # Loaded DLLs and EXEs
            'mapped_files': [],  # Memory-mapped files
            'special_regions': [],  # Stack, Heap, etc.
            'total_memory': 0,
            'filtered_count': 0,  # How many files were filtered out
            'errors': [],
            'show_system_files': show_system_files
        }
        
        # Get memory maps with better error handling
        try:
            memory_maps = None
            
            # Try with grouped=True (more reliable)
            try:
                memory_maps = proc.memory_maps(grouped=True)
            except (TypeError, AttributeError):
                pass
            
            # Fallback: Try without grouped parameter
            if not memory_maps:
                try:
                    memory_maps = proc.memory_maps()
                except Exception:
                    pass
            
            if not memory_maps:
                memory_tree['errors'].append(
                    "No memory maps returned. Process may require Administrator privileges. "
                    "Please run MAD as Administrator (right-click → Run as Administrator)."
                )
                return memory_tree
            
            # Group by file path
            file_regions = defaultdict(list)
            special_regions = []
            filtered_out = 0
            
            for mmap in memory_maps:
                try:
                    region_info = {}
                    
                    # Get path first (most important for filtering)
                    path = None
                    if hasattr(mmap, 'path'):
                        path = mmap.path
                    elif hasattr(mmap, 'pathname'):
                        path = mmap.pathname
                    
                    # PROCMON-STYLE FILTERING: Check if this file is relevant
                    if path and path.strip():
                        if not is_process_relevant_file(path, process_exe_path, show_system_files):
                            filtered_out += 1
                            continue  # Skip this file - it's system noise
                    
                    # Get address - try multiple approaches
                    addr_str = None
                    start_addr = 0
                    
                    for attr_name in ['addr', 'address']:
                        if hasattr(mmap, attr_name):
                            addr_str = getattr(mmap, attr_name)
                            break
                    
                    # Parse address
                    if addr_str and isinstance(addr_str, str) and '-' in addr_str:
                        try:
                            start_str, end_str = addr_str.split('-')
                            start_addr = int(start_str, 16) if start_str.startswith('0x') else int(start_str)
                            end_addr = int(end_str, 16) if end_str.startswith('0x') else int(end_str)
                            size = end_addr - start_addr
                        except:
                            size = 0
                    else:
                        size = 0
                    
                    # Get size from attributes if needed
                    if size == 0:
                        if hasattr(mmap, 'size'):
                            size = mmap.size
                        elif hasattr(mmap, 'rss'):
                            size = mmap.rss
                    
                    # Get permissions
                    perms = "unknown"
                    if hasattr(mmap, 'perms'):
                        perms = mmap.perms
                    elif hasattr(mmap, 'protection'):
                        perms = mmap.protection
                    
                    # Get RSS
                    rss_val = 0
                    if hasattr(mmap, 'rss'):
                        rss_val = mmap.rss
                    
                    # Build region info
                    region_info = {
                        'address': str(addr_str) if addr_str else 'unknown',
                        'start_addr': start_addr,
                        'size': size,
                        'size_kb': size / 1024 if size > 0 else 0,
                        'size_mb': size / (1024 * 1024) if size > 0 else 0,
                        'perms': perms,
                        'path': path if path else '[anonymous]',
                        'rss': rss_val,
                    }
                    
                    memory_tree['total_memory'] += size
                    
                    # Categorize by path
                    if path and path.strip():
                        file_regions[path].append(region_info)
                    else:
                        special_regions.append(region_info)
                
                except Exception as e:
                    # Better error reporting
                    try:
                        attrs = [attr for attr in dir(mmap) if not attr.startswith('_')]
                        memory_tree['errors'].append(
                            f"Could not parse memory region. Available attributes: {', '.join(attrs[:5])}..."
                        )
                    except:
                        memory_tree['errors'].append(f"Could not parse memory region: {str(e)}")
                    continue
            
            # Store filtered count
            memory_tree['filtered_count'] = filtered_out
            
            # Build hierarchical structure for files
            for file_path, regions in sorted(file_regions.items()):
                # Determine file type
                file_ext = os.path.splitext(file_path)[1].lower()
                
                # Determine icon and type
                if file_ext in ['.exe']:
                    file_type = 'Executable'
                    icon = '📋'
                elif file_ext in ['.dll', '.so', '.dylib']:
                    file_type = 'Library'
                    icon = '📚'
                elif file_ext in ['.sys', '.drv']:
                    file_type = 'Driver'
                    icon = '⚙️'
                elif file_ext in ['.config', '.xml', '.ini', '.json']:
                    file_type = 'Config File'
                    icon = '⚙️'
                elif '[' in file_path:  # Special regions
                    file_type = 'Special'
                    icon = '🔧'
                else:
                    file_type = 'Data File'
                    icon = '📄'
                
                # Calculate total size
                total_file_size = sum(r['size'] for r in regions)
                
                # Determine if this is the main executable
                is_main_exe = file_path.lower() == process_exe_path.lower()
                
                file_node = {
                    'path': file_path,
                    'filename': os.path.basename(file_path) if os.path.sep in file_path else file_path,
                    'type': file_type,
                    'icon': icon,
                    'is_main_exe': is_main_exe,
                    'num_regions': len(regions),
                    'total_size': total_file_size,
                    'total_size_kb': total_file_size / 1024,
                    'total_size_mb': total_file_size / (1024 * 1024),
                    'regions': sorted(regions, key=lambda r: r['start_addr'])
                }
                
                # Categorize
                if file_ext in ['.exe', '.dll', '.sys', '.drv', '.so', '.dylib']:
                    memory_tree['modules'].append(file_node)
                else:
                    memory_tree['mapped_files'].append(file_node)
            
            # Add special regions
            if special_regions:
                memory_tree['special_regions'] = sorted(special_regions, key=lambda r: r['start_addr'])
        
        except psutil.AccessDenied:
            memory_tree['errors'].append(
                "Access Denied: This process requires Administrator privileges. "
                "Please run MAD as Administrator (right-click → Run as Administrator)."
            )
        except Exception as e:
            memory_tree['errors'].append(
                f"Error reading memory maps: {type(e).__name__}: {str(e)}"
            )
        
        # Get additional process info
        try:
            memory_info = proc.memory_info()
            memory_tree['rss'] = memory_info.rss
            memory_tree['vms'] = memory_info.vms
            memory_tree['rss_mb'] = memory_info.rss / (1024 * 1024)
            memory_tree['vms_mb'] = memory_info.vms / (1024 * 1024)
        except:
            pass
        
        return memory_tree
    
    except psutil.NoSuchProcess:
        return {
            'error': f'Process {pid} not found - it may have terminated',
            'pid': pid
        }
    except psutil.AccessDenied:
        return {
            'error': f'Access Denied to process {pid}. Please run MAD as Administrator.',
            'pid': pid
        }
    except Exception as e:
        return {
            'error': f'Error reading process {pid}: {str(e)}',
            'pid': pid
        }


def format_memory_tree_text(memory_tree: Dict) -> str:
    """
    Format memory tree as text for display
    
    Args:
        memory_tree: Memory tree dictionary from get_process_memory_tree
        
    Returns:
        Formatted text string
    """
    if 'error' in memory_tree:
        return f"Error: {memory_tree['error']}"
    
    lines = []
    lines.append(f"Memory Map for PID {memory_tree['pid']} - {memory_tree['name']}")
    lines.append("=" * 80)
    
    # Show filtering info
    if memory_tree.get('filtered_count', 0) > 0:
        lines.append(f"🔍 FILTERED VIEW (Procmon-style)")
        lines.append(f"   Hidden {memory_tree['filtered_count']} system files (Windows DLLs, etc.)")
        lines.append(f"   Showing only process-relevant files")
        if not memory_tree.get('show_system_files', False):
            lines.append(f"   Tip: Set show_system_files=True to see all files")
        lines.append("")
    
    if 'rss_mb' in memory_tree:
        lines.append(f"Total RSS: {memory_tree['rss_mb']:.2f} MB")
        lines.append(f"Total VMS: {memory_tree['vms_mb']:.2f} MB")
        lines.append("")
    
    # Show modules (EXE, DLLs) - with main EXE first
    if memory_tree['modules']:
        lines.append(f"📚 LOADED MODULES ({len(memory_tree['modules'])})")
        lines.append("-" * 80)
        
        # Sort: Main EXE first, then by size
        modules_sorted = sorted(
            memory_tree['modules'],
            key=lambda m: (not m.get('is_main_exe', False), -m['total_size_mb'])
        )
        
        for module in modules_sorted:
            size_str = f"{module['total_size_mb']:.2f} MB" if module['total_size_mb'] >= 1 else f"{module['total_size_kb']:.0f} KB"
            
            # Mark main executable
            main_indicator = " ⭐ MAIN PROCESS" if module.get('is_main_exe', False) else ""
            
            lines.append(f"{module['icon']} {module['filename']}{main_indicator}")
            lines.append(f"   Path: {module['path']}")
            lines.append(f"   Size: {size_str} ({module['num_regions']} regions)")
            
            # Show first 3 regions
            for region in module['regions'][:3]:
                size_r = f"{region['size_kb']:.0f} KB" if region['size_kb'] < 1024 else f"{region['size_mb']:.2f} MB"
                lines.append(f"      └─ {region['address']} ({size_r}) [{region['perms']}]")
            
            if len(module['regions']) > 3:
                lines.append(f"      └─ ... and {len(module['regions']) - 3} more regions")
            
            lines.append("")
    
    # Show mapped files
    if memory_tree['mapped_files']:
        lines.append(f"📄 MEMORY-MAPPED FILES ({len(memory_tree['mapped_files'])})")
        lines.append("-" * 80)
        
        for mfile in memory_tree['mapped_files'][:10]:
            size_str = f"{mfile['total_size_mb']:.2f} MB" if mfile['total_size_mb'] >= 1 else f"{mfile['total_size_kb']:.0f} KB"
            lines.append(f"{mfile['icon']} {mfile['filename']}")
            lines.append(f"   Path: {mfile['path']}")
            lines.append(f"   Size: {size_str} ({mfile['num_regions']} regions)")
        
        if len(memory_tree['mapped_files']) > 10:
            lines.append(f"   ... and {len(memory_tree['mapped_files']) - 10} more files")
        lines.append("")
    
    # Show special regions
    if memory_tree['special_regions']:
        lines.append(f"🔧 SPECIAL REGIONS ({len(memory_tree['special_regions'])})")
        lines.append("-" * 80)
        
        for region in memory_tree['special_regions'][:10]:
            size_str = f"{region['size_kb']:.0f} KB" if region['size_kb'] < 1024 else f"{region['size_mb']:.2f} MB"
            lines.append(f"   {region['address']} ({size_str}) [{region['perms']}] - {region['path']}")
        
        if len(memory_tree['special_regions']) > 10:
            lines.append(f"   ... and {len(memory_tree['special_regions']) - 10} more regions")
    
    # Show summary
    if memory_tree.get('filtered_count', 0) > 0 or memory_tree['modules'] or memory_tree['mapped_files']:
        lines.append("")
        lines.append("=" * 80)
        lines.append("SUMMARY:")
        lines.append(f"  Process-relevant modules: {len(memory_tree['modules'])}")
        lines.append(f"  Process-relevant mapped files: {len(memory_tree['mapped_files'])}")
        lines.append(f"  Special regions: {len(memory_tree['special_regions'])}")
        if memory_tree.get('filtered_count', 0) > 0:
            lines.append(f"  Filtered out (system noise): {memory_tree['filtered_count']}")
        lines.append("=" * 80)
    
    # Show errors if any
    if memory_tree['errors']:
        lines.append("")
        lines.append("⚠️ WARNINGS/ERRORS:")
        lines.append("-" * 80)
        for error in memory_tree['errors']:
            lines.append(f"   {error}")
    
    return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        pid = int(sys.argv[1])
    else:
        # Find a test process
        for proc in psutil.process_iter(['pid', 'name']):
            name_lower = proc.info['name'].lower()
            if any(app in name_lower for app in ['notepad', 'calc', 'chrome', 'firefox', 'code']):
                pid = proc.info['pid']
                print(f"Found test process: {proc.info['name']} (PID {pid})")
                break
        else:
            print("No test process found. Please specify a PID:")
            print("Usage: python process_memory_tree.py <PID>")
            sys.exit(1)
    
    print()
    print("=" * 80)
    print("Testing PROCMON-FILTERED Memory Tree")
    print("=" * 80)
    print()
    
    # Test with filtering (default)
    print("TEST 1: WITH FILTERING (Procmon-style)")
    print("-" * 80)
    memory_tree = get_process_memory_tree(pid, show_system_files=False)
    print(format_memory_tree_text(memory_tree))
    
    print()
    print()
    print("=" * 80)
    print("TEST 2: WITHOUT FILTERING (Show all files)")
    print("-" * 80)
    memory_tree_full = get_process_memory_tree(pid, show_system_files=True)
    print(format_memory_tree_text(memory_tree_full))