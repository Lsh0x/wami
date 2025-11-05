#!/usr/bin/env python3
"""
Codebase analysis tool for WAMI Rust project.
Extracts modules, structs, enums, traits, functions, and relationships.
"""

import json
import re
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Any
from collections import defaultdict

# Get filtered file list
def get_filtered_files() -> List[str]:
    """Get list of source files to analyze."""
    result = subprocess.run(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
        capture_output=True,
        text=True,
        cwd='/Users/lsh/projects/crates/wami'
    )
    files = result.stdout.strip().split('\n')
    # Filter to only Rust source files, Cargo.toml, and README.md
    filtered = [
        f for f in files
        if (f.endswith('.rs') or f == 'Cargo.toml' or f == 'README.md')
        and not f.startswith('target/')
        and not f.startswith('.git/')
        and not f.startswith('examples/')  # Exclude examples as per plan
    ]
    return sorted(filtered)

# Patterns for Rust code extraction
MODULE_PATTERN = re.compile(r'^(pub\s+)?mod\s+(\w+)')
STRUCT_PATTERN = re.compile(r'^(pub\s+)?struct\s+(\w+)')
ENUM_PATTERN = re.compile(r'^(pub\s+)?enum\s+(\w+)')
TRAIT_PATTERN = re.compile(r'^(pub\s+)?trait\s+(\w+)')
FN_PATTERN = re.compile(r'^(pub\s+)?(async\s+)?fn\s+(\w+)')
TYPE_PATTERN = re.compile(r'^(pub\s+)?type\s+(\w+)')
USE_PATTERN = re.compile(r'^use\s+(.+?)(?:;|$)')
IMPL_PATTERN = re.compile(r'^impl\s+(.+?)(?:\s+for\s+(.+?))?$')
PUB_USE_PATTERN = re.compile(r'^pub\s+use\s+(.+?)(?:;|$)')

def parse_rust_file(filepath: str) -> Dict[str, Any]:
    """Parse a Rust file and extract structural elements."""
    result = {
        'path': filepath,
        'modules': [],
        'structs': [],
        'enums': [],
        'traits': [],
        'functions': [],
        'types': [],
        'imports': [],
        'exports': [],
        'impls': []
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments and empty lines
            if not stripped or stripped.startswith('//'):
                continue
                
            # Extract modules
            match = MODULE_PATTERN.match(stripped)
            if match:
                result['modules'].append({
                    'name': match.group(2),
                    'public': match.group(1) is not None,
                    'line': i
                })
            
            # Extract structs
            match = STRUCT_PATTERN.match(stripped)
            if match:
                result['structs'].append({
                    'name': match.group(2),
                    'public': match.group(1) is not None,
                    'line': i
                })
            
            # Extract enums
            match = ENUM_PATTERN.match(stripped)
            if match:
                result['enums'].append({
                    'name': match.group(2),
                    'public': match.group(1) is not None,
                    'line': i
                })
            
            # Extract traits
            match = TRAIT_PATTERN.match(stripped)
            if match:
                result['traits'].append({
                    'name': match.group(2),
                    'public': match.group(1) is not None,
                    'line': i
                })
            
            # Extract functions
            match = FN_PATTERN.match(stripped)
            if match:
                result['functions'].append({
                    'name': match.group(3),
                    'public': match.group(1) is not None,
                    'async': match.group(2) is not None,
                    'line': i
                })
            
            # Extract type aliases
            match = TYPE_PATTERN.match(stripped)
            if match:
                result['types'].append({
                    'name': match.group(2),
                    'public': match.group(1) is not None,
                    'line': i
                })
            
            # Extract use statements
            match = USE_PATTERN.match(stripped)
            if match:
                import_path = match.group(1).strip()
                result['imports'].append({
                    'path': import_path,
                    'line': i
                })
            
            # Extract pub use (exports)
            match = PUB_USE_PATTERN.match(stripped)
            if match:
                export_path = match.group(1).strip()
                result['exports'].append({
                    'path': export_path,
                    'line': i
                })
            
            # Extract impl blocks
            match = IMPL_PATTERN.match(stripped)
            if match:
                if match.group(2):  # impl X for Y
                    result['impls'].append({
                        'trait': match.group(1),
                        'for': match.group(2),
                        'line': i
                    })
                else:  # impl X
                    result['impls'].append({
                        'type': match.group(1),
                        'line': i
                    })
    
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        result['error'] = str(e)
    
    return result

def get_file_modification_date(filepath: str) -> str:
    """Get last modification date from git log."""
    try:
        result = subprocess.run(
            ['git', 'log', '-1', '--format=%ai', '--', filepath],
            capture_output=True,
            text=True,
            cwd='/Users/lsh/projects/crates/wami'
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    return ''

def resolve_import_path(import_path: str, current_file: str) -> str:
    """Try to resolve an import path to an actual file path."""
    # Remove 'crate::', 'super::', 'self::' prefixes
    path = import_path.replace('crate::', '').replace('super::', '').replace('self::', '')
    
    # Handle wami::, store::, etc.
    if path.startswith('wami::'):
        path = path.replace('wami::', 'src/wami/')
    elif path.startswith('store::'):
        path = path.replace('store::', 'src/store/')
    elif path.startswith('service::'):
        path = path.replace('service::', 'src/service/')
    elif path.startswith('arn::'):
        path = path.replace('arn::', 'src/arn/')
    elif path.startswith('provider::'):
        path = path.replace('provider::', 'src/provider/')
    
    # Replace :: with /
    path = path.replace('::', '/')
    
    # Add .rs extension if not present
    if not path.endswith('.rs'):
        path = path + '.rs'
    
    # If it doesn't start with src/, try to find it
    if not path.startswith('src/'):
        # Try relative to current file
        current_dir = os.path.dirname(current_file)
        if current_dir:
            potential = os.path.join(current_dir, path)
            if os.path.exists(potential):
                return potential
        # Try from src/
        potential = os.path.join('src', path)
        if os.path.exists(potential):
            return potential
    
    return path if os.path.exists(path) else ''

def create_inventory():
    """Create code inventory from all source files."""
    files = get_filtered_files()
    inventory = {
        'metadata': {
            'timestamp': datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
            'total_files': len(files),
            'language': 'rust'
        },
        'files': []
    }
    
    print(f"Analyzing {len(files)} files...")
    for i, filepath in enumerate(files, 1):
        if i % 50 == 0:
            print(f"  Processed {i}/{len(files)} files...")
        
        file_data = parse_rust_file(filepath)
        file_data['last_modified'] = get_file_modification_date(filepath)
        inventory['files'].append(file_data)
    
    # Save inventory
    inventory_file = f"codeanalysis/{inventory['metadata']['timestamp']}_code_inventory.json"
    with open(inventory_file, 'w') as f:
        json.dump(inventory, f, indent=2)
    
    print(f"Saved inventory to {inventory_file}")
    return inventory_file, inventory

if __name__ == '__main__':
    inventory_file, inventory = create_inventory()
    print(f"\nAnalysis complete!")
    print(f"Total files: {inventory['metadata']['total_files']}")

