#!/usr/bin/env python3
"""
Generate Mermaid knowledge graph and analysis report from code inventory.
"""

import json
import os
import glob
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Tuple
from collections import defaultdict

def load_latest_inventory() -> Dict[str, Any]:
    """Load the most recent inventory file."""
    inventory_files = glob.glob('codeanalysis/*_code_inventory.json')
    if not inventory_files:
        raise FileNotFoundError("No inventory file found")
    
    latest = max(inventory_files, key=os.path.getctime)
    print(f"Loading inventory from {latest}")
    
    with open(latest, 'r') as f:
        return json.load(f)

def resolve_module_path(module_path: str, current_file: str) -> str:
    """Resolve a module path to a file path."""
    # Remove common prefixes
    path = module_path.replace('crate::', '').replace('super::', '').replace('self::', '')
    
    # Handle module prefixes
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
    
    # Handle mod.rs files
    if path.endswith('mod'):
        path = path[:-3] + 'mod.rs'
    elif not path.endswith('.rs'):
        # Try mod.rs first
        mod_path = path + '/mod.rs'
        if os.path.exists(mod_path):
            return mod_path
        # Try .rs
        path = path + '.rs'
    
    # Check if file exists
    if os.path.exists(path):
        return path
    
    # Try relative to current file
    current_dir = os.path.dirname(current_file)
    if current_dir:
        potential = os.path.join(current_dir, path)
        if os.path.exists(potential):
            return potential
        # Try with mod.rs
        potential_mod = os.path.join(current_dir, os.path.dirname(path) or '.', 'mod.rs')
        if os.path.exists(potential_mod):
            return potential_mod
    
    return ''

def build_relationships(inventory: Dict[str, Any]) -> Dict[str, Any]:
    """Build relationship map from inventory."""
    files_by_path = {f['path']: f for f in inventory['files']}
    
    relationships = {
        'imports': defaultdict(list),  # file -> [imported files]
        'defines': defaultdict(list),   # file -> [entities defined]
        'uses': defaultdict(list),     # file -> [entities used]
        'implements': defaultdict(list) # file -> [impl relationships]
    }
    
    # Track all entities
    entity_locations = {}  # entity_name -> file
    
    # First pass: map entities to files
    for file_data in inventory['files']:
        filepath = file_data['path']
        
        # Map structs
        for struct in file_data.get('structs', []):
            entity_locations[struct['name']] = filepath
        
        # Map enums
        for enum in file_data.get('enums', []):
            entity_locations[enum['name']] = filepath
        
        # Map traits
        for trait in file_data.get('traits', []):
            entity_locations[trait['name']] = filepath
        
        # Map types
        for type_alias in file_data.get('types', []):
            entity_locations[type_alias['name']] = filepath
    
    # Second pass: build relationships
    for file_data in inventory['files']:
        filepath = file_data['path']
        
        # Track what this file defines
        for struct in file_data.get('structs', []):
            relationships['defines'][filepath].append(('struct', struct['name']))
        for enum in file_data.get('enums', []):
            relationships['defines'][filepath].append(('enum', enum['name']))
        for trait in file_data.get('traits', []):
            relationships['defines'][filepath].append(('trait', trait['name']))
        for func in file_data.get('functions', []):
            relationships['defines'][filepath].append(('function', func['name']))
        
        # Track module declarations (pub mod) - these are direct file relationships
        for mod_decl in file_data.get('modules', []):
            mod_name = mod_decl['name']
            # Try to find the corresponding mod.rs or {mod_name}.rs file
            current_dir = os.path.dirname(filepath) if filepath != 'src/lib.rs' else 'src'
            
            # Check for mod.rs in subdirectory
            mod_file_path = os.path.join(current_dir, mod_name, 'mod.rs')
            if mod_file_path in files_by_path:
                relationships['imports'][filepath].append(mod_file_path)
            
            # Check for {mod_name}.rs in same directory
            mod_file_path2 = os.path.join(current_dir, f'{mod_name}.rs')
            if mod_file_path2 in files_by_path:
                relationships['imports'][filepath].append(mod_file_path2)
        
        # Track imports
        for imp in file_data.get('imports', []):
            import_path = imp['path']
            # Try to resolve to actual file
            resolved = resolve_module_path(import_path, filepath)
            if resolved and resolved in files_by_path:
                if resolved not in relationships['imports'][filepath]:
                    relationships['imports'][filepath].append(resolved)
            elif resolved and os.path.exists(resolved):
                # File exists but not in our inventory (might be external)
                pass
        
        # Track impl blocks
        for impl_block in file_data.get('impls', []):
            if 'for' in impl_block:
                # impl Trait for Type
                trait_name = impl_block.get('trait', '')
                type_name = impl_block.get('for', '')
                if trait_name in entity_locations and type_name in entity_locations:
                    relationships['implements'][filepath].append({
                        'trait': trait_name,
                        'trait_file': entity_locations[trait_name],
                        'type': type_name,
                        'type_file': entity_locations[type_name]
                    })
    
    return relationships

def find_orphan_entities(inventory: Dict[str, Any], relationships: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Find entities that are not used/imported."""
    orphans = []
    
    files_by_path = {f['path']: f for f in inventory['files']}
    all_imported_files = set()
    for imported_files in relationships['imports'].values():
        all_imported_files.update(imported_files)
    
    for file_data in inventory['files']:
        filepath = file_data['path']
        
        # Skip if file is imported
        if filepath in all_imported_files:
            continue
        
        # Check if file has any exports or public items
        has_public = False
        for struct in file_data.get('structs', []):
            if struct.get('public'):
                has_public = True
                break
        
        if not has_public and filepath not in all_imported_files:
            # Check if it's a main entry point
            if filepath == 'src/lib.rs' or filepath == 'Cargo.toml':
                continue
            orphans.append({
                'file': filepath,
                'reason': 'No imports found'
            })
    
    return orphans

def find_stale_files(inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Find files not modified in last 6 months."""
    stale = []
    six_months_ago = datetime.now() - timedelta(days=180)
    
    for file_data in inventory['files']:
        last_modified = file_data.get('last_modified', '')
        if last_modified:
            try:
                mod_date = datetime.strptime(last_modified.split()[0], '%Y-%m-%d')
                if mod_date < six_months_ago:
                    stale.append({
                        'file': file_data['path'],
                        'last_modified': last_modified,
                        'days_old': (datetime.now() - mod_date).days
                    })
            except:
                pass
    
    return sorted(stale, key=lambda x: x.get('days_old', 0), reverse=True)

def detect_circular_dependencies(relationships: Dict[str, Any]) -> List[List[str]]:
    """Detect circular import dependencies."""
    cycles = []
    visited = set()
    rec_stack = set()
    
    def dfs(node, path):
        if node in rec_stack:
            # Found cycle
            cycle_start = path.index(node)
            cycle = path[cycle_start:] + [node]
            if len(cycle) > 2:  # Only report cycles of 3+ nodes
                cycles.append(cycle)
            return
        
        if node in visited:
            return
        
        visited.add(node)
        rec_stack.add(node)
        
        for neighbor in relationships['imports'].get(node, []):
            dfs(neighbor, path + [node])
        
        rec_stack.remove(node)
    
    for filepath in relationships['imports']:
        if filepath not in visited:
            dfs(filepath, [])
    
    return cycles

def sanitize_id(text: str) -> str:
    """Convert file path to safe Mermaid node ID."""
    return text.replace('/', '_').replace('.', '_').replace('-', '_').replace('\\', '_')

def generate_mermaid_graph(inventory: Dict[str, Any], relationships: Dict[str, Any]) -> str:
    """Generate Mermaid graph syntax."""
    lines = ['graph TD;']
    
    # Define subgraphs
    lines.append('    subgraph SourceCode["Source & Logic"]')
    
    # Group files by category
    core_files = []
    wami_files = []
    service_files = []
    store_files = []
    provider_files = []
    other_files = []
    
    for file_data in inventory['files']:
        path = file_data['path']
        if not path.startswith('src/'):
            continue
        
        if path.startswith('src/arn/') or path.startswith('src/context') or path.startswith('src/error') or path.startswith('src/types'):
            core_files.append(path)
        elif path.startswith('src/wami/'):
            wami_files.append(path)
        elif path.startswith('src/service/'):
            service_files.append(path)
        elif path.startswith('src/store/'):
            store_files.append(path)
        elif path.startswith('src/provider/'):
            provider_files.append(path)
        else:
            other_files.append(path)
    
    # Define all nodes first
    node_ids = {}
    
    # Core nodes
    for path in sorted(core_files):
        node_id = sanitize_id(path)
        node_ids[path] = node_id
        display_name = path.replace('src/', '')
        lines.append(f'        {node_id}["{display_name}"]:::fileNode')
    
    # WAMI nodes
    lines.append('    end')
    lines.append('    subgraph WAMILayer["WAMI Layer (Domain Models)"]')
    for path in sorted(wami_files):
        node_id = sanitize_id(path)
        node_ids[path] = node_id
        display_name = path.replace('src/wami/', 'wami/')
        lines.append(f'        {node_id}["{display_name}"]:::fileNode')
    
    # Service nodes
    lines.append('    end')
    lines.append('    subgraph ServiceLayer["Service Layer (Orchestration)"]')
    for path in sorted(service_files):
        node_id = sanitize_id(path)
        node_ids[path] = node_id
        display_name = path.replace('src/service/', 'service/')
        lines.append(f'        {node_id}["{display_name}"]:::fileNode')
    
    # Store nodes
    lines.append('    end')
    lines.append('    subgraph StoreLayer["Store Layer (Persistence)"]')
    for path in sorted(store_files):
        node_id = sanitize_id(path)
        node_ids[path] = node_id
        display_name = path.replace('src/store/', 'store/')
        lines.append(f'        {node_id}["{display_name}"]:::fileNode')
    
    # Provider nodes
    lines.append('    end')
    lines.append('    subgraph ProviderLayer["Provider Layer (Cloud Integration)"]')
    for path in sorted(provider_files):
        node_id = sanitize_id(path)
        node_ids[path] = node_id
        display_name = path.replace('src/provider/', 'provider/')
        lines.append(f'        {node_id}["{display_name}"]:::fileNode')
    
    lines.append('    end')
    lines.append('    subgraph BuildDeps["Build & Dependencies"]')
    
    # Add Cargo.toml and lib.rs
    for file_data in inventory['files']:
        path = file_data['path']
        if path == 'Cargo.toml' or path == 'src/lib.rs':
            node_id = sanitize_id(path)
            node_ids[path] = node_id
            lines.append(f'        {node_id}["{path}"]:::fileNode')
    
    lines.append('    end')
    
    # Now define all relationships
    lines.append('')
    lines.append('    %% Relationships')
    
    # Import relationships
    for source_file, imported_files in relationships['imports'].items():
        if source_file not in node_ids:
            continue
        source_id = node_ids[source_file]
        for imported_file in imported_files:
            if imported_file in node_ids:
                target_id = node_ids[imported_file]
                lines.append(f'    {source_id} --"imports"--> {target_id}')
    
    return '\n'.join(lines)

def generate_analysis_report(inventory: Dict[str, Any], relationships: Dict[str, Any], 
                             orphans: List[Dict[str, Any]], stale: List[Dict[str, Any]], 
                             cycles: List[List[str]]) -> str:
    """Generate HTML sidebar report."""
    html_parts = []
    
    # Orphan entities
    html_parts.append('<h3>Orphan Entities</h3>')
    if orphans:
        html_parts.append('<ul>')
        for orphan in orphans[:20]:  # Limit to 20
            html_parts.append(f'<li><strong>{orphan["file"]}</strong><br/>')
            html_parts.append(f'<small>{orphan.get("reason", "Not referenced")}</small></li>')
        html_parts.append('</ul>')
        if len(orphans) > 20:
            html_parts.append(f'<p><em>... and {len(orphans) - 20} more</em></p>')
    else:
        html_parts.append('<p>No orphan entities found.</p>')
    
    # Stale files
    html_parts.append('<h3>Stale Files</h3>')
    if stale:
        html_parts.append('<ul>')
        for file_info in stale[:15]:  # Limit to 15
            html_parts.append(f'<li><strong>{file_info["file"]}</strong><br/>')
            html_parts.append(f'<small>Last modified: {file_info["last_modified"]} ({file_info["days_old"]} days ago)</small></li>')
        html_parts.append('</ul>')
        if len(stale) > 15:
            html_parts.append(f'<p><em>... and {len(stale) - 15} more</em></p>')
    else:
        html_parts.append('<p>No stale files found.</p>')
    
    # Circular dependencies
    html_parts.append('<h3>Circular Dependencies</h3>')
    if cycles:
        html_parts.append('<ul>')
        for cycle in cycles[:10]:  # Limit to 10
            cycle_str = ' → '.join([os.path.basename(f) for f in cycle])
            html_parts.append(f'<li><strong>Cycle detected:</strong><br/><small>{cycle_str}</small></li>')
        html_parts.append('</ul>')
    else:
        html_parts.append('<p>No circular dependencies detected.</p>')
    
    # Statistics
    html_parts.append('<h3>Statistics</h3>')
    html_parts.append('<ul>')
    html_parts.append(f'<li>Total files: {inventory["metadata"]["total_files"]}</li>')
    
    total_structs = sum(len(f.get('structs', [])) for f in inventory['files'])
    total_traits = sum(len(f.get('traits', [])) for f in inventory['files'])
    total_functions = sum(len(f.get('functions', [])) for f in inventory['files'])
    
    html_parts.append(f'<li>Total structs: {total_structs}</li>')
    html_parts.append(f'<li>Total traits: {total_traits}</li>')
    html_parts.append(f'<li>Total functions: {total_functions}</li>')
    html_parts.append(f'<li>Total import relationships: {sum(len(v) for v in relationships["imports"].values())}</li>')
    html_parts.append('</ul>')
    
    return '\n'.join(html_parts)

if __name__ == '__main__':
    print("Loading inventory...")
    inventory = load_latest_inventory()
    
    print("Building relationships...")
    relationships = build_relationships(inventory)
    
    print("Finding orphan entities...")
    orphans = find_orphan_entities(inventory, relationships)
    
    print("Finding stale files...")
    stale = find_stale_files(inventory)
    
    print("Detecting circular dependencies...")
    cycles = detect_circular_dependencies(relationships)
    
    print("Generating Mermaid graph...")
    mermaid_graph = generate_mermaid_graph(inventory, relationships)
    
    print("Generating analysis report...")
    analysis_report = generate_analysis_report(inventory, relationships, orphans, stale, cycles)
    
    # Save Mermaid source
    with open('knowledge_graph.mmd', 'w') as f:
        f.write(mermaid_graph)
    print("Saved knowledge_graph.mmd")
    
    # Save analysis report for later
    with open('codeanalysis/analysis_report.html', 'w') as f:
        f.write(analysis_report)
    
    # Generate final HTML
    html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Codebase Analysis Report</title>
    <style>
        body {{ font-family: sans-serif; display: flex; flex-direction: column; align-items: center; }}
        #report-container {{ display: flex; width: 98%; gap: 16px; margin-top: 20px; }}
        #graph-container {{ flex-grow: 1; border: 1px solid #ccc; padding: 10px; border-radius: 8px; }}
        #sidebar {{ width: 400px; flex-shrink: 0; border: 1px solid #ccc; padding: 10px; border-radius: 8px; max-height: 85vh; overflow-y: auto; }}
        h1, h2 {{ color: #333; }}
        #analysis-report ul {{ list-style-type: none; padding-left: 0; }}
        #analysis-report h3 {{ border-bottom: 1px solid #eee; padding-bottom: 5px; margin-top: 20px;}}
        #analysis-report li {{ background-color: #f9f9f9; border: 1px solid #eee; padding: 8px; margin-bottom: 5px; border-radius: 4px; }}
        #analysis-report strong {{ color: #c0392b; }}
        /* Mermaid Node Styling */
        .classNode {{ fill:#DDA0DD; stroke:#8A2BE2; stroke-width:2px; }}
        .functionNode {{ fill:#87CEEB; stroke:#4682B4; stroke-width:2px; }}
        .dependencyNode {{ fill:#90EE90; stroke:#2E8B57; stroke-width:2px; }}
        .fileNode {{ fill:#FFFACD; stroke:#FFD700; stroke-width:2px; }}
    </style>
</head>
<body>
    <h1>Codebase Analysis Report</h1>
    <div id="report-container">
        <div id="graph-container">
            <h2>Knowledge Graph</h2>
            <!-- The raw source for this graph is also saved in knowledge_graph.mmd -->
            <pre class="mermaid">
{merimaid_content}
            </pre>
        </div>
        <div id="sidebar">
            <h2>Analysis & Refactoring</h2>
            <div id="analysis-report">
{analysis_content}
            </div>
        </div>
    </div>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        
        mermaid.initialize({{
            startOnLoad: true,
            theme: 'default',
            mermaid: {{
              curve: 'basis'
            }},
            htmlLabels: true
        }});
    </script>
</body>
</html>'''
    
    final_html = html_template.format(
        merimaid_content=mermaid_graph,
        analysis_content=analysis_report
    )
    
    with open('knowledge_graph.html', 'w') as f:
        f.write(final_html)
    
    print("Saved knowledge_graph.html")
    print("\nAnalysis complete!")
    print(f"  - Orphan entities: {len(orphans)}")
    print(f"  - Stale files: {len(stale)}")
    print(f"  - Circular dependencies: {len(cycles)}")

