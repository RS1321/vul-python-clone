"""
Code Repair Tool

Static analysis tool that normalizes LLM-generated fixes:
- Hoists in-function imports to module level
- Deduplicates imports
- Maintains correct ordering

This allows the LLM to focus on security logic while the tool handles code style.
"""

import ast
import re
from pathlib import Path
from typing import List, Set, Tuple


class CodeRepair:
    """Repairs common LLM code generation issues"""
    
    def __init__(self):
        self.repaired_files = []
    
    def hoist_imports(self, file_path: Path) -> Tuple[bool, str, dict]:
        """
        Hoist imports from inside functions to module level
        
        Args:
            file_path: Path to Python file
        
        Returns:
            (modified: bool, message: str, stats: dict)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            # Parse AST
            try:
                tree = ast.parse(source)
            except SyntaxError as e:
                return False, f"Syntax error in file: {e}", {}
            
            # Find imports at module level
            module_imports = set()
            module_import_lines = []
            
            for node in tree.body:
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_imports.add(('import', alias.name, alias.asname))
                        module_import_lines.append(node.lineno)
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        module_imports.add(('from', node.module, alias.name, alias.asname))
                        module_import_lines.append(node.lineno)
            
            # Find imports inside functions
            in_function_imports = []
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for child in node.body:
                        if isinstance(child, ast.Import):
                            for alias in child.names:
                                import_tuple = ('import', alias.name, alias.asname)
                                if import_tuple not in module_imports:
                                    in_function_imports.append({
                                        'line': child.lineno,
                                        'type': 'import',
                                        'module': alias.name,
                                        'as': alias.asname,
                                        'code': f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                                    })
                        elif isinstance(child, ast.ImportFrom):
                            for alias in child.names:
                                import_tuple = ('from', child.module, alias.name, alias.asname)
                                if import_tuple not in module_imports:
                                    in_function_imports.append({
                                        'line': child.lineno,
                                        'type': 'from',
                                        'module': child.module,
                                        'name': alias.name,
                                        'as': alias.asname,
                                        'code': f"from {child.module} import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                                    })
            
            if not in_function_imports:
                return False, "No in-function imports found", {'hoisted': 0}
            
            # Remove in-function imports and hoist to module level
            lines = source.split('\n')
            
            # Remove in-function import lines (reverse order to maintain line numbers)
            for import_info in sorted(in_function_imports, key=lambda x: x['line'], reverse=True):
                line_idx = import_info['line'] - 1
                if line_idx < len(lines):
                    # Remove the import line and any immediately following blank lines
                    del lines[line_idx]
            
            # Find insertion point (after last module-level import)
            if module_import_lines:
                insert_at = max(module_import_lines)
            else:
                # Insert after module docstring if exists, otherwise at top
                insert_at = 0
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        if stripped.startswith('"""') or stripped.startswith("'''"):
                            # Skip docstring
                            quote = '"""' if stripped.startswith('"""') else "'''"
                            if stripped.count(quote) >= 2:
                                insert_at = i + 1
                                break
                            else:
                                # Multi-line docstring
                                for j in range(i + 1, len(lines)):
                                    if quote in lines[j]:
                                        insert_at = j + 1
                                        break
                                break
                        else:
                            insert_at = i
                            break
            
            # Insert hoisted imports
            hoisted_lines = [imp['code'] for imp in in_function_imports]
            
            # Insert at appropriate position
            lines.insert(insert_at, '\n'.join(hoisted_lines))
            
            # Write repaired file
            repaired_source = '\n'.join(lines)
            
            # Validate syntax
            try:
                ast.parse(repaired_source)
            except SyntaxError as e:
                return False, f"Repaired code has syntax error: {e}", {}
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(repaired_source)
            
            stats = {
                'hoisted': len(in_function_imports),
                'imports': [imp['code'] for imp in in_function_imports]
            }
            
            return True, f"Hoisted {len(in_function_imports)} import(s) to module level", stats
        
        except Exception as e:
            return False, f"Error during repair: {str(e)}", {}
    
    def repair_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Apply all repair operations to a file
        
        Args:
            file_path: Path to Python file
        
        Returns:
            (modified: bool, messages: List[str])
        """
        messages = []
        modified = False
        
        # Hoist imports
        hoisted, msg, stats = self.hoist_imports(file_path)
        if hoisted:
            modified = True
            messages.append(f"✓ {msg}")
            if stats.get('imports'):
                for imp in stats['imports']:
                    messages.append(f"  • {imp}")
        
        # Could add more repairs here:
        # - Remove duplicate code blocks
        # - Fix common syntax patterns
        # - Normalize debug=True to debug=False
        
        return modified, messages


def repair_code(file_path: str) -> Tuple[bool, List[str]]:
    """
    Convenience function to repair a single file
    
    Args:
        file_path: Path to file to repair
    
    Returns:
        (modified: bool, messages: List[str])
    """
    repairer = CodeRepair()
    return repairer.repair_file(Path(file_path))


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python code_repair.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    modified, messages = repair_code(file_path)
    
    if modified:
        print(f"✓ Repaired: {file_path}")
        for msg in messages:
            print(f"  {msg}")
    else:
        print(f"• No repairs needed: {file_path}")
