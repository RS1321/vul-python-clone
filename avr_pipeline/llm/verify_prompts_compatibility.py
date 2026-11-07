"""
Verification script to ensure prompts.py and new_prompts.py are drop-in compatible.

This script tests that both modules:
1. Export the same functions
2. Have identical function signatures
3. Can be dynamically imported
4. Return valid prompts with the same structure
"""

import importlib
import inspect
import json


def verify_module_interface(module_name: str) -> dict:
    """
    Verify a prompts module has the required interface.
    
    Returns:
        dict: Module attributes and signatures
    """
    print(f"\\n{'='*70}")
    print(f"VERIFYING: {module_name}")
    print(f"{'='*70}")
    
    try:
        module = importlib.import_module(module_name)
        print(f"✓ Successfully imported '{module_name}'")
    except ImportError as e:
        print(f"✗ Failed to import '{module_name}': {e}")
        return None
    
    # Check required attributes
    required_attrs = {
        'build_initial_fix_prompt': 'function',
        'build_refinement_prompt': 'function',
        'SYSTEM_PROMPT': 'str'
    }
    
    results = {}
    
    for attr_name, expected_type in required_attrs.items():
        if hasattr(module, attr_name):
            attr = getattr(module, attr_name)
            
            if expected_type == 'function':
                if callable(attr):
                    sig = inspect.signature(attr)
                    results[attr_name] = {
                        'present': True,
                        'type': 'function',
                        'signature': str(sig)
                    }
                    print(f"✓ {attr_name}{sig}")
                else:
                    results[attr_name] = {'present': True, 'type': 'not callable'}
                    print(f"✗ {attr_name} is not callable")
            
            elif expected_type == 'str':
                if isinstance(attr, str):
                    results[attr_name] = {
                        'present': True,
                        'type': 'str',
                        'length': len(attr)
                    }
                    print(f"✓ {attr_name} (string, {len(attr)} chars)")
                else:
                    results[attr_name] = {'present': True, 'type': type(attr).__name__}
                    print(f"✗ {attr_name} is not a string")
        else:
            results[attr_name] = {'present': False}
            print(f"✗ {attr_name} not found")
    
    return results


def test_function_compatibility(module1_name: str, module2_name: str) -> bool:
    """
    Test that two modules have compatible function signatures.
    
    Returns:
        bool: True if compatible, False otherwise
    """
    print(f"\\n{'='*70}")
    print(f"COMPATIBILITY CHECK: {module1_name} vs {module2_name}")
    print(f"{'='*70}")
    
    try:
        module1 = importlib.import_module(module1_name)
        module2 = importlib.import_module(module2_name)
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    
    # Compare function signatures
    functions_to_check = ['build_initial_fix_prompt', 'build_refinement_prompt']
    
    all_compatible = True
    for func_name in functions_to_check:
        func1 = getattr(module1, func_name, None)
        func2 = getattr(module2, func_name, None)
        
        if func1 is None or func2 is None:
            print(f"✗ {func_name}: Missing in one or both modules")
            all_compatible = False
            continue
        
        sig1 = inspect.signature(func1)
        sig2 = inspect.signature(func2)
        
        if str(sig1) == str(sig2):
            print(f"✓ {func_name}: Signatures match")
            print(f"  {sig1}")
        else:
            print(f"✗ {func_name}: Signatures differ")
            print(f"  {module1_name}: {sig1}")
            print(f"  {module2_name}: {sig2}")
            all_compatible = False
    
    return all_compatible


def test_prompt_generation(module_name: str) -> bool:
    """
    Test that a module can generate valid prompts.
    
    Returns:
        bool: True if successful, False otherwise
    """
    print(f"\\n{'='*70}")
    print(f"PROMPT GENERATION TEST: {module_name}")
    print(f"{'='*70}")
    
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    
    # Create mock finding data
    mock_finding = {
        "finding_id": "test-finding-001",
        "finding_number": "FINDING 001",
        "baseline_severity": "high",
        "sast": {
            "present": True,
            "tool": "codeql",
            "rule_id": "py/test-rule",
            "severity": "high",
            "confidence": "high",
            "cwe": "CWE-089",
            "description": "Test vulnerability description",
            "location": {
                "file_path": "test.py",
                "start_line": 10,
                "end_line": 12,
                "function": "test_function"
            },
            "data_flow": {
                "full_path": [
                    {"step": 1, "location": "test.py:5", "node": "user_input"},
                    {"step": 2, "location": "test.py:10", "node": "vulnerable_call"}
                ]
            }
        },
        "dast": {
            "present": False,
            "reason": "not scanned"
        }
    }
    
    mock_analysis = {
        "description": "Test analysis",
        "severity": "high"
    }
    
    mock_code = """def test_function(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)
    return cursor.fetchall()"""
    
    try:
        # Test initial prompt generation
        initial_prompt = module.build_initial_fix_prompt(
            finding=mock_finding,
            analysis=mock_analysis,
            vulnerable_function_code=mock_code,
            file_path="test.py"
        )
        
        print(f"✓ build_initial_fix_prompt succeeded")
        print(f"  Prompt length: {len(initial_prompt)} chars")
        
        # Verify prompt contains key information
        required_in_prompt = [
            "FINDING 001",
            "CWE-089",
            "test.py",
            "test_function"
        ]
        
        missing = []
        for item in required_in_prompt:
            if item not in initial_prompt:
                missing.append(item)
        
        if missing:
            print(f"✗ Prompt missing required content: {missing}")
            return False
        else:
            print(f"✓ Prompt contains all required information")
        
        # Test refinement prompt generation
        refinement_prompt = module.build_refinement_prompt(
            original_context="Original prompt",
            previous_fix="Previous fix code",
            validation_failures="Syntax error on line 5",
            finding=mock_finding,
            iteration=2,
            max_iterations=3
        )
        
        print(f"✓ build_refinement_prompt succeeded")
        print(f"  Prompt length: {len(refinement_prompt)} chars")
        
        return True
        
    except Exception as e:
        print(f"✗ Error generating prompts: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all verification tests."""
    print("\\n" + "="*70)
    print("PROMPTS MODULE COMPATIBILITY VERIFICATION")
    print("="*70)
    
    # Test both modules independently
    prompts_results = verify_module_interface('prompts')
    new_prompts_results = verify_module_interface('new_prompts')
    
    if prompts_results is None or new_prompts_results is None:
        print("\\n✗ FAILED: One or both modules could not be loaded")
        return False
    
    # Test compatibility between modules
    compatible = test_function_compatibility('prompts', 'new_prompts')
    
    # Test prompt generation for both modules
    prompts_works = test_prompt_generation('prompts')
    new_prompts_works = test_prompt_generation('new_prompts')
    
    # Final summary
    print(f"\\n{'='*70}")
    print("VERIFICATION SUMMARY")
    print(f"{'='*70}")
    print(f"prompts.py interface:      {'✓ PASS' if prompts_results else '✗ FAIL'}")
    print(f"new_prompts.py interface:  {'✓ PASS' if new_prompts_results else '✗ FAIL'}")
    print(f"Signature compatibility:   {'✓ PASS' if compatible else '✗ FAIL'}")
    print(f"prompts.py generation:     {'✓ PASS' if prompts_works else '✗ FAIL'}")
    print(f"new_prompts.py generation: {'✓ PASS' if new_prompts_works else '✗ FAIL'}")
    
    all_pass = all([
        prompts_results,
        new_prompts_results,
        compatible,
        prompts_works,
        new_prompts_works
    ])
    
    if all_pass:
        print(f"\\n{'='*70}")
        print("✓ ALL TESTS PASSED - new_prompts.py is a drop-in replacement")
        print(f"{'='*70}")
        print("\\nTo use new_prompts.py, update config.json:")
        print('  "pipeline": {')
        print('    "prompts_module": "new_prompts"')
        print('  }')
    else:
        print(f"\\n{'='*70}")
        print("✗ SOME TESTS FAILED - Please review issues above")
        print(f"{'='*70}")
    
    return all_pass


if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)
