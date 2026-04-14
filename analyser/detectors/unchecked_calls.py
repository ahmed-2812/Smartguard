"""
unchecked_calls.py
Detects external calls whose return values are ignored (not unwrapped / matched).
Severity: HIGH
"""

import re
from analyser.parser import get_node_text, get_line_number, walk_tree

EXTERNAL_CALL_NAMES = {
    'invoke', 'invoke_signed', 'transfer', 'sol_transfer',
    'create_account', 'initialize_account', 'mint_to', 'burn',
    'close_account', 'set_authority', 'approve', 'revoke',
    'thaw_account', 'freeze_account', 'sync_native',
}

# Patterns that indicate the return value IS being handled
HANDLED_PATTERNS = [
    r'\?\s*;',          # foo()?;
    r'\.unwrap\s*\(',   # foo().unwrap()
    r'\.expect\s*\(',   # foo().expect(...)
    r'\.unwrap_or',     # foo().unwrap_or(...)
    r'match\s+',        # match foo() { ... }
    r'if\s+let\s+',     # if let Ok(...) = foo()
    r'let\s+\w+\s*=',   # let result = foo()
    r'=>\s*',           # match arm
]


def _return_is_handled(stmt_text: str) -> bool:
    return any(re.search(p, stmt_text) for p in HANDLED_PATTERNS)


def _get_enclosing_function_name(node, raw: bytes) -> str:
    cursor = node.parent
    while cursor is not None:
        if cursor.type == 'function_item':
            name_node = cursor.child_by_field_name('name')
            if name_node:
                return get_node_text(name_node, raw)
        cursor = cursor.parent
    return 'unknown'


def _is_target_external_call(node, raw: bytes) -> bool:
    if node.type != 'call_expression':
        return False
    func = node.child_by_field_name('function')
    if func is None:
        return False
    text = get_node_text(func, raw)
    base = text.split('::')[-1].strip()
    return base in EXTERNAL_CALL_NAMES


def detect_unchecked_calls(tree, raw: bytes) -> list:
    findings = []
    seen = set()

    for node in walk_tree(tree.root_node):
        if not _is_target_external_call(node, raw):
            continue

        # Walk up to expression_statement — if the call IS the whole statement
        # then its return value is dropped
        parent = node.parent
        if parent is None:
            continue

        # If the call is the direct child of an expression_statement it is discarded
        if parent.type != 'expression_statement':
            continue

        # Get the full statement text to check for ? / unwrap etc.
        stmt_text = get_node_text(parent, raw)
        if _return_is_handled(stmt_text):
            continue

        fn_name = _get_enclosing_function_name(node, raw)
        line = get_line_number(node)
        key = (fn_name, line)
        if key in seen:
            continue
        seen.add(key)

        call_text = get_node_text(node, raw)
        findings.append({
            'vulnerability_type': 'Unchecked External Call',
            'severity': 'HIGH',
            'line_number': line,
            'function_name': fn_name,
            'description': (
                f"The return value of external call '{call_text[:80]}' is "
                "discarded. If the call fails silently, subsequent logic "
                "will execute as if it succeeded."
            ),
            'impact': (
                "A failed CPI (e.g. transfer, create_account) that goes "
                "unchecked allows execution to continue in an inconsistent "
                "state, potentially leading to fund loss or data corruption."
            ),
            'recommendation': (
                "Propagate the result with '?' or explicitly match/unwrap it. "
                "In Anchor-based programs use the Result<()> return type and "
                "append '?' to every CPI call so errors bubble up automatically."
            ),
            'vulnerable_code': (
                f"// Return value ignored\n"
                f"{call_text};"
            ),
            'secure_code': (
                f"// Propagate error with ?\n"
                f"{call_text}?;"
            ),
        })

    return findings
