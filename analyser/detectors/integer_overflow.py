"""
integer_overflow.py
Detects raw arithmetic operations that do not use checked or saturating math.
Severity: HIGH
"""

import re
from analyser.parser import get_node_text, get_line_number, walk_tree

# Tree-sitter node types for binary arithmetic
ARITHMETIC_OPS = {'+', '-', '*', '/'}

# Method calls that indicate safe math is already in use
SAFE_MATH_PATTERNS = [
    r'\.checked_add\s*\(',
    r'\.checked_sub\s*\(',
    r'\.checked_mul\s*\(',
    r'\.checked_div\s*\(',
    r'\.saturating_add\s*\(',
    r'\.saturating_sub\s*\(',
    r'\.saturating_mul\s*\(',
    r'\.wrapping_add\s*\(',
    r'\.wrapping_sub\s*\(',
    r'\.wrapping_mul\s*\(',
    r'u64::MAX',
    r'i64::MAX',
    r'u128',
]

# Integer-like type names (to avoid flagging float arithmetic)
INTEGER_TYPES = {'u8', 'u16', 'u32', 'u64', 'u128', 'usize',
                 'i8', 'i16', 'i32', 'i64', 'i128', 'isize'}


def _get_enclosing_function_name(node, raw: bytes) -> str:
    cursor = node.parent
    while cursor is not None:
        if cursor.type == 'function_item':
            name_node = cursor.child_by_field_name('name')
            if name_node:
                return get_node_text(name_node, raw)
        cursor = cursor.parent
    return 'unknown'


def _expression_uses_safe_math(stmt_node, raw: bytes) -> bool:
    stmt_text = get_node_text(stmt_node, raw)
    return any(re.search(p, stmt_text) for p in SAFE_MATH_PATTERNS)


def detect_integer_overflow(tree, raw: bytes) -> list:
    findings = []
    seen = set()  # deduplicate by (fn_name, line)

    for node in walk_tree(tree.root_node):
        if node.type != 'binary_expression':
            continue

        op_node = node.child_by_field_name('operator')
        if op_node is None:
            continue
        op = get_node_text(op_node, raw).strip()
        if op not in ARITHMETIC_OPS:
            continue

        # Skip if the enclosing statement already uses safe math
        if _expression_uses_safe_math(node, raw):
            continue

        # Walk up to the enclosing let/expression statement for context
        stmt = node.parent
        while stmt is not None and stmt.type not in (
            'let_declaration', 'expression_statement',
            'assignment_expression', 'compound_assignment_expr',
        ):
            stmt = stmt.parent

        if stmt and _expression_uses_safe_math(stmt, raw):
            continue

        fn_name = _get_enclosing_function_name(node, raw)
        line = get_line_number(node)
        key = (fn_name, line)
        if key in seen:
            continue
        seen.add(key)

        expr_text = get_node_text(node, raw)
        left_text = get_node_text(node.child_by_field_name('left'), raw) if node.child_by_field_name('left') else 'a'
        right_text = get_node_text(node.child_by_field_name('right'), raw) if node.child_by_field_name('right') else 'b'

        safe_method = {
            '+': 'checked_add',
            '-': 'checked_sub',
            '*': 'checked_mul',
            '/': 'checked_div',
        }[op]

        findings.append({
            'vulnerability_type': 'Integer Overflow / Underflow',
            'severity': 'HIGH',
            'line_number': line,
            'function_name': fn_name,
            'description': (
                f"Raw arithmetic operator '{op}' used in expression "
                f"'{expr_text[:80]}' without checked or saturating math. "
                "In Rust release builds this wraps silently on overflow."
            ),
            'impact': (
                "An attacker can craft inputs that overflow/underflow the "
                "integer, bypassing balance checks or corrupting accounting "
                "values (e.g. setting a balance to near-zero or near-max)."
            ),
            'recommendation': (
                f"Replace raw '{op}' with '.{safe_method}()' and handle the "
                "None case, or use '.saturating_add/sub/mul()' if truncation "
                "is an acceptable behaviour. Example: "
                f"let result = {left_text}.{safe_method}({right_text})"
                ".ok_or(ErrorCode::Overflow)?;"
            ),
            'vulnerable_code': expr_text,
            'secure_code': (
                f"let result = {left_text}\n"
                f"    .{safe_method}({right_text})\n"
                "    .ok_or(ErrorCode::Overflow)?;"
            ),
        })

    return findings
