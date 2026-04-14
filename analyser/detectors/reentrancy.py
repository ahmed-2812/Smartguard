"""
reentrancy.py
Detects reentrancy: an external call (invoke / invoke_signed / transfer)
that occurs BEFORE a state variable is written within the same function.
Severity: CRITICAL
"""

from analyser.parser import get_node_text, get_line_number, walk_tree

EXTERNAL_CALL_NAMES = {'invoke', 'invoke_signed', 'transfer', 'sol_transfer'}

# Keywords that indicate a state/account field is being written
STATE_WRITE_INDICATORS = {
    'amount', 'balance', 'lamports', 'data', 'owner', 'is_closed',
    'initialized', 'authority', 'bump', 'total', 'count', 'supply',
}


def _is_external_call(node, raw: bytes) -> bool:
    """Return True if node is a call expression whose function name is an external call."""
    if node.type != 'call_expression':
        return False
    func = node.child_by_field_name('function')
    if func is None:
        return False
    text = get_node_text(func, raw)
    # Strip path prefix (e.g. system_program::transfer -> transfer)
    base = text.split('::')[-1].strip()
    return base in EXTERNAL_CALL_NAMES


def _is_state_write(node, raw: bytes) -> bool:
    """Return True if this node looks like a state variable assignment."""
    if node.type not in ('assignment_expression', 'compound_assignment_expr'):
        return False
    left = node.child_by_field_name('left')
    if left is None:
        return False
    left_text = get_node_text(left, raw).lower()
    return any(kw in left_text for kw in STATE_WRITE_INDICATORS)


def _get_enclosing_function_name(node, raw: bytes) -> str:
    cursor = node.parent
    while cursor is not None:
        if cursor.type == 'function_item':
            name_node = cursor.child_by_field_name('name')
            if name_node:
                return get_node_text(name_node, raw)
        cursor = cursor.parent
    return 'unknown'


def _collect_statements(fn_node):
    """Collect top-level statements from a function body in order."""
    body = fn_node.child_by_field_name('body')
    if body is None:
        return []
    stmts = []
    for child in body.children:
        if child.type not in ('{', '}', 'line_comment', 'block_comment'):
            stmts.append(child)
    return stmts


def detect_reentrancy(tree, raw: bytes) -> list:
    findings = []

    for fn_node in walk_tree(tree.root_node):
        if fn_node.type != 'function_item':
            continue

        name_node = fn_node.child_by_field_name('name')
        fn_name = get_node_text(name_node, raw) if name_node else 'unknown'

        # Collect all external calls and state writes within this function
        ext_calls = []
        state_writes = []

        for node in walk_tree(fn_node):
            if _is_external_call(node, raw):
                ext_calls.append(node)
            if _is_state_write(node, raw):
                state_writes.append(node)

        if not ext_calls or not state_writes:
            continue

        # Flag if any external call appears at an earlier byte offset than a state write
        for call in ext_calls:
            for write in state_writes:
                if call.start_byte < write.start_byte:
                    call_text = get_node_text(call, raw)
                    write_text = get_node_text(write, raw)
                    findings.append({
                        'vulnerability_type': 'Reentrancy',
                        'severity': 'CRITICAL',
                        'line_number': get_line_number(call),
                        'function_name': fn_name,
                        'description': (
                            f"External call '{call_text[:80]}' is made before state "
                            f"variable '{write_text[:60]}' is updated. An attacker "
                            "may re-enter the program before state changes are committed."
                        ),
                        'impact': (
                            "An attacker can repeatedly invoke this function via a "
                            "malicious program before the contract updates its state, "
                            "potentially draining funds or corrupting data."
                        ),
                        'recommendation': (
                            "Apply the Checks-Effects-Interactions pattern: update all "
                            "state variables BEFORE making any external calls. Use "
                            "reentrancy guards (a boolean lock) when ordering cannot be changed."
                        ),
                        'vulnerable_code': (
                            f"// External call before state update\n"
                            f"{call_text}\n"
                            f"// State updated AFTER the call (vulnerable)\n"
                            f"{write_text}"
                        ),
                        'secure_code': (
                            f"// Update state FIRST\n"
                            f"{write_text}\n"
                            f"// Then make the external call\n"
                            f"{call_text}"
                        ),
                    })
                    break  # one finding per external call is enough
            else:
                continue
            break  # avoid duplicate findings for same function

    return findings
