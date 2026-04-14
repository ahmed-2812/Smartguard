"""
timestamp.py
Detects use of Clock::get() / unix_timestamp in conditional logic that
controls fund transfers or access decisions.
Severity: MEDIUM
"""

import re
from analyser.parser import get_node_text, get_line_number, walk_tree

CLOCK_PATTERNS = [
    r'Clock::get\s*\(',
    r'\.unix_timestamp',
    r'clock\.unix_timestamp',
    r'Clock\s*{',
    r'sysvar::clock',
]

# Conditions that indicate the timestamp is used in access/transfer logic
SENSITIVE_CONTEXT_PATTERNS = [
    r'\btransfer\b',
    r'\bwithdraw\b',
    r'\binvoke\b',
    r'\binvoke_signed\b',
    r'\bif\b',
    r'\bwhile\b',
    r'\brequire!\s*\(',
    r'\bassert!\s*\(',
    r'\bunlock\b',
    r'\bexpire',
    r'\bdeadline\b',
    r'\bvesting\b',
    r'\bclaim\b',
]


def _get_enclosing_function_name(node, raw: bytes) -> str:
    cursor = node.parent
    while cursor is not None:
        if cursor.type == 'function_item':
            name_node = cursor.child_by_field_name('name')
            if name_node:
                return get_node_text(name_node, raw)
        cursor = cursor.parent
    return 'unknown'


def _enclosing_fn_text(node, raw: bytes) -> str:
    cursor = node.parent
    while cursor is not None:
        if cursor.type == 'function_item':
            return get_node_text(cursor, raw)
        cursor = cursor.parent
    return ''


def detect_timestamp(tree, raw: bytes) -> list:
    findings = []
    seen = set()

    raw_str = raw.decode('utf-8', errors='replace')

    for node in walk_tree(tree.root_node):
        node_text = get_node_text(node, raw)

        # Look for nodes that reference clock/timestamp
        if not any(re.search(p, node_text) for p in CLOCK_PATTERNS):
            continue

        # Skip tiny nodes (identifiers inside expressions — we want larger context)
        if len(node_text) < 5:
            continue

        fn_text = _enclosing_fn_text(node, raw)
        if not fn_text:
            continue

        # Only flag if the function also contains sensitive operations
        if not any(re.search(p, fn_text) for p in SENSITIVE_CONTEXT_PATTERNS):
            continue

        fn_name = _get_enclosing_function_name(node, raw)
        line = get_line_number(node)
        key = (fn_name, line)
        if key in seen:
            continue
        seen.add(key)

        findings.append({
            'vulnerability_type': 'Timestamp Dependence',
            'severity': 'MEDIUM',
            'line_number': line,
            'function_name': fn_name,
            'description': (
                f"The function '{fn_name}' uses 'unix_timestamp' from the "
                "Solana Clock sysvar in logic that controls access or fund "
                "transfers. Validators can manipulate the slot timestamp by "
                "a small margin."
            ),
            'impact': (
                "A malicious validator can skew the reported timestamp by "
                "several seconds to minutes, allowing them to bypass "
                "time-locks, claim vesting rewards early, or delay expiry."
            ),
            'recommendation': (
                "Avoid making security-critical decisions solely on "
                "'unix_timestamp'. Use slot-based logic where possible, add "
                "a tolerance buffer, or combine timestamps with other "
                "on-chain state. Never use timestamps as the only gate for "
                "high-value transfers."
            ),
            'vulnerable_code': (
                "let clock = Clock::get()?;\n"
                "if clock.unix_timestamp >= unlock_time {\n"
                "    transfer(ctx)?;  // timestamp can be manipulated\n"
                "}"
            ),
            'secure_code': (
                "let clock = Clock::get()?;\n"
                "// Add a tolerance buffer and prefer slot-based checks\n"
                "require!(\n"
                "    clock.unix_timestamp >= unlock_time + BUFFER_SECS,\n"
                "    ErrorCode::TooEarly\n"
                ");\n"
                "transfer(ctx)?;"
            ),
        })

    return findings
