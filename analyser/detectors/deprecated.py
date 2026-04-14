"""
deprecated.py
Detects usage of known deprecated Solana / Anchor / Rust patterns.
Severity: LOW
"""

import re
from analyser.parser import get_node_text, get_line_number, walk_tree

# (pattern, description, recommendation)
DEPRECATED_PATTERNS = [
    (
        r'\bspl_token::instruction::transfer\b',
        "Direct use of spl_token::instruction::transfer is deprecated.",
        "Use anchor_spl::token::transfer or the CPI helper from the token program crate.",
    ),
    (
        r'\bsol_log_compute_units\b',
        "sol_log_compute_units is a debug utility and should not appear in production code.",
        "Remove compute-unit logging before deploying to mainnet.",
    ),
    (
        r'\bAccountInfo::assign\b',
        "AccountInfo::assign bypasses ownership checks and is considered unsafe.",
        "Use the system program's 'assign' instruction via CPI instead.",
    ),
    (
        r'#\[deprecated\]',
        "This item is explicitly marked as deprecated by its author.",
        "Check the deprecation notice and migrate to the recommended replacement.",
    ),
    (
        r'\bsolana_program::system_instruction::create_account_with_seed\b',
        "create_account_with_seed has known pitfalls with seed collision.",
        "Prefer PDA-based account creation with invoke_signed for predictable addressing.",
    ),
    (
        r'\bget_return_data\b',
        "get_return_data is not yet stable and its API may change.",
        "Avoid relying on return data in production contracts until the API is stabilised.",
    ),
    (
        r'\bAccountMeta::new_readonly\s*\(\s*solana_program::sysvar::recent_blockhashes',
        "The RecentBlockhashes sysvar is deprecated as of Solana 1.9.",
        "Use SlotHashes or a different randomness source such as a VRF.",
    ),
    (
        r'\bunwrap\s*\(\s*\)',
        "Calling .unwrap() in on-chain code will panic and abort the transaction with an unhelpful error.",
        "Use .ok_or(ErrorCode::...)? to return a descriptive error instead of panicking.",
    ),
    (
        r'\bpanic!\s*\(',
        "panic! in on-chain code causes an abrupt transaction failure with no useful error code.",
        "Return a typed error with Err(ErrorCode::...) or use require!/assert! macros.",
    ),
    (
        r'\btodo!\s*\(',
        "todo!() is a placeholder that will always panic at runtime.",
        "Replace todo!() with a full implementation before deploying.",
    ),
    (
        r'\bunimplemented!\s*\(',
        "unimplemented!() is a placeholder that will always panic at runtime.",
        "Provide a real implementation before deploying.",
    ),
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


def detect_deprecated(tree, raw: bytes) -> list:
    findings = []
    raw_str = raw.decode('utf-8', errors='replace')
    lines = raw_str.splitlines()

    for pattern, description, recommendation in DEPRECATED_PATTERNS:
        for line_idx, line_text in enumerate(lines):
            if re.search(pattern, line_text):
                line_number = line_idx + 1

                # Find the corresponding AST node for function name
                fn_name = 'unknown'
                for node in walk_tree(tree.root_node):
                    if node.start_point[0] <= line_idx <= node.end_point[0]:
                        if node.type == 'function_item':
                            name_node = node.child_by_field_name('name')
                            if name_node:
                                fn_name = get_node_text(name_node, raw)
                            break

                findings.append({
                    'vulnerability_type': 'Deprecated Usage',
                    'severity': 'LOW',
                    'line_number': line_number,
                    'function_name': fn_name,
                    'description': description,
                    'impact': (
                        "Deprecated APIs may be removed in future versions, "
                        "could introduce subtle bugs, or may behave unexpectedly "
                        "on newer runtime versions."
                    ),
                    'recommendation': recommendation,
                    'vulnerable_code': line_text.strip(),
                    'secure_code': f"// {recommendation}",
                })

    return findings
