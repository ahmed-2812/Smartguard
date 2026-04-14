"""
access_control.py
Detects critical functions that lack proper authorisation checks.
Severity: CRITICAL
"""

import re
from analyser.parser import get_node_text, get_line_number, walk_tree

# Function names that should always require authorisation
CRITICAL_FN_KEYWORDS = {
    'close', 'transfer_authority', 'withdraw', 'drain', 'admin',
    'update_authority', 'set_authority', 'change_owner', 'upgrade',
    'mint', 'burn', 'freeze', 'thaw', 'delete', 'destroy',
}

# Patterns that indicate an authorisation check is present
AUTH_CHECK_PATTERNS = [
    r'\brequire!\s*\(',
    r'\bassert!\s*\(',
    r'\bassert_eq!\s*\(',
    r'\.is_signer',
    r'signer_seeds',
    r'authority\.key\(\)',
    r'owner\.key\(\)',
    r'#\[access_control',
    r'Signer\s*<',
    r'has_one\s*=',
    r'constraint\s*=',
    r'ctx\.accounts\.\w+\.key\(\)\s*==',
    r'ctx\.accounts\.\w+\.is_signer',
]


def _fn_has_auth_check(fn_node, raw: bytes) -> bool:
    fn_text = get_node_text(fn_node, raw)
    return any(re.search(p, fn_text) for p in AUTH_CHECK_PATTERNS)


def _fn_name_is_critical(name: str) -> bool:
    name_lower = name.lower()
    return any(kw in name_lower for kw in CRITICAL_FN_KEYWORDS)


def detect_access_control(tree, raw: bytes) -> list:
    findings = []

    for fn_node in walk_tree(tree.root_node):
        if fn_node.type != 'function_item':
            continue

        name_node = fn_node.child_by_field_name('name')
        if name_node is None:
            continue
        fn_name = get_node_text(name_node, raw)

        if not _fn_name_is_critical(fn_name):
            continue

        if _fn_has_auth_check(fn_node, raw):
            continue

        fn_text = get_node_text(fn_node, raw)
        # Show only the signature (first line)
        first_line = fn_text.split('\n')[0].strip()

        findings.append({
            'vulnerability_type': 'Missing Access Control',
            'severity': 'CRITICAL',
            'line_number': get_line_number(fn_node),
            'function_name': fn_name,
            'description': (
                f"The function '{fn_name}' performs a sensitive operation but "
                "contains no authorisation checks (require!, assert!, signer "
                "validation, or Anchor constraints). Any caller can invoke it."
            ),
            'impact': (
                "An unauthenticated attacker can call this function to transfer "
                "funds, change ownership, drain accounts, or otherwise corrupt "
                "program state without restriction."
            ),
            'recommendation': (
                "Add an authorisation check at the start of the function. "
                "With Anchor use 'has_one', 'constraint', or '#[access_control(...)]'. "
                "Without Anchor, use require!(ctx.accounts.authority.is_signer, ...) "
                "or assert!(signer.key() == expected_key)."
            ),
            'vulnerable_code': (
                f"pub fn {fn_name}(ctx: Context<...>) -> Result<()> {{\n"
                "    // No signer or authority check — anyone can call this\n"
                "    transfer_funds(ctx)?;\n"
                "    Ok(())\n"
                "}"
            ),
            'secure_code': (
                f"pub fn {fn_name}(ctx: Context<...>) -> Result<()> {{\n"
                "    require!(\n"
                "        ctx.accounts.authority.is_signer,\n"
                "        ErrorCode::Unauthorized\n"
                "    );\n"
                "    transfer_funds(ctx)?;\n"
                "    Ok(())\n"
                "}"
            ),
        })

    return findings
