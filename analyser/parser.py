"""
parser.py - Parses Rust source code into a tree-sitter AST.
"""

import tree_sitter_rust as tsrust
from tree_sitter import Language, Parser

RUST_LANGUAGE = Language(tsrust.language())


def parse_rust_code(source: str):
    """
    Parse raw Rust source code and return (tree, raw_bytes).

    Parameters
    ----------
    source : str
        The Rust source code as a string.

    Returns
    -------
    tuple[Tree, bytes]
        The tree-sitter parse tree and the source encoded as UTF-8 bytes.
    """
    raw = source.encode('utf-8')
    parser = Parser(RUST_LANGUAGE)
    tree = parser.parse(raw)
    return tree, raw


def get_node_text(node, raw: bytes) -> str:
    """Return the source text for a given AST node."""
    return raw[node.start_byte:node.end_byte].decode('utf-8', errors='replace')


def get_line_number(node) -> int:
    """Return 1-based line number for a node."""
    return node.start_point[0] + 1


def walk_tree(node):
    """Yield every node in the subtree via depth-first traversal."""
    yield node
    for child in node.children:
        yield from walk_tree(child)
