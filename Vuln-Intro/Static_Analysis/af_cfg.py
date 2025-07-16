import af_ast
import af_code
import networkx as nx
from pycparser import c_parser, c_ast
import sys
import time


def find_all_paths(G, start_node):
    """
    Find all possible paths from the start_node in the directed graph G.

    :param G: NetworkX directed graph representing control flow.
    :param start_node: Starting node (usually a function definition node).
    :return: List of paths, each path is a list of nodes.
    """
    paths = []

    def dfs(current_node, current_path):
        # Append current node to the current path
        current_path.append(current_node)

        # If current node has no successors, save the path
        if len(list(G.successors(current_node))) == 0:
            paths.append(list(current_path))
        else:
            # Recurse for each successor
            for successor in G.successors(current_node):
                dfs(successor, current_path)

        # Backtrack to previous node
        current_path.pop()

    # Start DFS from the start_node
    dfs(start_node, [])
    return paths


def get_node_info(node):
    """
    Get string description of a node including its type and line number if available.

    :param node: AST node.
    :return: String with node type and line info.
    """
    if hasattr(node, 'coord') and node.coord:
        return f"{type(node).__name__} (Line {node.coord.line})"
    else:
        return f"{type(node).__name__} (Unknown Line)"


def print_paths(paths):
    """
    Print all paths nicely formatted by node info.

    :param paths: List of paths (each path is a list of nodes).
    """
    for path in paths:
        path_str = " -> ".join(get_node_info(node) for node in path)
        print(f"Path: {path_str}")


def all_path(G):
    """
    Find all control flow paths in graph G starting from the first FuncDef node.

    :param G: Control flow graph.
    :return: List of all paths.
    """
    start_node = None
    for node in G.nodes():
        if isinstance(node, c_ast.FuncDef):
            start_node = node
            break

    paths = []
    if start_node:
        paths = find_all_paths(G, start_node)

    return paths


def main(CVE_id):
    """
    Main entry function:
    1. Get patched code blocks and counts from af_code.
    2. Build ASTs and CFGs from af_ast.
    3. Extract all control flow paths for each CFG.
    4. Return list of paths and count of lines filtered.

    :param CVE_id: CVE identifier string.
    :return: Tuple (list_of_all_paths_for_each_patch, count)
    """
    # Get patched code blocks and count of removed lines
    list1, count = af_code.main(CVE_id)

    # Get AST storage and CFGs for patched functions
    storage, Gs, count = af_ast.main(CVE_id)

    af_path = []
    for i in range(len(list1)):
        # For each patched function's CFG, get all paths
        paths = all_path(Gs[i])
        print_paths(paths)
        af_path.append(paths)

    return af_path, count

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
