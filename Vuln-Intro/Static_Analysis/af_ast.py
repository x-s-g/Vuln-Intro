import af_code
from pycparser import c_parser, c_ast
import networkx as nx


class ASTStorage:
    """
    Class to store and manage multiple ASTs parsed from C code snippets.
    """

    def __init__(self):
        self.asts = []  # List to store ASTs

    def add_ast(self, code):
        """
        Parse C code into an AST and add it to storage.

        Args:
            code (str): C code string to parse.
        """
        parser = c_parser.CParser()
        ast = parser.parse(code)
        self.asts.append(ast)

    def get_ast(self, index):
        """
        Retrieve the AST at the specified index.

        Args:
            index (int): Index of the AST to retrieve.

        Returns:
            c_ast.Node: Parsed AST node.

        Raises:
            IndexError: If index is out of range.
        """
        if 0 <= index < len(self.asts):
            return self.asts[index]
        else:
            raise IndexError("Index out of range")

    def show_ast(self, index):
        """
        Print the AST at the specified index with details.

        Args:
            index (int): Index of the AST to display.
        """
        ast = self.get_ast(index)
        ast.show(attrnames=True, nodenames=True, showcoord=True)

    def list_asts(self):
        """
        List summary of all stored ASTs.
        """
        for i, ast in enumerate(self.asts):
            print(f"AST {i}:")
            ast.show(attrnames=True, nodenames=True, showcoord=True, max_depth=1)
            print()


def build_control_flow_graph_recursive(node, G, prev_node=None, label_dict=None, pending_gotos=None):
    """
    Recursively build a control flow graph (CFG) from the given AST node.

    Args:
        node (c_ast.Node or list): Current AST node or list of nodes.
        G (networkx.DiGraph): Directed graph to build.
        prev_node (c_ast.Node, optional): Previous node in CFG.
        label_dict (dict, optional): Mapping from label names to nodes.
        pending_gotos (list, optional): List of unresolved goto nodes.
    """
    if label_dict is None:
        label_dict = {}
    if pending_gotos is None:
        pending_gotos = []

    if isinstance(node, c_ast.Compound):
        prev_child_node = None
        if node.block_items:
            for child in node.block_items:
                if prev_child_node is not None:
                    G.add_edge(prev_child_node, child)
                    build_control_flow_graph_recursive(child, G, prev_child_node, label_dict, pending_gotos)
                    prev_child_node = child
                else:
                    G.add_edge(node, child)
                    build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                    prev_child_node = child

    elif isinstance(node, c_ast.For):
        if node.init:
            for child in node.init:
                build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
        G.add_edge(node, node.stmt)
        build_control_flow_graph_recursive(node.stmt, G, node, label_dict, pending_gotos)
        if node.next:
            for child in node.next:
                build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.While):
        G.add_edge(node, node.stmt)
        build_control_flow_graph_recursive(node.stmt, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.DoWhile):
        G.add_edge(node, node.stmt)
        build_control_flow_graph_recursive(node.stmt, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.Switch):
        build_control_flow_graph_recursive(node.cond, G, prev_node, label_dict, pending_gotos)
        for child in node.stmt.block_items:
            G.add_edge(node, child)
            build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.Case):
        prev_child_node = None
        if node.stmts:
            for child in node.stmts:
                if prev_child_node is not None:
                    G.add_edge(prev_child_node, child)
                    build_control_flow_graph_recursive(child, G, prev_child_node, label_dict, pending_gotos)
                    prev_child_node = child
                else:
                    G.add_edge(node, child)
                    build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                    prev_child_node = child

    elif isinstance(node, c_ast.Default):
        prev_child_node = None
        if node.stmts:
            for child in node.stmts:
                if prev_child_node is not None:
                    G.add_edge(prev_child_node, child)
                    build_control_flow_graph_recursive(child, G, prev_child_node, label_dict, pending_gotos)
                    prev_child_node = child
                else:
                    G.add_edge(node, child)
                    build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                    prev_child_node = child

    elif isinstance(node, c_ast.If):
        if node.iftrue:
            if_true_node = node.iftrue
            if isinstance(if_true_node, c_ast.Compound):
                prev_child_node = None
                for child in if_true_node.block_items:
                    if prev_child_node is not None:
                        G.add_edge(prev_child_node, child)
                        build_control_flow_graph_recursive(child, G, prev_child_node, label_dict, pending_gotos)
                        prev_child_node = child
                    else:
                        G.add_edge(node, child)
                        build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                        prev_child_node = child
            else:
                G.add_edge(node, if_true_node)
                build_control_flow_graph_recursive(node.iftrue, G, node, label_dict, pending_gotos)

        if node.iffalse:
            if_false_node = node.iffalse
            if isinstance(if_false_node, c_ast.Compound):
                prev_child_node = None
                for child in if_false_node.block_items:
                    if prev_child_node is not None:
                        G.add_edge(prev_child_node, child)
                        build_control_flow_graph_recursive(child, G, prev_child_node, label_dict, pending_gotos)
                        prev_child_node = child
                    else:
                        G.add_edge(node, child)
                        build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                        prev_child_node = child
            else:
                G.add_edge(node, if_false_node)
                build_control_flow_graph_recursive(node.iffalse, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.FuncDef):
        G.add_edge(node, node.body)
        build_control_flow_graph_recursive(node.body, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.Label):
        label_dict[node.name] = node
        G.add_edge(node, node.stmt)
        build_control_flow_graph_recursive(node.stmt, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.Node):
        for _, child in node.children():
            G.add_edge(node, child)
            build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)

    elif isinstance(node, list):
        for item in node:
            build_control_flow_graph_recursive(item, G, prev_node, label_dict, pending_gotos)


def get_node_info(node):
    """
    Retrieve the line number of the node if available.
    """
    return node.coord.line if hasattr(node, 'coord') and node.coord else 'Unknown'


def print_control_flow_graph(G):
    """
    Print nodes and edges of the control flow graph with node types and line numbers.
    """
    print("Control Flow Graph Nodes:")
    for node in G.nodes():
        nodetype = type(node).__name__
        print(f"Node: {nodetype} (Line {get_node_info(node)})")

    print("\nControl Flow Graph Edges:")
    for src, tgt in G.edges():
        print(f"{type(src).__name__} (Line {get_node_info(src)}) -> {type(tgt).__name__} (Line {get_node_info(tgt)})")


def build_ast(code_list):
    """
    Build ASTs and their corresponding control flow graphs from code snippets.

    Args:
        code_list (list[str]): List of C code snippets as strings.

    Returns:
        tuple: (ASTStorage instance, list of networkx.DiGraph CFGs)
    """
    storage = ASTStorage()
    Gs = []
    for code in code_list:
        storage.add_ast(code)
        G = nx.DiGraph()
        build_control_flow_graph_recursive(storage.get_ast(len(storage.asts) - 1), G)
        Gs.append(G)
    return storage, Gs


def main(CVE_id):
    """
    Main function: get code patches by CVE ID, build ASTs and CFGs.

    Args:
        CVE_id (str): CVE identifier string.

    Returns:
        tuple: (ASTStorage instance, list of CFG graphs, patch count)
    """
    list1, count = af_code.main(CVE_id)
    storage, Gs = build_ast(list1)
    return storage, Gs, count

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
