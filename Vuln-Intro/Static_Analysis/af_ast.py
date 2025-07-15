import networkx as nx
from pycparser import c_parser, c_ast
import af_code   # assumed to expose: code_list, count = af_code.main(cve_id)
import sys
sys.path.append('/Data_Crawling/filter')

# import filter


class ASTStorage:
    """Light‑weight container for multiple ASTs."""

    def __init__(self) -> None:
        self._asts = []

    # ---------- CRUD ----------

    def add(self, code: str) -> None:
        """Parse C source `code` and store its AST."""
        ast = c_parser.CParser().parse(code)
        self._asts.append(ast)

    def get(self, index: int):
        """Return AST by index."""
        try:
            return self._asts[index]
        except IndexError as exc:
            raise IndexError("AST index out of range") from exc

    # ---------- Utilities ----------

    def show(self, index: int, *, full: bool = True) -> None:
        """Pretty‑print one AST (full tree or depth‑1 overview)."""
        ast = self.get(index)
        max_depth = None if full else 1
        ast.show(attrnames=True, nodenames=True, showcoord=True, max_depth=max_depth)

    def summary(self) -> None:
        """Print one‑line summaries of all stored ASTs."""
        for i in range(len(self._asts)):
            print(f"AST #{i}:")
            self.show(i, full=False)
            print()


class CFGBuilder:
    """Static helpers for building and printing control‑flow graphs."""

    # ──────────────────────────────────────────────────────────
    # recursive graph construction
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def build_recursive(node, graph: nx.DiGraph,
                        prev=None,
                        label_tbl=None,
                        pending_gotos=None) -> None:
        """
        Depth‑first traversal that adds control‑flow edges to `graph`.
        Handles common pycparser node types (Compound, If, Loop, Switch …).
        """
        if label_tbl is None:
            label_tbl = {}
        if pending_gotos is None:
            pending_gotos = []

        # ---------- Compound ----------
        if isinstance(node, c_ast.Compound):
            prev_child = None
            for child in (node.block_items or []):
                if prev_child is not None:
                    graph.add_edge(prev_child, child)
                else:
                    graph.add_edge(node, child)
                CFGBuilder.build_recursive(child, graph, prev_child or node,
                                           label_tbl, pending_gotos)
                prev_child = child

        # ---------- For ----------
        elif isinstance(node, c_ast.For):
            for child in (node.init or []):
                CFGBuilder.build_recursive(child, graph, node,
                                           label_tbl, pending_gotos)
            graph.add_edge(node, node.stmt)
            CFGBuilder.build_recursive(node.stmt, graph, node,
                                       label_tbl, pending_gotos)
            for child in (node.next or []):
                CFGBuilder.build_recursive(child, graph, node,
                                           label_tbl, pending_gotos)

        # ---------- While / DoWhile ----------
        elif isinstance(node, (c_ast.While, c_ast.DoWhile)):
            graph.add_edge(node, node.stmt)
            CFGBuilder.build_recursive(node.stmt, graph, node,
                                       label_tbl, pending_gotos)

        # ---------- Switch / Case / Default ----------
        elif isinstance(node, c_ast.Switch):
            CFGBuilder.build_recursive(node.cond, graph, prev,
                                       label_tbl, pending_gotos)
            for child in node.stmt.block_items:
                graph.add_edge(node, child)
                CFGBuilder.build_recursive(child, graph, node,
                                           label_tbl, pending_gotos)

        elif isinstance(node, (c_ast.Case, c_ast.Default)):
            prev_child = None
            for child in (node.stmts or []):
                if prev_child is not None:
                    graph.add_edge(prev_child, child)
                else:
                    graph.add_edge(node, child)
                CFGBuilder.build_recursive(child, graph, prev_child or node,
                                           label_tbl, pending_gotos)
                prev_child = child

        # ---------- If ----------
        elif isinstance(node, c_ast.If):
            for branch in (node.iftrue, node.iffalse):
                if branch:
                    if isinstance(branch, c_ast.Compound):
                        prev_child = None
                        for child in branch.block_items:
                            if prev_child is not None:
                                graph.add_edge(prev_child, child)
                            else:
                                graph.add_edge(node, child)
                            CFGBuilder.build_recursive(child, graph,
                                                       prev_child or node,
                                                       label_tbl, pending_gotos)
                            prev_child = child
                    else:
                        graph.add_edge(node, branch)
                        CFGBuilder.build_recursive(branch, graph, node,
                                                   label_tbl, pending_gotos)

        # ---------- Function Definition ----------
        elif isinstance(node, c_ast.FuncDef):
            graph.add_edge(node, node.body)
            CFGBuilder.build_recursive(node.body, graph, node,
                                       label_tbl, pending_gotos)

        # ---------- Label / Goto ----------
        elif isinstance(node, c_ast.Label):
            label_tbl[node.name] = node
            graph.add_edge(node, node.stmt)
            CFGBuilder.build_recursive(node.stmt, graph, node,
                                       label_tbl, pending_gotos)

        # ---------- Generic: traverse children ----------
        elif isinstance(node, c_ast.Node):
            for _name, child in node.children():
                graph.add_edge(node, child)
                CFGBuilder.build_recursive(child, graph, node,
                                           label_tbl, pending_gotos)

        # ---------- List of nodes ----------
        elif isinstance(node, list):
            for item in node:
                CFGBuilder.build_recursive(item, graph, prev,
                                           label_tbl, pending_gotos)

    # ──────────────────────────────────────────────────────────
    # helpers for debugging / printing
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _coord(node):
        return getattr(node, "coord", None) and node.coord.line or "?"

    @staticmethod
    def print_graph(graph: nx.DiGraph) -> None:
        """Pretty‑print all nodes and edges (type + line)."""
        print("Nodes:")
        for n in graph.nodes():
            print(f"  {type(n).__name__:<20}  line {CFGBuilder._coord(n)}")
        print("\nEdges:")
        for src, tgt in graph.edges():
            print(f"  {type(src).__name__:<20} {CFGBuilder._coord(src)}  →  "
                  f"{type(tgt).__name__:<20} {CFGBuilder._coord(tgt)}")
        print("-" * 40)


class ASTAnalyzer:
    """High‑level façade: CVE‑centric AST + CFG pipeline."""

    @staticmethod
    def build_asts_and_cfgs(code_snippets):
        storage = ASTStorage()
        cfgs = []

        for snippet in code_snippets:
            storage.add(snippet)
            g = nx.DiGraph()
            CFGBuilder.build_recursive(storage.get(len(storage._asts) - 1), g)
            cfgs.append(g)

        return storage, cfgs

    # ---------------------------------------------------------

    @staticmethod
    def process_cve(cve_id: str):
        """
        Entry point used by other scripts / CLI.
        1. Load code snippets from `af_code`.
        2. Build ASTs and CFGs.
        3. Return (storage, cfgs, count).
        """
        code_list, count = af_code.main(cve_id)
        storage, cfgs = ASTAnalyzer.build_asts_and_cfgs(code_list)
        return storage, cfgs, count


# ====================== Program Entry ======================
if __name__ == "__main__":
    CVE = "CVE-2023-6111"

    ast_store, cfg_list, snippet_count = ASTAnalyzer.process_cve(CVE)
    print(f"Loaded {snippet_count} code snippet(s) for {CVE}.")

    # Optional: print first CFG for inspection
    if cfg_list:
        print("\nFirst control‑flow graph:\n")
        CFGBuilder.print_graph(cfg_list[0])
