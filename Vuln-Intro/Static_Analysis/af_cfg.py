import networkx as nx
from pycparser import c_ast

import af_code     # returns: code_list, count
import af_ast      # returns: storage, cfgs, count


# ────────────────────────────────────────────────────────────────────
# Low‑level helper: path enumeration inside a single CFG
# ────────────────────────────────────────────────────────────────────
class CFGPathAnalyzer:
    """Static helpers to enumerate all root‑to‑leaf paths in one CFG."""

    # Depth‑first traversal ---------------------------------------------------
    @staticmethod
    def _dfs(G: nx.DiGraph, node, cur, out):
        cur.append(node)
        succ = list(G.successors(node))
        if not succ:
            out.append(cur.copy())
        else:
            for nxt in succ:
                CFGPathAnalyzer._dfs(G, nxt, cur, out)
        cur.pop()

    # Public API --------------------------------------------------------------
    @staticmethod
    def all_paths(G: nx.DiGraph):
        """Return every path starting at the first `FuncDef` node (root)."""
        root = next((n for n in G.nodes if isinstance(n, c_ast.FuncDef)), None)
        if root is None:
            return []
        paths = []
        CFGPathAnalyzer._dfs(G, root, [], paths)
        return paths

    # Pretty‑print (optional) --------------------------------------------------
    @staticmethod
    def _coord(node):
        return getattr(node, "coord", None) and node.coord.line or "?"

    @staticmethod
    def print_paths(paths):
        for p in paths:
            chain = " -> ".join(f"{type(n).__name__} (line {CFGPathAnalyzer._coord(n)})"
                                for n in p)
            print(f"Path: {chain}")


# ────────────────────────────────────────────────────────────────────
# High‑level façade: CVE‑centric workflow
# ────────────────────────────────────────────────────────────────────
class CVEPathPipeline:
    """
    Tie everything together:
        1. Load C‑patch snippets via af_code
        2. Build AST / CFG via af_ast
        3. Enumerate root‑to‑leaf paths for every CFG
    """

    @staticmethod
    def process(cve_id: str, *, echo: bool = False):
        """
        Parameters
        ----------
        cve_id : str
            e.g. "CVE-2023-6111".
        echo : bool, default=False
            If True, print every extracted path.

        Returns
        -------
        all_paths : list[list[list[c_ast.Node]]]
            • Outer length  = number of code snippets
            • Middle length = number of paths per snippet
            • Inner list    = nodes along one CFG path
        total_snippets : int
            The snippet count reported by af_code / af_ast.
        """

        # 1) Raw patch snippets (not directly used further, but keeps interface parity)
        _, total = af_code.main(cve_id)

        # 2) AST store + CFG list
        _, cfgs, total = af_ast.main(cve_id)

        # 3) Enumerate paths
        result = []
        for g in cfgs:
            paths = CFGPathAnalyzer.all_paths(g)
            if echo:
                CFGPathAnalyzer.print_paths(paths)
            result.append(paths)

        return result, total


# ====================== Program Entry ======================
if __name__ == "__main__":
    CVE = "CVE-2023-6111"
    all_paths, n_files = CVEPathPipeline.process(CVE, echo=True)
    print(f"\nExtracted {sum(len(p) for p in all_paths)} paths "
          f"from {n_files} code snippet(s).")
