import bf_code
import filter
import bf_ast
import af_cfg

def main(CVE_id):
    """
    Entry function to process patch code blocks, build control flow graphs,
    and extract all control flow paths for a given CVE.

    Args:
        CVE_id (str): The identifier for the CVE to analyze.

    Returns:
        tuple: (bf_path, count)
            - bf_path: List of all paths extracted from the CFGs of patch functions.
            - count: Number of code snippets processed.
    """
    # Get patch code blocks and count from bf_code module
    list1, count = bf_code.main(CVE_id)

    # Build AST storage and control flow graphs from patch functions
    storage, Gs, count = bf_ast.main(CVE_id)

    bf_path = []
    for i in range(len(list1)):
        # Optionally show AST and CFG for debugging:
        # storage.show_ast(i)
        # af_ast.print_control_flow_graph(Gs[i])

        # Extract all control flow paths from the CFG graph
        paths = af_cfg.all_path(Gs[i])

        # Print the extracted paths
        af_cfg.print_paths(paths)

        bf_path.append(paths)

    return bf_path, count

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
