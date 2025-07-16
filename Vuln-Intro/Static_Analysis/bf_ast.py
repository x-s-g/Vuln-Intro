import bf_code
import af_ast

def main(CVE_id):
    """
    Entry function to process CVE patch code, build ASTs and control flow graphs.

    Args:
        CVE_id (str): The identifier for the CVE to process.

    Returns:
        tuple: (storage, Gs, count)
            - storage: ASTStorage object containing parsed ASTs.
            - Gs: List of control flow graphs built from ASTs.
            - count: Number of code snippets processed.
    """
    # Retrieve patch code list and count from bf_code module
    list1, count = bf_code.main(CVE_id)

    # Build ASTs and control flow graphs for the retrieved code list
    storage, Gs = af_ast.build_ast(list1)

    return storage, Gs, count

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
