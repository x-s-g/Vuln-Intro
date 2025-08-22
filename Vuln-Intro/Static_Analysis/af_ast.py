import af_code
from pycparser import c_parser, c_ast
import networkx as nx


class ASTStorage:
    def __init__(self):
        self.asts = []  # List for storing ASTs

    def add_ast(self, code):
        """
        Parse C code into an AST and add it to the list
        :param code: C code string
        """
        parser = c_parser.CParser()
        ast = parser.parse(code)
        self.asts.append(ast)

    def get_ast(self, index):
        """
        Get the AST at a specific index
        :param index: Index of the AST
        :return: AST node
        """
        if 0 <= index < len(self.asts):
            return self.asts[index]
        else:
            raise IndexError("Index out of range")

    def show_ast(self, index):
        """
        Print the AST at a specific index
        :param index: Index of the AST
        """
        ast = self.get_ast(index)
        ast.show(attrnames=True, nodenames=True, showcoord=True)

    def list_asts(self):
        """
        List brief information of all stored ASTs
        """
        for i, ast in enumerate(self.asts):
            print(f"AST {i}:")
            ast.show(attrnames=True, nodenames=True, showcoord=True, max_depth=1)
            print()

def build_control_flow_graph_recursive(node, G, prev_node=None, label_dict=None, pending_gotos=None):
    if label_dict is None:
        label_dict = {}
    if pending_gotos is None:
        pending_gotos = []

    if isinstance(node, c_ast.Compound):
        nodetype = 'Compound'
        prev_child_node = None
        if node.block_items:  # Check if block_items is None
            for child in node.block_items:
                if prev_child_node is not None:
                    G.add_edge(prev_child_node, child)
                    build_control_flow_graph_recursive(child, G, prev_child_node,label_dict, pending_gotos)
                    prev_child_node = child
                if prev_child_node is None:
                    G.add_edge(node, child)
                    build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                    prev_child_node=child

    elif isinstance(node, c_ast.For):
        nodetype = 'For Loop'
        if node.init:  # Check if init is None
            for child in node.init:
                build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
        # build_control_flow_graph_recursive(node.cond, G, node, label_dict, pending_gotos)
        G.add_edge(node,node.stmt)
        build_control_flow_graph_recursive(node.stmt, G, node, label_dict, pending_gotos)
        if node.next:  # Check if next is None
            for child in node.next:
                build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.While):
        nodetype = 'While Loop'
        # build_control_flow_graph_recursive(node.cond, G, prev_node, label_dict, pending_gotos)
        G.add_edge(node,node.stmt)
        build_control_flow_graph_recursive(node.stmt, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.DoWhile):
        nodetype = 'Do While Loop'
        G.add_edge(node, node.stmt)
        build_control_flow_graph_recursive(node.stmt, G, node, label_dict, pending_gotos)
        #build_control_flow_graph_recursive(node.cond, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.Switch):
        nodetype = 'Switch Statement'
        build_control_flow_graph_recursive(node.cond, G, prev_node, label_dict, pending_gotos)
        for child in node.stmt.block_items:
            G.add_edge(node, child)
            build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.Case):
        nodetype = 'Case Statement'
        prev_child_node = None
        if node.stmts:  # Check if stmts is None
            for child in node.stmts:
                if prev_child_node is not None:
                    G.add_edge(prev_child_node, child)
                    build_control_flow_graph_recursive(child, G, prev_child_node,label_dict, pending_gotos)
                    prev_child_node = child
                if prev_child_node is None:
                    G.add_edge(node, child)
                    build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                    prev_child_node = child

    elif isinstance(node, c_ast.Default):
        nodetype = 'Default Statement'
        prev_child_node = None
        if node.stmts:  # Check if stmts is None
            for child in node.stmts:
                if prev_child_node is not None:
                    G.add_edge(prev_child_node, child)
                    build_control_flow_graph_recursive(child, G, prev_child_node)
                    prev_child_node = child
                if prev_child_node is None:
                    G.add_edge(node, child)
                    build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                    prev_child_node = child

    elif isinstance(node, c_ast.If):
        nodetype = 'If Statement'
        # Handle condition part
        # cond_node = node.cond
        # G.add_edge(node, cond_node)
        # build_control_flow_graph_recursive(node.cond, G, node, label_dict, pending_gotos)

        # Handle iftrue branch
        if node.iftrue:
            if_true_node = node.iftrue
            if isinstance(if_true_node,c_ast.Compound):
                prev_child_node=None
                for child in if_true_node.block_items:
                    if prev_child_node is not None:
                        G.add_edge(prev_child_node, child)
                        build_control_flow_graph_recursive(child, G, prev_child_node,label_dict, pending_gotos)
                        prev_child_node = child
                    if prev_child_node is None:
                        G.add_edge(node, child)
                        build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                        prev_child_node = child
            else:
                G.add_edge(node, if_true_node)
                build_control_flow_graph_recursive(node.iftrue, G, node, label_dict, pending_gotos)

        # Handle iffalse branch
        if node.iffalse:
            if_false_node = node.iffalse
            if isinstance(if_false_node,c_ast.Compound):
                prev_child_node=None
                for child in if_false_node.block_items:
                    if prev_child_node is not None:
                        G.add_edge(prev_child_node, child)
                        build_control_flow_graph_recursive(child, G, prev_child_node,label_dict, pending_gotos)
                        prev_child_node = child
                    if prev_child_node is None:
                        G.add_edge(node, child)
                        build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)
                        prev_child_node = child
            else:
                G.add_edge(node, if_false_node)
                build_control_flow_graph_recursive(node.iffalse, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.FuncDef):
        nodetype = 'Function Definition'
        G.add_edge(node,node.body)
        build_control_flow_graph_recursive(node.body, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.FuncDecl):
        nodetype = 'Function Declaration'

    elif isinstance(node, c_ast.Continue):
        nodetype = 'Continue Statement'

    elif isinstance(node, c_ast.Return):
        nodetype = 'Return Statement'

    elif isinstance(node, c_ast.Decl):
        nodetype = 'Declaration'
        # if node.init:
        #     build_control_flow_graph_recursive(node.init, G, node, label_dict, pending_gotos)
    elif isinstance(node, c_ast.Assignment):
        nodetype = 'Assignment'
        # build_control_flow_graph_recursive(node.rvalue, G, prev_node, label_dict, pending_gotos)
    elif isinstance(node, c_ast.ArrayDecl):
        nodetype = 'Array Declaration'
    elif isinstance(node, c_ast.ArrayRef):
        nodetype = 'Array Reference'
        # build_control_flow_graph_recursive(node.name, G, prev_node, label_dict, pending_gotos)
        # build_control_flow_graph_recursive(node.subscript, G, prev_node, label_dict, pending_gotos)
    elif isinstance(node, c_ast.ExprList):
        nodetype = 'Expression List'
    elif isinstance(node, c_ast.FuncCall):
        nodetype = 'Function Call'
        # build_control_flow_graph_recursive(node.args, G, prev_node, label_dict, pending_gotos)
    elif isinstance(node, c_ast.Constant):
        nodetype = 'Constant'
    elif isinstance(node, c_ast.Break):
        nodetype = 'Break Statement'
    elif isinstance(node, c_ast.StructRef):
        nodetype = 'Struct Reference'
        # build_control_flow_graph_recursive(node.name, G, prev_node, label_dict, pending_gotos)
        # build_control_flow_graph_recursive(node.field, G, prev_node, label_dict, pending_gotos)
    elif isinstance(node, c_ast.Continue):
        nodetype = 'Continue Statement'
    elif isinstance(node, c_ast.Goto):
        nodetype = 'Goto'
        # label_name = node.name
        #
        # if label_name in label_dict:
        #     target_node = label_dict[label_name]
        #     G.add_edge(node, target_node)
        # else:
        #     # 记录未解析的goto语句
        #     pending_gotos.append((node, label_name))

    elif isinstance(node, c_ast.Label):
        nodetype = 'Label'
        label_name = node.name
        label_dict[label_name] = node
        #print(label_name)

        # Handle unresolved goto statements
        # for goto_node, goto_label in list(pending_gotos):
        #
        #     if goto_label == label_name:
        #         # print(goto_label)
        #         # print(goto_node)
        #         G.add_edge(goto_node, node)
        #         pending_gotos.remove((goto_node, goto_label))

       # Handle child nodes of label
        G.add_edge(node, node.stmt)
        build_control_flow_graph_recursive(node.stmt, G, node, label_dict, pending_gotos)

    elif isinstance(node, c_ast.Node):  # Handle generic Node types
        for child_name, child in node.children():
            G.add_edge(node, child)
            build_control_flow_graph_recursive(child, G, node, label_dict, pending_gotos)

    elif isinstance(node, list):
        for item in node:
            build_control_flow_graph_recursive(item, G, prev_node, label_dict, pending_gotos)

def get_node_info(node):
    if hasattr(node, 'coord') and node.coord:
        return node.coord.line
    else:
        return 'Unknown'

def print_control_flow_graph(G):
    print("Control Flow Graph:")
    for node in G.nodes():
        if isinstance(node, c_ast.Compound):
            nodetype = 'Compound'
        elif isinstance(node, c_ast.For):
            nodetype = 'For Loop'
        elif isinstance(node, c_ast.If):
            nodetype = 'If Statement'
        elif isinstance(node, c_ast.While):
            nodetype = 'While Loop'
        elif isinstance(node, c_ast.DoWhile):
            nodetype = 'Do While Loop'
        elif isinstance(node, c_ast.Switch):
            nodetype = 'Switch Statement'
        elif isinstance(node, c_ast.Case):
            nodetype = 'Case Statement'
        elif isinstance(node, c_ast.Default):
            nodetype = 'Default Statement'
        elif isinstance(node, c_ast.FuncDef):
            nodetype = 'Function Definition'
        elif isinstance(node, c_ast.FuncDecl):
            nodetype = 'Function Declaration'
        elif isinstance(node, c_ast.Return):
            nodetype = 'Return Statement'
        elif isinstance(node, c_ast.Decl):
            nodetype = 'Declaration'
        elif isinstance(node, c_ast.ID):
            nodetype = 'Identifier'
        elif isinstance(node, c_ast.BinaryOp):
            nodetype = 'Binary Operation'
        elif isinstance(node, c_ast.UnaryOp):
            nodetype = 'Unary Operation'
        elif isinstance(node, c_ast.Assignment):
            nodetype = 'Assignment'
        elif isinstance(node, c_ast.ArrayDecl):
            nodetype = 'Array Declaration'
        elif isinstance(node, c_ast.ArrayRef):
            nodetype = 'Array Reference'
        elif isinstance(node, c_ast.Struct):
            nodetype = 'Struct'
        elif isinstance(node, c_ast.Union):
            nodetype = 'Union'
        elif isinstance(node, c_ast.Typedef):
            nodetype = 'Typedef'
        elif isinstance(node, c_ast.StructRef):
            nodetype = 'Struct Reference'
        elif isinstance(node, c_ast.Continue):
            nodetype = 'Continue'
        elif isinstance(node, c_ast.TypeDecl):
            nodetype = 'Type Declaration'
        elif isinstance(node, c_ast.PtrDecl):
            nodetype = 'Pointer Declaration'
        elif isinstance(node, c_ast.ExprList):
            nodetype = 'Expression List'
        elif isinstance(node, c_ast.FuncCall):
            nodetype = 'Function Call'
        elif isinstance(node, c_ast.Constant):
            nodetype = 'Constant'
        elif isinstance(node, c_ast.Break):
            nodetype = 'Break Statement'
        elif isinstance(node, c_ast.Continue):
            nodetype = 'Continue Statement'
        elif isinstance(node, c_ast.Goto):
            nodetype = 'Goto'
        elif isinstance(node, c_ast.Label):
            nodetype = 'Label'
        else:
            nodetype = 'Unknown'

        print(f"Node: {nodetype} (Line {get_node_info(node)})")
        # with open("node.txt","a")as file:
        #     file.write(f"Node: {nodetype} (Line {get_node_info(node)})\n")
        # file.close()

    print("\nEdges:")
    for edge in G.edges():
        source = edge[0]
        target = edge[1]
        source_code = get_node_info(source)


        if isinstance(source, c_ast.Compound):
            source_type = 'Compound'
        elif isinstance(source, c_ast.For):
            source_type = 'For Loop'
        elif isinstance(source, c_ast.If):
            source_type = 'If Statement'
        elif isinstance(source, c_ast.While):
            source_type = 'While Loop'
        elif isinstance(source, c_ast.DoWhile):
            source_type = 'Do While Loop'
        elif isinstance(source, c_ast.Switch):
            source_type = 'Switch Statement'
        elif isinstance(source, c_ast.Case):
            source_type = 'Case Statement'
        elif isinstance(source, c_ast.Default):
            source_type = 'Default Statement'
        elif isinstance(source, c_ast.FuncDef):
            source_type = 'Function Definition'
        elif isinstance(source, c_ast.FuncDecl):
            source_type = 'Function Declaration'
        elif isinstance(source, c_ast.Return):
            source_type = 'Return Statement'
        elif isinstance(source, c_ast.Continue):
            source_type = 'Continue'
        elif isinstance(source, c_ast.Decl):
            source_type = 'Declaration'
        elif isinstance(source, c_ast.ID):
            source_type = 'Identifier'
        elif isinstance(source, c_ast.BinaryOp):
            source_type = 'Binary Operation'
        elif isinstance(source, c_ast.UnaryOp):
            source_type = 'Unary Operation'
        elif isinstance(source, c_ast.StructRef):
            source_type = 'Struct Reference'
        elif isinstance(source, c_ast.Assignment):
            source_type = 'Assignment'
        elif isinstance(source, c_ast.ArrayDecl):
            source_type = 'Array Declaration'
        elif isinstance(source, c_ast.ArrayRef):
            source_type = 'Array Reference'
        elif isinstance(source, c_ast.Struct):
            source_type = 'Struct'
        elif isinstance(source, c_ast.Union):
            source_type = 'Union'
        elif isinstance(source, c_ast.Typedef):
            source_type = 'Typedef'
        elif isinstance(source, c_ast.TypeDecl):
            source_type = 'Type Declaration'
        elif isinstance(source, c_ast.PtrDecl):
            source_type = 'Pointer Declaration'
        elif isinstance(source, c_ast.ExprList):
            source_type = 'Expression List'
        elif isinstance(source, c_ast.FuncCall):
            source_type = 'Function Call'
        elif isinstance(source, c_ast.Constant):
            source_type = 'Constant'
        elif isinstance(source, c_ast.Break):
            source_type = 'Break Statement'
        elif isinstance(source, c_ast.Continue):
            source_type = 'Continue Statement'
        elif isinstance(source, c_ast.Goto):
            source_type = 'Goto'
        elif isinstance(source, c_ast.Label):
            source_type = 'Label'
        else:
            source_type = 'Unknown'

        target_code = get_node_info(target)

        if isinstance(target, c_ast.Compound):
            target_type = 'Compound'
        elif isinstance(target, c_ast.For):
            target_type = 'For Loop'
        elif isinstance(target, c_ast.If):
            target_type = 'If Statement'
        elif isinstance(target, c_ast.While):
            target_type = 'While Loop'
        elif isinstance(target, c_ast.DoWhile):
            target_type = 'Do While Loop'
        elif isinstance(target, c_ast.Switch):
            target_type = 'Switch Statement'
        elif isinstance(target, c_ast.Case):
            target_type = 'Case Statement'
        elif isinstance(target, c_ast.Default):
            target_type = 'Default Statement'
        elif isinstance(target, c_ast.FuncDef):
            target_type = 'Function Definition'
        elif isinstance(target, c_ast.FuncDecl):
            target_type = 'Function Declaration'
        elif isinstance(target, c_ast.Return):
            target_type = 'Return Statement'
        elif isinstance(target, c_ast.Decl):
            target_type = 'Declaration'
        elif isinstance(target, c_ast.Continue):
            target_type = 'Continue'
        elif isinstance(target, c_ast.StructRef):
            target_type = 'Struct Reference'
        elif isinstance(target, c_ast.ID):
            target_type = 'Identifier'
        elif isinstance(target, c_ast.BinaryOp):
            target_type = 'Binary Operation'
        elif isinstance(target, c_ast.UnaryOp):
            target_type = 'Unary Operation'
        elif isinstance(target, c_ast.Assignment):
            target_type = 'Assignment'
        elif isinstance(target, c_ast.ArrayDecl):
            target_type = 'Array Declaration'
        elif isinstance(target, c_ast.ArrayRef):
            target_type = 'Array Reference'
        elif isinstance(target, c_ast.Struct):
            target_type = 'Struct'
        elif isinstance(target, c_ast.Union):
            target_type = 'Union'
        elif isinstance(target, c_ast.Typedef):
            target_type = 'Typedef'
        elif isinstance(target, c_ast.TypeDecl):
            target_type = 'Type Declaration'
        elif isinstance(target, c_ast.PtrDecl):
            target_type = 'Pointer Declaration'
        elif isinstance(target, c_ast.ExprList):
            target_type = 'Expression List'
        elif isinstance(target, c_ast.FuncCall):
            target_type = 'Function Call'
        elif isinstance(target, c_ast.Constant):
            target_type = 'Constant'
        elif isinstance(target, c_ast.Break):
            target_type = 'Break Statement'
        elif isinstance(target, c_ast.Continue):
            target_type = 'Continue Statement'
        elif isinstance(target, c_ast.Goto):
            target_type = 'Goto'
        elif isinstance(target, c_ast.Label):
            target_type = 'Label'
        else:
            target_type = 'Unknown'

        print(f"{source_type } (Line {source_code}) -> {target_type} (Line {target_code})")
        # with open("node.txt", "a") as file:
        #     file.write(f"{source_type } (Line {source_code}) -> {target_type} (Line {target_code})\n")
        # file.close()


def build_ast(code_list):
    storage=ASTStorage()
    Gs=[]
    for i in range(len(code_list)):
        # print(code_list[i])
        storage.add_ast(code_list[i])
        #storage.show_ast(i)
        G = nx.DiGraph()
        build_control_flow_graph_recursive(storage.get_ast(i), G)
        Gs.append(G)
        #print_control_flow_graph(G)
    return storage,Gs


def main(CVE_id):
    list1,count=af_code.main(CVE_id)
    # for i in list1:
    #     print(i)
    #构建ast
    storage,Gs=build_ast(list1)
    return storage,Gs,count

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
