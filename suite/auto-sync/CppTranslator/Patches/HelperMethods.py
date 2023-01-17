from tree_sitter import Node
import logging as log


def get_function_params_of_node(n: Node) -> Node:
    """
    Returns for a given node the parameters of the function this node is a children from.
    Or None if the node is not part of a function definition.
    """
    fcn_def: Node = n
    while fcn_def.type != "function_definition":
        if fcn_def.parent == None:
            # root node reached
            return None
        fcn_def = fcn_def.parent

    # Get parameter list of the function definition
    param_list: Node = None
    for child in fcn_def.children:
        if child.type == "function_declarator":
            param_list = child.children[1]
            break
    if not param_list:
        log.warning(f"Could not find the functions parameter list for {n.text}")
    return param_list


def get_MCInst_var_name(src: bytes, n: Node) -> bytes:
    """Searches for the name of the parameter of type MCInst and returns it."""
    params = get_function_params_of_node(n)
    mcinst_var_name = b""
    for p in params.named_children:
        p_text = get_text(src, p.start_byte, p.end_byte)
        if b"MCInst" in p_text:
            mcinst_var_name = p_text.split((b"&" if b"&" in p_text else b"*"))[1]
            break
    if mcinst_var_name == b"":
        log.debug("Could not find `MCInst` variable name. Defaulting to `Inst`.")
        mcinst_var_name = b"Inst"
    return mcinst_var_name


def template_param_list_to_dict(param_list: Node) -> [dict]:
    if param_list.type != "template_parameter_list":
        log.fatal(f"Node of type {param_list.type} given. Not 'template_parameter_list'.")
    pl = list()
    for c in param_list.named_children:
        pl.append(parameter_declaration_to_dict(c))
    return pl


def parameter_declaration_to_dict(param_decl: Node) -> dict:
    if param_decl.type != "parameter_declaration":
        log.fatal(f"Node of type {param_decl.type} given. Not 'parameter_declaration'.")
    return {
        "prim_type": param_decl.children[0].type == "primitive_type",
        "type": param_decl.children[0].text,
        "identifier": param_decl.children[1].text,
    }


def get_text(src: bytes, start_byte: int, end_byte: int) -> bytes:
    """Workaround for https://github.com/tree-sitter/py-tree-sitter/issues/122"""
    return src[start_byte:end_byte]
