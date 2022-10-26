from tree_sitter import Node
import logging as log


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
