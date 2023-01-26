import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class FieldFromInstr(Patch):
    """
    Patch   fieldFromInstr(...)
    to      fieldFromInstr_<instr_width>(...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        # Search for fieldFromInstruction() calls.
        return '(call_expression ((identifier) @fcn_name (#eq? @fcn_name "fieldFromInstruction"))) @field_from_instr'

    def get_main_capture_name(self) -> str:
        return "field_from_instr"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        ffi_call: Node = captures[0][0]
        fcn_def: Node = captures[0][0].parent

        # Search up to the function definition this call belongs to
        while fcn_def.type != "function_definition":
            fcn_def = fcn_def.parent
        fcn_def_text = get_text(src, fcn_def.start_byte, fcn_def.end_byte)

        # Get parameter list of the function definition
        param_list: Node = None
        for child in fcn_def.children:
            if child.type == "function_declarator":
                param_list = child.children[1]
                break

        # Get the Val/Inst parameter.
        # Its type determines the instruction width.
        val_param: Node = param_list.named_children[1]
        val_param_text = get_text(src, val_param.start_byte, val_param.end_byte)

        # Search for the 'Inst' parameter and determine its type
        # and with it the width of the instruction.
        inst_type = val_param_text.split(b" ")[0]
        inst_width = 0
        if b"getThumbInstruction" in fcn_def_text:
            # This function implies an instruction width of 2 bytes.
            inst_width = 2
        elif inst_type:
            if inst_type in [b"unsigned", b"uint32_t"]:
                inst_width = 4
            elif inst_type in [b"uint16_t"]:
                inst_width = 2
            else:
                log.fatal(f"Type {inst_type} no handled.")
                exit(1)
        else:
            log.fatal(f"fieldFromInstruction() called from unhandled function/method '{fcn_def_text}'.")
            exit(1)
        return re.sub(
            rb"fieldFromInstruction",
            b"fieldFromInstruction_%d" % inst_width,
            get_text(src, ffi_call.start_byte, ffi_call.end_byte),
        )
