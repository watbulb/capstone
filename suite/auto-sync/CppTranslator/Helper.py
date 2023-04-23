import logging as log
import shutil
import termcolor

from tree_sitter import Node


def convert_loglevel(level: str) -> int:
    if level == "debug":
        return log.DEBUG
    elif level == "info":
        return log.INFO
    elif level == "warning":
        return log.WARNING
    elif level == "error":
        return log.ERROR
    elif level == "fatal":
        return log.FATAL
    elif level == "critical":
        return log.CRITICAL
    raise ValueError(f'Unknown loglevel "{level}"')


def find_id_by_type(node: Node, node_types: [str], type_must_match: bool) -> bytes:
    """
    Recursively searches for a node sequence with given node types.

    A valid sequence is a path from !\f$node_n\f$ to !\f$node_{(n + |node\_types|-1)}\f$ where
    !\f$\forall i \in \{0, ..., |node\_types|-1\}: type(node_{(n + i)}) = node\_types_i\f$.

    If a node sequence is found, this functions returns the text associated with the
    last node in the sequence.

    :param node: Current node.
    :param node_types: List of node types.
    :param type_must_match: If true, it is mandatory for the current node that its type matches node_types[0]
    :return: The nodes text of the last node in a valid sequence of and empty string of no such sequence exists.
    """
    if len(node_types) == 0:
        # No ids left to compare to: Nothing found
        return b""

    # Set true if:
    #     current node type matches.
    #  OR
    #     parent dictates that node type match
    type_must_match = node.type == node_types[0] or type_must_match
    if type_must_match and node.type != node_types[0]:
        # This child has no matching type. Return.
        return b""

    if len(node_types) == 1 and type_must_match:
        if node.type == node_types[0]:
            # Found it
            return node.text
        else:
            # Not found. Return to parent
            return b""

    # If this nodes type matches the first in the list
    # we remove this one from the list.
    # Otherwise, give the whole list to the child (since our type does not matter).
    children_id_types = node_types[1:] if type_must_match else node_types

    # Check if any child has a matching type.
    for child in node.named_children:
        res = find_id_by_type(child, children_id_types, type_must_match)
        if res:
            # A path from this node matches the id_types!
            return res

    # None of our children matched the type list.
    return b""


def print_prominent_warning(msg: str) -> None:
    print("\n" + termcolor.colored("#" * shutil.get_terminal_size()[0], "yellow") + "\n")
    print(termcolor.colored("WARNING", "yellow", attrs=["bold"]) + "\n")
    print(msg)
    print("\n" + termcolor.colored("#" * shutil.get_terminal_size()[0], "yellow"))
    input("Press enter to continue...")


def print_prominent_info(msg: str) -> None:
    print("\n" + termcolor.colored("#" * shutil.get_terminal_size()[0], "blue") + "\n")
    print(msg)
    print("\n" + termcolor.colored("#" * shutil.get_terminal_size()[0], "blue"))
    input("Press enter to continue...")
