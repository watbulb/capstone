from tree_sitter import Tree, Node
import logging as log


class Patch:
    priority: int = None

    def __init__(self, priority: int = 0):
        self.priority = priority

    def get_search_pattern(self) -> str:
        """
        Returns a search pattern for the syntax tree of the C++ file.
        The search pattern must be formed according to:
        https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries

        Also, each pattern needs to be assigned a name in order to work.
        See: https://github.com/tree-sitter/py-tree-sitter/issues/77

        :return: The search pattern which matches a part in the syntax tree which will be patched.
        """
        log.fatal("Method must be overloaded.")
        exit()

    def get_main_capture_name(self) -> str:
        """
        :return: The name of the capture which matches the complete syntax to be patched.
        """
        log.fatal("Method must be overloaded.")
        exit()

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        """
        Patches the given subtree accordingly and returns the patch as string.

        :param src: The source code currently patched.
        :param captures: The subtree and its name which needs to be patched.
        :param **kwargs: Additional arguments the Patch might need.
        :return: The patched version of the code.
        """
        log.fatal("Method must be overloaded.")
        exit()
