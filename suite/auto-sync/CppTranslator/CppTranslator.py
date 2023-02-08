#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

from tree_sitter import Language, Parser, Tree, Node
import argparse
import logging as log
import sys

from tree_sitter.binding import Query

from Patches.Assert import Assert
from Patches.CheckDecoderStatus import CheckDecoderStatus
from Patches.ClassesDef import ClassesDef
from Patches.CreateOperand0 import CreateOperand0
from Patches.CreateOperand1 import CreateOperand1
from Patches.DeclarationInConditionClause import DeclarationInConditionalClause
from Patches.DecodeInstruction import DecodeInstruction
from Patches.DecoderCast import DecoderCast
from Patches.DecoderParameter import DecoderParameter
from Patches.FallThrough import FallThrough
from Patches.FeatureBits import FeatureBits
from Patches.FeatureBitsDecl import FeatureBitsDecl
from Patches.FieldFromInstr import FieldFromInstr
from Patches.GetOpcode import GetOpcode
from Patches.GetOperandRegImm import GetOperandRegImm
from Patches.GetOperand import GetOperand
from Patches.Includes import Includes
from Patches.IsOptionalDef import IsOptionalDef
from Patches.IsPredicate import IsPredicate
from Patches.LLVMFallThrough import LLVMFallThrough
from Patches.MethodToFunctions import MethodToFunction
from Patches.MethodTypeQualifier import MethodTypeQualifier
from Patches.NamespaceLLVM import NamespaceLLVM
from Patches.NamespaceAnon import NamespaceAnon
from Patches.NamespaceArch import NamespaceArch
from Patches.OutStreamParam import OutStreamParam
from Patches.PredicateBlockFunctions import PredicateBlockFunctions
from Patches.QualifiedIdentifier import QualifiedIdentifier
from Patches.Patch import Patch
from Patches.ReferencesDecl import ReferencesDecl
from Patches.STIArgument import STIArgument
from Patches.STIFeatureBits import STIFeatureBits
from Patches.STParameter import SubtargetInfoParam
from Patches.SetOpcode import SetOpcode
from Patches.SignExtend32 import SignExtend32
from Patches.SizeAssignments import SizeAssignment
from Patches.StreamOperation import StreamOperations
from Patches.TemplateDeclaration import TemplateDeclaration
from Patches.TemplateDefinition import TemplateDefinition
from Patches.TemplateParamDecl import TemplateParamDecl
from Patches.TemplateRefs import TemplateRefs
from Patches.UsingDeclaration import UsingDeclaration
from TemplateCollector import TemplateCollector


class Translator:
    ts_cpp_lang: Language = None
    parser: Parser = None
    template_collector: TemplateCollector = None
    src_paths: [Path]
    out_paths: [Path]
    conf: dict
    src = b""
    current_src_path_in: Path = None
    current_src_path_out: Path = None
    tree: Tree = None

    # Patch priorities: The bigger the number the later the patch will be applied.
    # Patches which create templates must always be executed last. Since syntax
    # in macros is no longer parsed as such (but is only recognized as macro body).
    #
    # If a patch must be executed before another patch (because the matching rules depend on it)
    # mark this dependency as you see below.
    patches: [Patch] = list()

    patch_priorities: {str: int} = {
        STIArgument.__name__: 0,
        DecodeInstruction.__name__: 0,
        FallThrough.__name__: 0,
        SizeAssignment.__name__: 0,
        FieldFromInstr.__name__: 0,
        FeatureBitsDecl.__name__: 0,
        FeatureBits.__name__: 0,
        STIFeatureBits.__name__: 0,
        Includes.__name__: 0,
        CreateOperand0.__name__: 0,
        CreateOperand1.__name__: 0,
        GetOpcode.__name__: 0,
        SetOpcode.__name__: 0,
        GetOperand.__name__: 0,
        GetOperandRegImm.__name__: 0,
        SignExtend32.__name__: 0,
        DecoderParameter.__name__: 0,
        UsingDeclaration.__name__: 0,
        DecoderCast.__name__: 0,
        IsPredicate.__name__: 0,
        IsOptionalDef.__name__: 0,
        Assert.__name__: 0,
        LLVMFallThrough.__name__: 0,
        DeclarationInConditionalClause.__name__: 0,
        SubtargetInfoParam.__name__: 0,
        OutStreamParam.__name__: 0,
        StreamOperations.__name__: 0,
        MethodToFunction.__name__: 0,
        NamespaceAnon.__name__: 0,  # ◁─────┐ "llvm" and anonymous namespaces must be removed first,
        NamespaceLLVM.__name__: 0,  # ◁─────┤ so they don't match in NamespaceArch.
        NamespaceArch.__name__: 1,  # ──────┘
        PredicateBlockFunctions.__name__: 0,
        ClassesDef.__name__: 0,  # ◁────────┐ Declarations must be extracted first from the classes.
        MethodTypeQualifier.__name__: 1,  # ┘
        # All previous patches can contain qualified identifiers (Ids with the "::" operator) in their search patterns.
        # After this patch they are removed.
        QualifiedIdentifier.__name__: 2,
        ReferencesDecl.__name__: 3,  # ◁────┐
        CheckDecoderStatus.__name__: 4,  # ─┘ Reference declarations must be removed first.
        TemplateParamDecl.__name__: 5,
        TemplateRefs.__name__: 5,
        # Template declarations are replaced with macros.
        # Those declarations are parsed as macro afterwards
        TemplateDeclaration.__name__: 5,
        # Template definitions are replaced with macros.
        # Those template functions are parsed as macro afterwards.
        TemplateDefinition.__name__: 6,
    }

    def __init__(
        self,
        arch: str,
        conf_path: Path,
        ts_grammar_path: Path,
        ts_compile_path: Path,
    ):
        self.ts_grammar_path: Path = ts_grammar_path
        self.ts_so_path: Path = ts_compile_path
        self.arch = arch

        self.load_config(conf_path)
        self.src_paths: [Path] = [Path(sp["in"]) for sp in self.conf["files_to_translate"]]
        self.out_paths: [Path] = [Path(sp["out"]) for sp in self.conf["files_to_translate"]]

        self.ts_compile_cpp()
        self.ts_set_language()
        self.init_parser()
        self.collect_template_instances()
        self.init_patches()

    def load_config(self, conf_path: Path) -> None:
        if not Path.exists(conf_path):
            log.fatal(f"Could not load arch config file at '{conf_path}'")
            exit(1)
        with open(conf_path) as f:
            conf = json.loads(f.read())
        if self.arch not in conf:
            log.fatal(f"{self.arch} has not configuration. Please the them in {conf_path}!")
            exit(1)
        self.conf = conf[self.arch]

    def ts_compile_cpp(self) -> None:
        log.info("Compile Cpp language")
        if not Path.exists(self.ts_grammar_path):
            log.fatal(f"Could not load the tree-sitter grammar at '{self.ts_grammar_path}'")
            exit(1)
        Language.build_library(str(self.ts_so_path), [self.ts_grammar_path])

    def ts_set_language(self) -> None:
        log.info(f"Load language '{self.ts_so_path}'")
        if not Path.exists(self.ts_so_path):
            log.fatal(f"Could not load the tree-sitter language shared object at '{self.ts_so_path}'")
            exit(1)
        self.ts_cpp_lang = Language(self.ts_so_path, "cpp")

    def init_parser(self) -> None:
        log.debug("Init parser")
        self.parser = Parser()
        self.parser.set_language(self.ts_cpp_lang)

    def read_src_file(self, src_path: Path) -> None:
        """Reads the file at src_path into self.src"""
        log.debug(f"Read {src_path}")
        if not Path.exists(src_path):
            log.fatal(f"Could not open the source file '{src_path}'")
            exit(1)
        with open(src_path) as f:
            self.src = bytes(f.read(), "utf8")

    def init_patches(self):
        log.debug("Init patches")
        priorities = dict(sorted(self.patch_priorities.items(), key=lambda item: item[1]))
        patch: Patch = None
        for ptype, p in priorities.items():
            if ptype == CheckDecoderStatus.__name__:
                patch = CheckDecoderStatus(p)
            elif ptype == ReferencesDecl.__name__:
                patch = ReferencesDecl(p)
            elif ptype == FieldFromInstr.__name__:
                patch = FieldFromInstr(p)
            elif ptype == FeatureBitsDecl.__name__:
                patch = FeatureBitsDecl(p)
            elif ptype == FeatureBits.__name__:
                patch = FeatureBits(p, bytes(self.arch, "utf8"))
            elif ptype == STIFeatureBits.__name__:
                patch = STIFeatureBits(p, bytes(self.arch, "utf8"))
            elif ptype == QualifiedIdentifier.__name__:
                patch = QualifiedIdentifier(p)
            elif ptype == Includes.__name__:
                patch = Includes(p, self.arch)
            elif ptype == ClassesDef.__name__:
                patch = ClassesDef(p)
            elif ptype == CreateOperand0.__name__:
                patch = CreateOperand0(p)
            elif ptype == CreateOperand1.__name__:
                patch = CreateOperand1(p)
            elif ptype == GetOpcode.__name__:
                patch = GetOpcode(p)
            elif ptype == SetOpcode.__name__:
                patch = SetOpcode(p)
            elif ptype == GetOperand.__name__:
                patch = GetOperand(p)
            elif ptype == SignExtend32.__name__:
                patch = SignExtend32(p)
            elif ptype == TemplateDeclaration.__name__:
                patch = TemplateDeclaration(p, self.template_collector)
            elif ptype == TemplateDefinition.__name__:
                patch = TemplateDefinition(p, self.template_collector)
            elif ptype == DecoderParameter.__name__:
                patch = DecoderParameter(p)
            elif ptype == TemplateRefs.__name__:
                patch = TemplateRefs(p)
            elif ptype == TemplateParamDecl.__name__:
                patch = TemplateParamDecl(p)
            elif ptype == MethodTypeQualifier.__name__:
                patch = MethodTypeQualifier(p)
            elif ptype == UsingDeclaration.__name__:
                patch = UsingDeclaration(p)
            elif ptype == NamespaceLLVM.__name__:
                patch = NamespaceLLVM(p)
            elif ptype == DecoderCast.__name__:
                patch = DecoderCast(p)
            elif ptype == IsPredicate.__name__:
                patch = IsPredicate(p)
            elif ptype == IsOptionalDef.__name__:
                patch = IsOptionalDef(p)
            elif ptype == Assert.__name__:
                patch = Assert(p)
            elif ptype == LLVMFallThrough.__name__:
                patch = LLVMFallThrough(p)
            elif ptype == DeclarationInConditionalClause.__name__:
                patch = DeclarationInConditionalClause(p)
            elif ptype == OutStreamParam.__name__:
                patch = OutStreamParam(p)
            elif ptype == MethodToFunction.__name__:
                patch = MethodToFunction(p)
            elif ptype == GetOperandRegImm.__name__:
                patch = GetOperandRegImm(p)
            elif ptype == StreamOperations.__name__:
                patch = StreamOperations(p)
            elif ptype == SubtargetInfoParam.__name__:
                patch = SubtargetInfoParam(p)
            elif ptype == SizeAssignment.__name__:
                patch = SizeAssignment(p)
            elif ptype == NamespaceArch.__name__:
                patch = NamespaceArch(p)
            elif ptype == NamespaceAnon.__name__:
                patch = NamespaceAnon(p)
            elif ptype == PredicateBlockFunctions.__name__:
                patch = PredicateBlockFunctions(p)
            elif ptype == FallThrough.__name__:
                patch = FallThrough(p)
            elif ptype == DecodeInstruction.__name__:
                patch = DecodeInstruction(p)
            elif ptype == STIArgument.__name__:
                patch = STIArgument(p)
            else:
                log.fatal(f"Patch type {ptype} not in Patch init routine.")
                exit(1)
            self.patches.append(patch)

    def parse(self, src_path: Path) -> None:
        self.read_src_file(src_path)
        log.debug("Parse source code")
        self.tree = self.parser.parse(self.src, keep_text=True)

    def patch_src(self, p_list: [(bytes, Node)]) -> None:
        if len(p_list) == 0:
            return
        # Sort list of patches descending so the patches which are last in the file
        # get patched first. This way the indices of the code snippets before
        # don't change.
        patches = sorted(p_list, key=lambda x: x[1].start_byte, reverse=True)

        new_src = b""
        patch: bytes
        node: Node
        for patch, node in patches:
            start_byte: int = node.start_byte
            old_end_byte: int = node.end_byte
            start_point: (int, int) = node.start_point
            old_end_point: (int, int) = node.end_point

            new_src = self.src[:start_byte] + patch + self.src[old_end_byte:]
            self.src = new_src
            d = len(patch) - (old_end_byte - start_byte)
            self.tree.edit(
                start_byte=start_byte,
                old_end_byte=old_end_byte,
                new_end_byte=old_end_byte + d,
                start_point=start_point,
                old_end_point=old_end_point,
                new_end_point=(old_end_point[0], old_end_point[1] + d),
            )
        self.tree = self.parser.parse(new_src, self.tree, keep_text=True)

    def translate(self) -> None:
        for self.current_src_path_in, self.current_src_path_out in zip(self.src_paths, self.out_paths):
            log.info(f"Translate '{self.current_src_path_in}'")
            self.parse(self.current_src_path_in)
            patch: Patch
            for patch in self.patches:
                pattern: str = patch.get_search_pattern()

                # Each patch has a capture which includes the whole subtree searched for.
                # Additionally, it can include captures within this subtree.
                # Here we bundle these captures together.
                query: Query = self.ts_cpp_lang.query(pattern)
                captures_bundle: [[(Node, str)]] = list()
                for q in query.captures(self.tree.root_node):
                    if q[1] == patch.get_main_capture_name():
                        # The main capture the patch is looking for.
                        captures_bundle.append([q])
                    else:
                        # A capture which is part of the main capture.
                        # Add it to the bundle.
                        captures_bundle[-1].append(q)

                log.debug(f"Patch {patch.__class__.__name__} (to patch: {len(captures_bundle)}).")

                p_list: (bytes, Node) = list()
                cb: [(Node, str)]
                for cb in captures_bundle:
                    patch_kwargs = self.get_patch_kwargs(patch)
                    bytes_patch: bytes = patch.get_patch(cb, self.src, **patch_kwargs)
                    p_list.append((bytes_patch, cb[0][0]))
                self.patch_src(p_list)
            log.info(f"Patched file at '{self.current_src_path_out}'")
            with open(self.current_src_path_out, "w") as f:
                f.write(self.src.decode("utf8"))
        self.run_clang_format()

    def collect_template_instances(self):
        search_paths = [Path(p) for p in self.conf["files_for_template_search"]]
        self.template_collector = TemplateCollector(self.parser, self.ts_cpp_lang, search_paths)
        self.template_collector.collect()

    def get_patch_kwargs(self, patch):
        if isinstance(patch, Includes):
            return {"filename": self.current_src_path_in.name}
        return dict()

    def run_clang_format(self):
        for out_file in self.out_paths:
            log.info(f"Format {out_file}")
            subprocess.run(["clang-format-13", "-style=file", "-i", out_file])


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="CppTranslator",
        description="Capstones C++ to C translator for LLVM source files",
    )
    parser.add_argument("-a", dest="arch", help="Name of target architecture.", choices=["ARM"], required=True)
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "fatal"],
        default="info",
    )
    parser.add_argument(
        "-c", dest="arch_config", help="Config file for architectures.", default="arch_config.json", type=Path
    )
    parser.add_argument(
        "-g", dest="grammar", help="Path to the tree-sitter C++ grammar.", default="vendor/tree-sitter-cpp", type=Path
    )
    parser.add_argument(
        "-l", dest="lang_so", help="File to store the compiled C++ language.", default="build/ts-cpp.so", type=Path
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    args = parse_args()
    log.basicConfig(
        level=convert_loglevel(args.verbosity),
        stream=sys.stdout,
        format="%(levelname)-5s - %(message)s",
    )
    translator = Translator(args.arch, args.arch_config, args.grammar, args.lang_so)
    translator.translate()
