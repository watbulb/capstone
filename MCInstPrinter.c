/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org>, 2023 */

#include "MCInstPrinter.h"
#include <capstone/platform.h>

const char *matchAliasPatterns(const MCInst *MI, const AliasMatchingData *M) {
  // TODO Rewrite to C
  
  // Binary search by opcode. Return false if there are no aliases for this
  // opcode.
  // auto It = lower_bound(M.OpToPatterns, MI->getOpcode(),
  //                       [](const PatternsForOpcode &L, unsigned Opcode) {
  //                         return L.Opcode < Opcode;
  //                       });
  // if (It == M.OpToPatterns.end() || It->Opcode != MI->getOpcode())
  //   return nullptr;

  // // Try all patterns for this opcode.
  // uint32_t AsmStrOffset = ~0U;
  // ArrayRef<AliasPattern> Patterns =
  //     M.Patterns.slice(It->PatternStart, It->NumPatterns);
  // for (const AliasPattern &P : Patterns) {
  //   // Check operand count first.
  //   if (MI->getNumOperands() != P.NumOperands)
  //     return nullptr;

  //   // Test all conditions for this pattern.
  //   ArrayRef<AliasPatternCond> Conds =
  //       M.PatternConds.slice(P.AliasCondStart, P.NumConds);
  //   unsigned OpIdx = 0;
  //   bool OrPredicateResult = false;
  //   if (llvm::all_of(Conds, [&](const AliasPatternCond &C) {
  //         return matchAliasCondition(*MI, STI, MRI, OpIdx, M, C,
  //                                    OrPredicateResult);
  //       })) {
  //     // If all conditions matched, use this asm string.
  //     AsmStrOffset = P.AsmStrOffset;
  //     break;
  //   }
  // }

  // // If no alias matched, don't print an alias.
  // if (AsmStrOffset == ~0U)
  //   return nullptr;

  // // Go to offset AsmStrOffset and use the null terminated string there. The
  // // offset should point to the beginning of an alias string, so it should
  // // either be zero or be preceded by a null byte.
  // assert(AsmStrOffset < M.AsmStrings.size() &&
  //        (AsmStrOffset == 0 || M.AsmStrings[AsmStrOffset - 1] == '\0') &&
  //        "bad asm string offset");
  // return M.AsmStrings.data() + AsmStrOffset;
}

// TODO Add functionality to toggle the flag.
bool getUseMarkup() { return false; }

/// Utility functions to make adding mark ups simpler.
const char *markup(const char *s) {
  if (getUseMarkup())
    return s;
  else
    return "";
}
