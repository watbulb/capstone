/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically translated source file from LLVM. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Only small edits allowed. */
/* For multiple similiar edits, please create a Patch for the translator. */

/* Capstone's C++ file translator: */
/* https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */

//===-- PPCPredicates.h - PPC Branch Predicate Information ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file describes the PowerPC branch predicates.
//
//===----------------------------------------------------------------------===//

#ifndef CS_PPC_PREDICATES_H
#define CS_PPC_PREDICATES_H

// GCC #defines PPC on Linux but we use it as our namespace name
#undef PPC

// Generated files will use "namespace PPC". To avoid symbol clash,
// undefine PPC here. PPC may be predefined on some hosts.
#undef PPC

/// Predicate - These are "(BI << 5) | BO"  for various predicates.
typedef enum {
	PPC_PRED_LT = (0 << 5) | 12,
	PPC_PRED_LE = (1 << 5) | 4,
	PPC_PRED_EQ = (2 << 5) | 12,
	PPC_PRED_GE = (0 << 5) | 4,
	PPC_PRED_GT = (1 << 5) | 12,
	PPC_PRED_NE = (2 << 5) | 4,
	PPC_PRED_UN = (3 << 5) | 12,
	PPC_PRED_NU = (3 << 5) | 4,
	PPC_PRED_LT_MINUS = (0 << 5) | 14,
	PPC_PRED_LE_MINUS = (1 << 5) | 6,
	PPC_PRED_EQ_MINUS = (2 << 5) | 14,
	PPC_PRED_GE_MINUS = (0 << 5) | 6,
	PPC_PRED_GT_MINUS = (1 << 5) | 14,
	PPC_PRED_NE_MINUS = (2 << 5) | 6,
	PPC_PRED_UN_MINUS = (3 << 5) | 14,
	PPC_PRED_NU_MINUS = (3 << 5) | 6,
	PPC_PRED_LT_PLUS = (0 << 5) | 15,
	PPC_PRED_LE_PLUS = (1 << 5) | 7,
	PPC_PRED_EQ_PLUS = (2 << 5) | 15,
	PPC_PRED_GE_PLUS = (0 << 5) | 7,
	PPC_PRED_GT_PLUS = (1 << 5) | 15,
	PPC_PRED_NE_PLUS = (2 << 5) | 7,
	PPC_PRED_UN_PLUS = (3 << 5) | 15,
	PPC_PRED_NU_PLUS = (3 << 5) | 7,

	// SPE scalar compare instructions always set the GT bit.
	PPC_PRED_SPE = PPC_PRED_GT,

	// When dealing with individual condition-register bits, we have simple set
	// and unset predicates.
	PPC_PRED_BIT_SET = 1024,
	PPC_PRED_BIT_UNSET = 1025
} PPC_Predicate;

// Bit for branch taken (plus) or not-taken (minus) hint
enum BranchHintBit {
	PPC_BR_NO_HINT = 0x0,
	PPC_BR_NONTAKEN_HINT = 0x2,
	PPC_BR_TAKEN_HINT = 0x3,
	PPC_BR_HINT_MASK = 0x3
};

/// Invert the specified predicate.  != -> ==, < -> >=.
PPC_Predicate InvertPredicate(PPC_Predicate Opcode);
/// Assume the condition register is set by MI(a,b), return the predicate if
/// we modify the instructions such that condition register is set by MI(b,a).
PPC_Predicate getSwappedPredicate(PPC_Predicate Opcode);
/// Return the condition without hint bits.
inline unsigned PPC_getPredicateCondition(PPC_Predicate Opcode)
{
	return (unsigned)(Opcode & ~PPC_BR_HINT_MASK);
}

/// Return the hint bits of the predicate.
inline unsigned PPC_getPredicateHint(PPC_Predicate Opcode)
{
	return (unsigned)(Opcode & PPC_BR_HINT_MASK);
}

/// Return predicate consisting of specified condition and hint bits.
inline PPC_Predicate PPC_getPredicate(unsigned Condition, unsigned Hint)
{
	return (PPC_Predicate)((Condition & ~PPC_BR_HINT_MASK) | (Hint & PPC_BR_HINT_MASK));
}

#endif // CS_PPC_PREDICATES_H
