/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org>, 2023 */

#include "MCInstPrinter.h"
#include "cs_priv.h"
#include <capstone/platform.h>

extern bool ARM_getFeatureBits(unsigned int mode, unsigned int feature);

static bool testFeatureBits(const MCInst *MI, uint32_t Value)
{
	assert(MI);
	switch (MI->csh->arch) {
	default:
		assert(0 && "Not implemented for current arch.");
	case CS_ARCH_ARM:
		return ARM_getFeatureBits(MI->csh->mode, Value);
	}
}

static bool matchAliasCondition(MCInst *MI, const MCRegisterInfo *MRI,
								unsigned *OpIdx, const AliasMatchingData *M,
								const AliasPatternCond *C,
								bool *OrPredicateResult)
{
	// Feature tests are special, they don't consume operands.
	if (C->Kind == AliasPatternCond_K_Feature)
		return testFeatureBits(MI, C->Value);
	if (C->Kind == AliasPatternCond_K_NegFeature)
		return !testFeatureBits(MI, C->Value);
	// For feature tests where just one feature is required in a list, set the
	// predicate result bit to whether the expression will return true, and only
	// return the real result at the end of list marker.
	if (C->Kind == AliasPatternCond_K_OrFeature) {
		*OrPredicateResult |= testFeatureBits(MI, C->Value);
		return true;
	}
	if (C->Kind == AliasPatternCond_K_OrNegFeature) {
		*OrPredicateResult |= !(testFeatureBits(MI, C->Value));
		return true;
	}
	if (C->Kind == AliasPatternCond_K_EndOrFeatures) {
		bool Res = *OrPredicateResult;
		*OrPredicateResult = false;
		return Res;
	}

	// Get and consume an operand.
	MCOperand *Opnd = MCInst_getOperand(MI, *OpIdx);
	++OpIdx;

	// Check the specific condition for the operand.
	switch (C->Kind) {
	case AliasPatternCond_K_Imm:
		// Operand must be a specific immediate.
		return MCOperand_isImm(Opnd) &&
			   MCOperand_getImm(Opnd) == (int32_t)C->Value;
	case AliasPatternCond_K_Reg:
		// Operand must be a specific register.
		return MCOperand_isReg(Opnd) && MCOperand_getReg(Opnd) == C->Value;
	case AliasPatternCond_K_TiedReg:
		// Operand must match the register of another operand.
		return MCOperand_isReg(Opnd) &&
			   MCOperand_getReg(Opnd) ==
				   MCOperand_getReg(MCInst_getOperand(MI, C->Value));
	case AliasPatternCond_K_RegClass:
		// Operand must be a register in this class. Value is a register class
		// id.
		return MCOperand_isReg(Opnd) &&
			   MCRegisterClass_contains(
				   MCRegisterInfo_getRegClass(MRI, C->Value),
				   MCOperand_getReg(Opnd));
	case AliasPatternCond_K_Custom:
		// Operand must match some custom criteria.
		// return M.ValidateMCOperand(Opnd, *STI, C->Value);
		assert(0 && "Custom operand condition check not implemented.");
	case AliasPatternCond_K_Ignore:
		// Operand can be anything.
		return true;
	case AliasPatternCond_K_Feature:
	case AliasPatternCond_K_NegFeature:
	case AliasPatternCond_K_OrFeature:
	case AliasPatternCond_K_OrNegFeature:
	case AliasPatternCond_K_EndOrFeatures:
		assert(0 && "handled earlier");
	}
	assert(0 && "invalid kind");
}

/// Check if PatternsForOpcode is all zero.
static inline bool validOpToPatter(const PatternsForOpcode *P)
{
	return !(P->Opcode == 0 && P->PatternStart == 0 && P->NumPatterns == 0);
}

const char *matchAliasPatterns(MCInst *MI, const AliasMatchingData *M)
{
	// TODO Rewrite to C

	// auto It = lower_bound(M.OpToPatterns, MI->getOpcode(),
	//                       [](const PatternsForOpcode &L, unsigned Opcode) {
	//                         return L.Opcode < Opcode;
	//                       });
	// if (It == M.OpToPatterns.end() || It->Opcode != MI->getOpcode())
	//   return nullptr;

	// Binary search by opcode. Return false if there are no aliases for this
	// opcode.
	unsigned MIOpcode = MI->Opcode;
	size_t i = 0;
	uint32_t PatternOpcode = M->OpToPatterns[i].Opcode;
	while (PatternOpcode < MIOpcode && validOpToPatter(&M->OpToPatterns[i]))
		PatternOpcode = M->OpToPatterns[++i].Opcode;
	if (PatternOpcode != MI->Opcode || !validOpToPatter(&M->OpToPatterns[i]))
		return NULL;

	// // Try all patterns for this opcode.
	uint32_t AsmStrOffset = ~0U;
	const AliasPattern *Patterns = M->Patterns + M->OpToPatterns->PatternStart;
	for (const AliasPattern *P = Patterns;
		 P != Patterns + M->OpToPatterns->NumPatterns; ++P) {
		// Check operand count first.
		if (MCInst_getNumOperands(MI) != P->NumOperands)
			return NULL;

		// Test all conditions for this pattern.
		const AliasPatternCond *Conds = M->PatternConds + P->AliasCondStart;
		unsigned OpIdx = 0;
		bool OrPredicateResult = false;
		for (const AliasPatternCond *C = Conds; C != Conds + P->NumConds; ++C) {
			if (matchAliasCondition(MI, MI->MRI, &OpIdx, M, C,
									&OrPredicateResult)) {
				AsmStrOffset = P->AsmStrOffset;
				break;
			}
		}
		if (AsmStrOffset != ~0U)
			break;
	}
	// If no alias matched, don't print an alias.
	if (AsmStrOffset == ~0U)
		return NULL;

	// Go to offset AsmStrOffset and use the null terminated string there. The
	// offset should point to the beginning of an alias string, so it should
	// either be zero or be preceded by a null byte.
	return M->AsmStrings + AsmStrOffset;
}
// TODO Add functionality to toggle the flag.
bool getUseMarkup() { return false; }

/// Utility functions to make adding mark ups simpler.
const char *markup(const char *s)
{
	static const char *no_markup = "";
	if (getUseMarkup())
		return s;
	else
		return no_markup;
}
