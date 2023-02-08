/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org>, 2023 */

#ifndef CS_MCINSTPRINTER_H
#define CS_MCINSTPRINTER_H

#include <capstone/platform.h>

/// Map from opcode to pattern list by binary search.
typedef struct {
  uint32_t Opcode;
  uint16_t PatternStart;
  uint16_t NumPatterns;
} PatternsForOpcode;

/// Data for each alias pattern. Includes feature bits, string, number of
/// operands, and a variadic list of conditions to check.
typedef struct {
  uint32_t AsmStrOffset;
  uint32_t AliasCondStart;
  uint8_t NumOperands;
  uint8_t NumConds;
} AliasPattern;

typedef enum {
  AliasPatternCond_K_Feature,	    // Match only if a feature is enabled.
  AliasPatternCond_K_NegFeature,    // Match only if a feature is disabled.
  AliasPatternCond_K_OrFeature,	    // Match only if one of a set of features is
				    // enabled.
  AliasPatternCond_K_OrNegFeature,  // Match only if one of a set of features is
				    // disabled.
  AliasPatternCond_K_EndOrFeatures, // Note end of list of K_Or(Neg)?Features.
  AliasPatternCond_K_Ignore,	    // Match any operand.
  AliasPatternCond_K_Reg,	    // Match a specific register.
  AliasPatternCond_K_TiedReg,	    // Match another already matched register.
  AliasPatternCond_K_Imm,	    // Match a specific immediate.
  AliasPatternCond_K_RegClass,	    // Match registers in a class.
  AliasPatternCond_K_Custom,	    // Call custom matcher by index.
} AliasPatternCond_CondKind;

typedef struct {
  AliasPatternCond_CondKind Kind;
  uint32_t Value;
} AliasPatternCond;

#endif // CS_MCINSTPRINTER_H
