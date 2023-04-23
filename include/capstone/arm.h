#ifndef CAPSTONE_ARM_H
#define CAPSTONE_ARM_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <string.h>

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

// Enums corresponding to ARM condition codes
// The CondCodes constants map directly to the 4-bit encoding of the
// condition field for predicated instructions.
typedef enum CondCodes {
  // Meaning (integer)          Meaning (floating-point)
  ARMCC_EQ, // Equal                      Equal
  ARMCC_NE, // Not equal                  Not equal, or unordered
  ARMCC_HS, // Carry set                  >, ==, or unordered
  ARMCC_LO, // Carry clear                Less than
  ARMCC_MI, // Minus, negative            Less than
  ARMCC_PL, // Plus, positive or zero     >, ==, or unordered
  ARMCC_VS, // Overflow                   Unordered
  ARMCC_VC, // No overflow                Not unordered
  ARMCC_HI, // Unsigned higher            Greater than, or unordered
  ARMCC_LS, // Unsigned lower or same     Less than or equal
  ARMCC_GE, // Greater than or equal      Greater than or equal
  ARMCC_LT, // Less than                  Less than, or unordered
  ARMCC_GT, // Greater than               Greater than
  ARMCC_LE, // Less than or equal         <, ==, or unordered
  ARMCC_AL, // Always (unconditional)     Always (unconditional)
  ARMCC_UNDEF = 15, // Undefined
} ARMCC_CondCodes;

inline static ARMCC_CondCodes ARMCC_getOppositeCondition(ARMCC_CondCodes CC)
{
  switch (CC) {
  default:
    // llvm_unreachable("Unknown condition code");
    assert(0);
  case ARMCC_EQ:
    return ARMCC_NE;
  case ARMCC_NE:
    return ARMCC_EQ;
  case ARMCC_HS:
    return ARMCC_LO;
  case ARMCC_LO:
    return ARMCC_HS;
  case ARMCC_MI:
    return ARMCC_PL;
  case ARMCC_PL:
    return ARMCC_MI;
  case ARMCC_VS:
    return ARMCC_VC;
  case ARMCC_VC:
    return ARMCC_VS;
  case ARMCC_HI:
    return ARMCC_LS;
  case ARMCC_LS:
    return ARMCC_HI;
  case ARMCC_GE:
    return ARMCC_LT;
  case ARMCC_LT:
    return ARMCC_GE;
  case ARMCC_GT:
    return ARMCC_LE;
  case ARMCC_LE:
    return ARMCC_GT;
  }
}

/// getSwappedCondition - assume the flags are set by MI(a,b), return
/// the condition code if we modify the instructions such that flags are
/// set by MI(b,a).
inline static ARMCC_CondCodes ARMCC_getSwappedCondition(ARMCC_CondCodes CC)
{
  switch (CC) {
  default:
    return ARMCC_AL;
  case ARMCC_EQ:
    return ARMCC_EQ;
  case ARMCC_NE:
    return ARMCC_NE;
  case ARMCC_HS:
    return ARMCC_LS;
  case ARMCC_LO:
    return ARMCC_HI;
  case ARMCC_HI:
    return ARMCC_LO;
  case ARMCC_LS:
    return ARMCC_HS;
  case ARMCC_GE:
    return ARMCC_LE;
  case ARMCC_LT:
    return ARMCC_GT;
  case ARMCC_GT:
    return ARMCC_LT;
  case ARMCC_LE:
    return ARMCC_GE;
  }
}

typedef enum VPTCodes {
  ARMVCC_None = 0,
  ARMVCC_Then,
  ARMVCC_Else
} ARMVCC_VPTCodes;

/// Mask values for IT and VPT Blocks, to be used by MCOperands.
/// Note that this is different from the "real" encoding used by the
/// instructions. In this encoding, the lowest set bit indicates the end of
/// the encoding, and above that, "1" indicates an else, while "0" indicates
/// a then.
///   Tx = x100
///   Txy = xy10
///   Txyz = xyz1
typedef enum PredBlockMask {
  ARM_T = 0b1000,
  ARM_TT = 0b0100,
  ARM_TE = 0b1100,
  ARM_TTT = 0b0010,
  ARM_TTE = 0b0110,
  ARM_TEE = 0b1110,
  ARM_TET = 0b1010,
  ARM_TTTT = 0b0001,
  ARM_TTTE = 0b0011,
  ARM_TTEE = 0b0111,
  ARM_TTET = 0b0101,
  ARM_TEEE = 0b1111,
  ARM_TEET = 0b1101,
  ARM_TETT = 0b1001,
  ARM_TETE = 0b1011
} ARM_PredBlockMask;

// Expands a PredBlockMask by adding an E or a T at the end, depending on Kind.
// e.g ExpandPredBlockMask(T, Then) = TT, ExpandPredBlockMask(TT, Else) = TTE,
// and so on.
inline static const char *ARMVPTPredToString(ARMVCC_VPTCodes CC)
{
  switch (CC) {
  case ARMVCC_None:
    return "none";
  case ARMVCC_Then:
    return "t";
  case ARMVCC_Else:
    return "e";
  }
  assert(0 && "Unknown VPT code");
}

inline static unsigned ARMVectorCondCodeFromString(const char CC)
{
  switch (CC) {
  default:
    return ~0U;
  case 't':
    return ARMVCC_Then;
  case 'e':
    return ARMVCC_Else;
  }
}

inline static const char *ARMCondCodeToString(ARMCC_CondCodes CC)
{
  switch (CC) {
  case ARMCC_EQ:
    return "eq";
  case ARMCC_NE:
    return "ne";
  case ARMCC_HS:
    return "hs";
  case ARMCC_LO:
    return "lo";
  case ARMCC_MI:
    return "mi";
  case ARMCC_PL:
    return "pl";
  case ARMCC_VS:
    return "vs";
  case ARMCC_VC:
    return "vc";
  case ARMCC_HI:
    return "hi";
  case ARMCC_LS:
    return "ls";
  case ARMCC_GE:
    return "ge";
  case ARMCC_LT:
    return "lt";
  case ARMCC_GT:
    return "gt";
  case ARMCC_LE:
    return "le";
  case ARMCC_AL:
    return "al";
  }
  assert(0 && "Unknown condition code");
}

inline static unsigned ARMCondCodeFromString(const char *CC)
{
  if (strcmp("eq", CC) == 0)
    return ARMCC_EQ;
  else if (strcmp("ne", CC) == 0)
    return ARMCC_NE;
  else if (strcmp("hs", CC) == 0)
    return ARMCC_HS;
  else if (strcmp("cs", CC) == 0)
    return ARMCC_HS;
  else if (strcmp("lo", CC) == 0)
    return ARMCC_LO;
  else if (strcmp("cc", CC) == 0)
    return ARMCC_LO;
  else if (strcmp("mi", CC) == 0)
    return ARMCC_MI;
  else if (strcmp("pl", CC) == 0)
    return ARMCC_PL;
  else if (strcmp("vs", CC) == 0)
    return ARMCC_VS;
  else if (strcmp("vc", CC) == 0)
    return ARMCC_VC;
  else if (strcmp("hi", CC) == 0)
    return ARMCC_HI;
  else if (strcmp("ls", CC) == 0)
    return ARMCC_LS;
  else if (strcmp("ge", CC) == 0)
    return ARMCC_GE;
  else if (strcmp("lt", CC) == 0)
    return ARMCC_LT;
  else if (strcmp("gt", CC) == 0)
    return ARMCC_GT;
  else if (strcmp("le", CC) == 0)
    return ARMCC_LE;
  else if (strcmp("al", CC) == 0)
    return ARMCC_AL;
  return (~0U);
}

/// ARM shift type
typedef enum arm_shifter {
	ARM_SFT_INVALID = 0,
	ARM_SFT_ASR,	///< shift with immediate const
	ARM_SFT_LSL,	///< shift with immediate const
	ARM_SFT_LSR,	///< shift with immediate const
	ARM_SFT_ROR,	///< shift with immediate const
	ARM_SFT_RRX,	///< shift with immediate const
	ARM_SFT_ASR_REG,	///< shift with register
	ARM_SFT_LSL_REG,	///< shift with register
	ARM_SFT_LSR_REG,	///< shift with register
	ARM_SFT_ROR_REG,	///< shift with register
	ARM_SFT_RRX_REG,	///< shift with register
} arm_shifter;

/// The memory barrier constants map directly to the 4-bit encoding of
/// the option field for Memory Barrier operations.
typedef enum MemBOpt {
	ARM_MB_RESERVED_0,
	ARM_MB_OSHLD,
	ARM_MB_OSHST,
	ARM_MB_OSH,
	ARM_MB_RESERVED_4,
	ARM_MB_NSHLD,
	ARM_MB_NSHST,
	ARM_MB_NSH,
	ARM_MB_RESERVED_8,
	ARM_MB_ISHLD,
	ARM_MB_ISHST,
	ARM_MB_ISH,
	ARM_MB_RESERVED_12,
	ARM_MB_LD,
	ARM_MB_ST,
	ARM_MB_SY,
} arm_mem_bo_opt;

typedef enum {
	/// Special registers for MSR
	ARM_SYSREG_INVALID = 0,

	// SPSR* registers can be OR combined
	ARM_SYSREG_SPSR_C = 1,
	ARM_SYSREG_SPSR_X = 2,
	ARM_SYSREG_SPSR_S = 4,
	ARM_SYSREG_SPSR_F = 8,

	// CPSR* registers can be OR combined
	ARM_SYSREG_CPSR_C = 16,
	ARM_SYSREG_CPSR_X = 32,
	ARM_SYSREG_CPSR_S = 64,
	ARM_SYSREG_CPSR_F = 128,
} arm_sysreg_bits;

typedef enum {
#include "inc/ARMGenCSSystemRegisterEnum.inc"
} arm_sysreg;

/// Operand type for instruction's operands
typedef enum arm_op_type {
	ARM_OP_INVALID = 0, ///< = CS_OP_INVALID (Uninitialized).
	ARM_OP_REG, ///< = CS_OP_REG (Register operand).
	ARM_OP_IMM, ///< = CS_OP_IMM (Immediate operand).
	ARM_OP_FP,  ///< = CS_OP_FP (Floating-Point operand).
	ARM_OP_PRED, ///< CS_OP_PRED (Predicate operand).
	ARM_OP_CIMM = 64, ///< C-Immediate (coprocessor registers)
	ARM_OP_PIMM, ///< P-Immediate (coprocessor registers)
	ARM_OP_SETEND,	///< operand for SETEND instruction
	ARM_OP_SYSREG,	///< MSR/MRS special register operand
	ARM_OP_VPRED_R, ///< Vector predicate. Leaves inactive lanes of output vector register unchanged.
	ARM_OP_VPRED_N, ///< Vector predicate. Don't preserved inactive lanes of output register.
	ARM_OP_MEM = 0x80, ///< = CS_OP_MEM (Memory operand).
} arm_op_type;

/// Operand type for SETEND instruction
typedef enum arm_setend_type {
	ARM_SETEND_INVALID = 0,	///< Uninitialized.
	ARM_SETEND_BE,	///< BE operand.
	ARM_SETEND_LE, ///< LE operand
} arm_setend_type;

typedef enum arm_cpsmode_type {
	ARM_CPSMODE_INVALID = 0,
	ARM_CPSMODE_IE = 2,
	ARM_CPSMODE_ID = 3
} arm_cpsmode_type;

/// Operand type for SETEND instruction
typedef enum arm_cpsflag_type {
	ARM_CPSFLAG_INVALID = 0,
	ARM_CPSFLAG_F = 1,
	ARM_CPSFLAG_I = 2,
	ARM_CPSFLAG_A = 4,
	ARM_CPSFLAG_NONE = 16,	///< no flag
} arm_cpsflag_type;

/// Data type for elements of vector instructions.
typedef enum arm_vectordata_type {
	ARM_VECTORDATA_INVALID = 0,

	// Integer type
	ARM_VECTORDATA_I8,
	ARM_VECTORDATA_I16,
	ARM_VECTORDATA_I32,
	ARM_VECTORDATA_I64,

	// Signed integer type
	ARM_VECTORDATA_S8,
	ARM_VECTORDATA_S16,
	ARM_VECTORDATA_S32,
	ARM_VECTORDATA_S64,

	// Unsigned integer type
	ARM_VECTORDATA_U8,
	ARM_VECTORDATA_U16,
	ARM_VECTORDATA_U32,
	ARM_VECTORDATA_U64,

	// Data type for VMUL/VMULL
	ARM_VECTORDATA_P8,

	// Floating type
	ARM_VECTORDATA_F16,
	ARM_VECTORDATA_F32,
	ARM_VECTORDATA_F64,

	// Convert float <-> float
	ARM_VECTORDATA_F16F64,	// f16.f64
	ARM_VECTORDATA_F64F16,	// f64.f16
	ARM_VECTORDATA_F32F16,	// f32.f16
	ARM_VECTORDATA_F16F32,	// f32.f16
	ARM_VECTORDATA_F64F32,	// f64.f32
	ARM_VECTORDATA_F32F64,	// f32.f64

	// Convert integer <-> float
	ARM_VECTORDATA_S32F32,	// s32.f32
	ARM_VECTORDATA_U32F32,	// u32.f32
	ARM_VECTORDATA_F32S32,	// f32.s32
	ARM_VECTORDATA_F32U32,	// f32.u32
	ARM_VECTORDATA_F64S16,	// f64.s16
	ARM_VECTORDATA_F32S16,	// f32.s16
	ARM_VECTORDATA_F64S32,	// f64.s32
	ARM_VECTORDATA_S16F64,	// s16.f64
	ARM_VECTORDATA_S16F32,	// s16.f64
	ARM_VECTORDATA_S32F64,	// s32.f64
	ARM_VECTORDATA_U16F64,	// u16.f64
	ARM_VECTORDATA_U16F32,	// u16.f32
	ARM_VECTORDATA_U32F64,	// u32.f64
	ARM_VECTORDATA_F64U16,	// f64.u16
	ARM_VECTORDATA_F32U16,	// f32.u16
	ARM_VECTORDATA_F64U32,	// f64.u32
	ARM_VECTORDATA_F16U16,	// f16.u16
	ARM_VECTORDATA_U16F16,	// u16.f16
	ARM_VECTORDATA_F16U32,	// f16.u32
	ARM_VECTORDATA_U32F16,	// u32.f16
} arm_vectordata_type;

/// ARM registers
typedef enum arm_reg {
	#include "inc/ARMGenCSRegEnum.inc"

	// alias registers
	ARM_REG_R13 = ARM_REG_SP,
	ARM_REG_R14 = ARM_REG_LR,
	ARM_REG_R15 = ARM_REG_PC,

	ARM_REG_SB = ARM_REG_R9,
	ARM_REG_SL = ARM_REG_R10,
	ARM_REG_FP = ARM_REG_R11,
	ARM_REG_IP = ARM_REG_R12,
} arm_reg;

/// Instruction's operand referring to memory
/// This is associated with ARM_OP_MEM operand type above
typedef struct arm_op_mem {
	arm_reg base;	///< base register
	arm_reg index;	///< index register
	int scale;	///< scale for index register (can be 1, or -1)
	int disp;	///< displacement/offset value
	/// left-shift on index register, or 0 if irrelevant
	/// NOTE: this value can also be fetched via operand.shift.value
	int lshift;
} arm_op_mem;

/// Instruction operand
typedef struct cs_arm_op {
	int vector_index;	///< Vector Index for some vector operands (or -1 if irrelevant)

	struct {
		arm_shifter type;
		unsigned int value;
	} shift;

	arm_op_type type;	///< operand type

	union {
		int reg;	///< register value for REG/SYSREG operand
		int32_t imm;			///< immediate value for C-IMM, P-IMM or IMM operand
		int pred;			///< Predicate operand value.
		double fp;			///< floating point value for FP operand
		arm_op_mem mem;		///< base/index/scale/disp value for MEM operand
		arm_setend_type setend; ///< SETEND instruction's operand type
	};

	/// in some instructions, an operand can be subtracted or added to
	/// the base register,
	/// if TRUE, this operand is subtracted. otherwise, it is added.
	bool subtracted;

	/// How is this operand accessed? (READ, WRITE or READ|WRITE)
	/// This field is combined of cs_ac_type.
	/// NOTE: this field is irrelevant if engine is compiled in DIET mode.
	uint8_t access;

	/// Neon lane index for NEON instructions (or -1 if irrelevant)
	int8_t neon_lane;
} cs_arm_op;

#define MAX_ARM_OPS 36

/// Instruction structure
typedef struct cs_arm {
	bool usermode;	///< User-mode registers to be loaded (for LDM/STM instructions)
	int vector_size; 	///< Scalar size for vector instructions
	arm_vectordata_type vector_data; ///< Data type for elements of vector instructions
	arm_cpsmode_type cps_mode;	///< CPS mode for CPS instruction
	arm_cpsflag_type cps_flag;	///< CPS mode for CPS instruction
	ARMCC_CondCodes cc;		///< conditional code for this insn
	ARMVCC_VPTCodes vcc;	///< Vector conditional code for this instruction.
	bool update_flags;	///< does this insn update flags?
	bool post_index;	///< only set if writeback is 'True', if 'False' pre-index, otherwise post.
	int /* arm_mem_bo_opt */ mem_barrier;	///< Option for some memory barrier instructions
	// Check ARM_PredBlockMask for encoding details.
	uint8_t /* ARM_PredBlockMask */ pred_mask;	///< Used by IT/VPT block instructions.
	/// Number of operands of this instruction,
	/// or 0 when instruction has no operand.
	uint8_t op_count;

	cs_arm_op operands[MAX_ARM_OPS];	///< operands for this instruction.
} cs_arm;

/// ARM instruction
typedef enum arm_insn {
	ARM_INS_INVALID = 0,

	#include "inc/ARMGenCSInsnEnum.inc"

	ARM_INS_ENDING,	// <-- mark the end of the list of instructions
} arm_insn;

/// Group of ARM instructions
typedef enum arm_insn_group {
	ARM_GRP_INVALID = 0, ///< = CS_GRP_INVALID

	// Generic groups
	// all jump instructions (conditional+direct+indirect jumps)
	ARM_GRP_JUMP,	///< = CS_GRP_JUMP
	ARM_GRP_CALL,	///< = CS_GRP_CALL
	ARM_GRP_INT = 4, ///< = CS_GRP_INT
	ARM_GRP_PRIVILEGE = 6, ///< = CS_GRP_PRIVILEGE
	ARM_GRP_BRANCH_RELATIVE, ///< = CS_GRP_BRANCH_RELATIVE

	// Architecture-specific groups
	#include "inc/ARMGenCSFeatureEnum.inc"

	ARM_GRP_ENDING,
} arm_insn_group;

#ifdef __cplusplus
}
#endif

#endif
