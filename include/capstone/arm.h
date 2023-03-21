#ifndef CAPSTONE_ARM_H
#define CAPSTONE_ARM_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

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

/// ARM condition code
typedef enum arm_cc {
	ARM_CC_INVALID = 0,
	ARM_CC_EQ,            ///< Equal                      Equal
	ARM_CC_NE,            ///< Not equal                  Not equal, or unordered
	ARM_CC_HS,            ///< Carry set                  >, ==, or unordered
	ARM_CC_LO,            ///< Carry clear                Less than
	ARM_CC_MI,            ///< Minus, negative            Less than
	ARM_CC_PL,            ///< Plus, positive or zero     >, ==, or unordered
	ARM_CC_VS,            ///< Overflow                   Unordered
	ARM_CC_VC,            ///< No overflow                Not unordered
	ARM_CC_HI,            ///< Unsigned higher            Greater than, or unordered
	ARM_CC_LS,            ///< Unsigned lower or same     Less than or equal
	ARM_CC_GE,            ///< Greater than or equal      Greater than or equal
	ARM_CC_LT,            ///< Less than                  Less than, or unordered
	ARM_CC_GT,            ///< Greater than               Greater than
	ARM_CC_LE,            ///< Less than or equal         <, ==, or unordered
	ARM_CC_AL             ///< Always (unconditional)     Always (unconditional)
} arm_cc;

typedef enum arm_sysreg {
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

	// independent registers
	ARM_SYSREG_APSR = 256,
	ARM_SYSREG_APSR_G,
	ARM_SYSREG_APSR_NZCVQ,
	ARM_SYSREG_APSR_NZCVQG,

	ARM_SYSREG_IAPSR,
	ARM_SYSREG_IAPSR_G,
	ARM_SYSREG_IAPSR_NZCVQG,
	ARM_SYSREG_IAPSR_NZCVQ,

	ARM_SYSREG_EAPSR,
	ARM_SYSREG_EAPSR_G,
	ARM_SYSREG_EAPSR_NZCVQG,
	ARM_SYSREG_EAPSR_NZCVQ,

	ARM_SYSREG_XPSR,
	ARM_SYSREG_XPSR_G,
	ARM_SYSREG_XPSR_NZCVQG,
	ARM_SYSREG_XPSR_NZCVQ,

	ARM_SYSREG_IPSR,
	ARM_SYSREG_EPSR,
	ARM_SYSREG_IEPSR,

	ARM_SYSREG_MSP,
	ARM_SYSREG_PSP,
	ARM_SYSREG_PRIMASK,
	ARM_SYSREG_BASEPRI,
	ARM_SYSREG_BASEPRI_MAX,
	ARM_SYSREG_FAULTMASK,
	ARM_SYSREG_CONTROL,
	ARM_SYSREG_MSPLIM,
	ARM_SYSREG_PSPLIM,
	ARM_SYSREG_MSP_NS,
	ARM_SYSREG_PSP_NS,
	ARM_SYSREG_MSPLIM_NS,
	ARM_SYSREG_PSPLIM_NS,
	ARM_SYSREG_PRIMASK_NS,
	ARM_SYSREG_BASEPRI_NS,
	ARM_SYSREG_FAULTMASK_NS,
	ARM_SYSREG_CONTROL_NS,
	ARM_SYSREG_SP_NS,

	// Banked Registers
	ARM_SYSREG_R8_USR,
	ARM_SYSREG_R9_USR,
	ARM_SYSREG_R10_USR,
	ARM_SYSREG_R11_USR,
	ARM_SYSREG_R12_USR,
	ARM_SYSREG_SP_USR,
	ARM_SYSREG_LR_USR,
	ARM_SYSREG_R8_FIQ,
	ARM_SYSREG_R9_FIQ,
	ARM_SYSREG_R10_FIQ,
	ARM_SYSREG_R11_FIQ,
	ARM_SYSREG_R12_FIQ,
	ARM_SYSREG_SP_FIQ,
	ARM_SYSREG_LR_FIQ,
	ARM_SYSREG_LR_IRQ,
	ARM_SYSREG_SP_IRQ,
	ARM_SYSREG_LR_SVC,
	ARM_SYSREG_SP_SVC,
	ARM_SYSREG_LR_ABT,
	ARM_SYSREG_SP_ABT,
	ARM_SYSREG_LR_UND,
	ARM_SYSREG_SP_UND,
	ARM_SYSREG_LR_MON,
	ARM_SYSREG_SP_MON,
	ARM_SYSREG_ELR_HYP,
	ARM_SYSREG_SP_HYP,

	ARM_SYSREG_SPSR_FIQ,
	ARM_SYSREG_SPSR_IRQ,
	ARM_SYSREG_SPSR_SVC,
	ARM_SYSREG_SPSR_ABT,
	ARM_SYSREG_SPSR_UND,
	ARM_SYSREG_SPSR_MON,
	ARM_SYSREG_SPSR_HYP,
} arm_sysreg;

/// The memory barrier constants map directly to the 4-bit encoding of
/// the option field for Memory Barrier operations.
typedef enum arm_mem_barrier {
	ARM_MB_INVALID = 0,
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
} arm_mem_barrier;

/// Operand type for instruction's operands
typedef enum arm_op_type {
	ARM_OP_INVALID = 0, ///< = CS_OP_INVALID (Uninitialized).
	ARM_OP_REG, ///< = CS_OP_REG (Register operand).
	ARM_OP_IMM, ///< = CS_OP_IMM (Immediate operand).
	ARM_OP_MEM, ///< = CS_OP_MEM (Memory operand).
	ARM_OP_FP,  ///< = CS_OP_FP (Floating-Point operand).
	ARM_OP_PRED, ///< CS_OP_PRED (Predicate operand).
	ARM_OP_CIMM = 64, ///< C-Immediate (coprocessor registers)
	ARM_OP_PIMM, ///< P-Immediate (coprocessor registers)
	ARM_OP_SETEND,	///< operand for SETEND instruction
	ARM_OP_SYSREG,	///< MSR/MRS special register operand
	ARM_OP_VPRED_R, ///< Vector predicate. Leaves inactive lanes of output vector register unchanged.
	ARM_OP_VPRED_N, ///< Vector predicate. Don't preserved inactive lanes of output register.
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

/// Instruction structure
typedef struct cs_arm {
	bool usermode;	///< User-mode registers to be loaded (for LDM/STM instructions)
	int vector_size; 	///< Scalar size for vector instructions
	arm_vectordata_type vector_data; ///< Data type for elements of vector instructions
	arm_cpsmode_type cps_mode;	///< CPS mode for CPS instruction
	arm_cpsflag_type cps_flag;	///< CPS mode for CPS instruction
	arm_cc cc;			///< conditional code for this insn
	int /* ARMVCC_VPTCodes */ vcc;	///< Vector conditional code for this instruction.
	bool update_flags;	///< does this insn update flags?
	bool writeback;		///< does this insn write-back?
	bool post_index;	///< only set if writeback is 'True', if 'False' pre-index, otherwise post.
	arm_mem_barrier mem_barrier;	///< Option for some memory barrier instructions

	/// Number of operands of this instruction,
	/// or 0 when instruction has no operand.
	uint8_t op_count;

	cs_arm_op operands[36];	///< operands for this instruction.
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
