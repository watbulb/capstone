/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#include "ARMAddressingModes.h"
#ifdef CAPSTONE_HAS_ARM

#include <stdio.h>	// debug
#include <string.h>

#include "../../cs_simple_types.h"
#include "../../cs_priv.h"
#include "../../MCDisassembler.h"

#include "ARMMapping.h"
#include "ARMBaseInfo.h"
#include "ARMDisassembler.h"
#include "ARMInstPrinter.h"

const char *ARM_reg_name(csh handle, unsigned int reg) {
	if (((cs_struct *)(uintptr_t)handle)->syntax & CS_OPT_SYNTAX_NOREGNAME) {
		return getRegisterName(reg, ARM_NoRegAltName);
	}
	return getRegisterName(reg, ARM_RegNamesRaw);
}

const insn_map arm_insns[] = {
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
#include "ARMGenCSMappingInsn.inc"
};

// look for @id in @insns
// return -1 if not found
static unsigned int find_insn(unsigned int id)
{
	// binary searching since the IDs are sorted in order
	unsigned int left, right, m;
	unsigned int max = ARR_SIZE(arm_insns);

	right = max - 1;

	if (id < arm_insns[0].id || id > arm_insns[right].id)
		// not found
		return -1;

	left = 0;

	while(left <= right) {
		m = (left + right) / 2;
		if (id == arm_insns[m].id) {
			return m;
		}

		if (id < arm_insns[m].id)
			right = m - 1;
		else
			left = m + 1;
	}

	// not found
	// printf("NOT FOUNDDDDDDDDDDDDDDD id = %u\n", id);
	return -1;
}

void ARM_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned int i = find_insn(id);
	if (i != -1) {
		insn->id = arm_insns[i].mapid;

		// printf("id = %u, mapid = %u\n", id, insn->id);

		if (h->detail) {
#ifndef CAPSTONE_DIET
			cs_struct handle;
			handle.detail = h->detail;

			memcpy(insn->detail->regs_read, arm_insns[i].regs_use, sizeof(arm_insns[i].regs_use));
			insn->detail->regs_read_count = (uint8_t)count_positive(arm_insns[i].regs_use);

			memcpy(insn->detail->regs_write, arm_insns[i].regs_mod, sizeof(arm_insns[i].regs_mod));
			insn->detail->regs_write_count = (uint8_t)count_positive(arm_insns[i].regs_mod);

			memcpy(insn->detail->groups, arm_insns[i].groups, sizeof(arm_insns[i].groups));
			insn->detail->groups_count = (uint8_t)count_positive8(arm_insns[i].groups);

			insn->detail->arm.update_flags = cs_reg_write((csh)&handle, insn, ARM_REG_CPSR);

			if (arm_insns[i].branch || arm_insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = ARM_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

#ifndef CAPSTONE_DIET
static const char * const insn_name_maps[] = {
	NULL, // ARM_INS_INVALID
#include "ARMGenCSMappingInsnName.inc"
};
#endif

const char *ARM_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= ARM_INS_ENDING)
		return NULL;

	return insn_name_maps[id];
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ ARM_GRP_INVALID, NULL },
	{ ARM_GRP_JUMP,	"jump" },
	{ ARM_GRP_CALL,	"call" },
	{ ARM_GRP_INT,	"int" },
	{ ARM_GRP_PRIVILEGE, "privilege" },
	{ ARM_GRP_BRANCH_RELATIVE, "branch_relative" },

	// architecture-specific groups
	#include "ARMGenCSFeatureName.inc"
};
#endif

const char *ARM_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

// list all relative branch instructions
// ie: insns[i].branch && !insns[i].indirect_branch
static const unsigned int insn_rel[] = {
	ARM_BL,
	ARM_BLX_pred,
	ARM_Bcc,
	ARM_t2B,
	ARM_t2Bcc,
	ARM_tB,
	ARM_tBcc,
	ARM_tCBNZ,
	ARM_tCBZ,
	ARM_BL_pred,
	ARM_BLXi,
	ARM_tBL,
	ARM_tBLXi,
	0
};

static const unsigned int insn_blx_rel_to_arm[] = {
	ARM_tBLXi,
	0
};

// check if this insn is relative branch
bool ARM_rel_branch(cs_struct *h, unsigned int id)
{
	int i;

	for (i = 0; insn_rel[i]; i++) {
		if (id == insn_rel[i]) {
			return true;
		}
	}

	// not found
	return false;
}

bool ARM_blx_to_arm_mode(cs_struct *h, unsigned int id) {
	int i;

	for (i = 0; insn_blx_rel_to_arm[i]; i++)
		if (id == insn_blx_rel_to_arm[i])
			return true;

	// not found
	return false;

}

bool ARM_getInstruction(csh handle, const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *info) {
	ARM_init_cs_detail(instr);
	return getInstruction(handle, code, code_len, instr, size, address, info) == MCDisassembler_Success;
}

#define GET_REGINFO_MC_DESC
#include "ARMGenRegisterInfo.inc"

void ARM_init_mri(MCRegisterInfo *MRI)
{
	/*
		InitMCRegisterInfo(ARMRegDesc, 289,
		RA, PC,
		ARMMCRegisterClasses, 103,
		ARMRegUnitRoots, 77, ARMRegDiffLists, ARMRegStrings,
		ARMSubRegIdxLists, 57,
		ARMSubRegIdxRanges, ARMRegEncodingTable);
	 */

	MCRegisterInfo_InitMCRegisterInfo(MRI, ARMRegDesc, 289,
			0, 0,
			ARMMCRegisterClasses, 103,
			0, 0, ARMRegDiffLists, 0,
			ARMSubRegIdxLists, 57,
			0);
}

#ifndef CAPSTONE_DIET
///< A LLVM<->CS Mapping entry of an operand.
typedef struct insn_op {
	uint8_t /* cs_op_type */ type; ///< Operand type (e.g.: reg, imm, mem)
	uint8_t /* cs_ac_type */ access; ///< The access type (read, write)
	uint8_t /* cs_data_type */ dtypes[10]; ///< List of op types. Terminated by CS_DATA_TYPE_LAST
} insn_op;

///< Operands of an instruction.
typedef struct {
	insn_op ops[8]; ///< NULL terminated array of operands.
} insn_ops;

const insn_ops insn_operands[] = {
	{
		// NULL item
		{{ 0 }}
	},
#include "ARMGenCSMappingInsnOp.inc"
};

// given internal insn id, return operand access info
// const uint8_t *ARM_get_op_access(cs_struct *h, unsigned int id)
// {
// 	int i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
// 	if (i != 0) {
// 		return insn_ops[i].access;
// 	}

// 	return NULL;
// }

void ARM_reg_access(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_arm *arm = &(insn->detail->arm);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read, read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write, write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch((int)op->type) {
			case ARM_OP_REG:
				if ((op->access & CS_AC_READ) && !arr_exist(regs_read, read_count, op->reg)) {
					regs_read[read_count] = (uint16_t)op->reg;
					read_count++;
				}
				if ((op->access & CS_AC_WRITE) && !arr_exist(regs_write, write_count, op->reg)) {
					regs_write[write_count] = (uint16_t)op->reg;
					write_count++;
				}
				break;
			case ARM_OP_MEM:
				// registers appeared in memory references always being read
				if ((op->mem.base != ARM_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.base)) {
					regs_read[read_count] = (uint16_t)op->mem.base;
					read_count++;
				}
				if ((op->mem.index != ARM_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.index)) {
					regs_read[read_count] = (uint16_t)op->mem.index;
					read_count++;
				}
				if ((arm->writeback) && (op->mem.base != ARM_REG_INVALID) && !arr_exist(regs_write, write_count, op->mem.base)) {
					regs_write[write_count] = (uint16_t)op->mem.base;
					write_count++;
				}
			default:
				break;
		}
	}

	*regs_read_count = read_count;
	*regs_write_count = write_count;
}
#endif

void ARM_init_cs_detail(MCInst *MI) {
	if (MI->flat_insn->detail) {
		unsigned int i;

		memset(MI->flat_insn->detail, 0, offsetof(cs_detail, arm) + sizeof(cs_arm));

		for (i = 0; i < ARR_SIZE(MI->flat_insn->detail->arm.operands); i++) {
			MI->flat_insn->detail->arm.operands[i].vector_index = -1;
			MI->flat_insn->detail->arm.operands[i].neon_lane = -1;
		}
	}
}

/// Initializes or finishes a memory operand of Capstone (depending on \p status).
/// A memory operand in Capstone can be assembled by two LLVM operands.
/// E.g. the base register and the immediate disponent.
void ARM_set_mem_access(MCInst *MI, bool status)
{
	MI->csh->doing_mem = status;
	if (status) {
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].type = ARM_OP_MEM;
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].mem.base = ARM_REG_INVALID;
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].mem.index = ARM_REG_INVALID;
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].mem.scale = 1;
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].mem.disp = 0;

#ifndef CAPSTONE_DIET
		uint8_t access = ARM_get_op_access(MI, MI->flat_insn->detail->arm.op_count);
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].access = access;
#endif
	} else {
		// done, create the next operand slot
		MI->flat_insn->detail->arm.op_count++;
	}
}

/// Fills cs_detail with operand shift information for the last added operand.
static void add_cs_detail_RegImmShift(MCInst *MI, ARM_AM_ShiftOpc ShOpc, unsigned ShImm) {
	if (!MI->csh->detail)
		return;

	if (MI->csh->doing_mem)
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].shift.type = (arm_shifter)ShOpc;
	else
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count - 1].shift.type = (arm_shifter)ShOpc;

	if (ShOpc != ARM_AM_rrx) {
		if (MI->csh->doing_mem)
			MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].shift.value = translateShiftImm(ShImm);
		else
			MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count - 1].shift.value = translateShiftImm(ShImm);
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which's original printer function has no specialities.
static void add_cs_detail_general(MCInst *MI, arm_op_group op_group, unsigned OpNum) {
	if (!MI->csh->detail)
		return;
	cs_op_type op_type = ARM_get_op_type(MI, OpNum);

	// Fill cs_detail
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
	case ARM_OP_GROUP_PredicateOperand:
	case ARM_OP_GROUP_MandatoryPredicateOperand:
	case ARM_OP_GROUP_MandatoryInvertedPredicateOperand:
	case ARM_OP_GROUP_MandatoryRestrictedPredicateOperand:
	{
		ARMCC_CondCodes CC = (ARMCC_CondCodes)MCOperand_getImm(MCInst_getOperand(MI, OpNum));
		if ((unsigned)CC == 15 && op_group == ARM_OP_GROUP_PredicateOperand) {
			MI->flat_insn->detail->arm.cc = ARM_CC_INVALID;
			return;
		}
		if (CC == ARMCC_HS && op_group == ARM_OP_GROUP_MandatoryRestrictedPredicateOperand) {
			MI->flat_insn->detail->arm.cc = ARM_CC_HS;
			return;
		}
		MI->flat_insn->detail->arm.cc = CC + 1;
		return;
	}
	case ARM_OP_GROUP_VPTPredicateOperand:
	{
		ARMVCC_VPTCodes VCC = (ARMVCC_VPTCodes)MCOperand_getImm(MCInst_getOperand(MI, OpNum));
		assert(VCC <= ARMVCC_Else);
		MI->flat_insn->detail->arm.vcc = VCC;
		return;
	}
	case ARM_OP_GROUP_Operand:
		// TODO: PC relative immediates
		if (op_type == CS_OP_IMM)
			ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM);
		else if (op_type == CS_OP_REG)
			ARM_set_detail_op_reg(MI, OpNum);
		else
			assert(0 && "Op type not handled.");
	case ARM_OP_GROUP_PImmediate:
			ARM_set_detail_op_imm(MI, OpNum, ARM_OP_PIMM);
	case ARM_OP_GROUP_CImmediate:
			ARM_set_detail_op_imm(MI, OpNum, ARM_OP_CIMM);
	case ARM_OP_GROUP_SBitModifierOperand:
	case ARM_OP_GROUP_SORegRegOperand:
	case ARM_OP_GROUP_ModImmOperand:
	case ARM_OP_GROUP_SORegImmOperand:
	case ARM_OP_GROUP_T2SOOperand:
	case ARM_OP_GROUP_ThumbS4ImmOperand:
	case ARM_OP_GROUP_ThumbSRImm:
	case ARM_OP_GROUP_BitfieldInvMaskImmOperand:
	case ARM_OP_GROUP_RegisterList:
	case ARM_OP_GROUP_CPSIMod:
	case ARM_OP_GROUP_CPSIFlag:
	case ARM_OP_GROUP_GPRPairOperand:
	case ARM_OP_GROUP_MemBOption:
	case ARM_OP_GROUP_FPImmOperand:
	case ARM_OP_GROUP_VectorIndex:
	case ARM_OP_GROUP_InstSyncBOption:
	case ARM_OP_GROUP_ThumbITMask:
	case ARM_OP_GROUP_AddrMode7Operand:
	case ARM_OP_GROUP_CoprocOptionImm:
	case ARM_OP_GROUP_PostIdxImm8s4Operand:
	case ARM_OP_GROUP_ThumbLdrLabelOperand:
	case ARM_OP_GROUP_ThumbAddrModeImm5S4Operand:
	case ARM_OP_GROUP_ThumbAddrModeRROperand:
	case ARM_OP_GROUP_ThumbAddrModeSPOperand:
	case ARM_OP_GROUP_AddrMode2Operand:
	case ARM_OP_GROUP_T2AddrModeSoRegOperand:
	case ARM_OP_GROUP_AddrMode2OffsetOperand:
	case ARM_OP_GROUP_T2AddrModeImm8OffsetOperand:
	case ARM_OP_GROUP_ThumbAddrModeImm5S1Operand:
	case ARM_OP_GROUP_T2AddrModeImm8s4OffsetOperand:
	case ARM_OP_GROUP_AddrMode3OffsetOperand:
	case ARM_OP_GROUP_T2AddrModeImm0_1020s4Operand:
	case ARM_OP_GROUP_ThumbAddrModeImm5S2Operand:
	case ARM_OP_GROUP_PostIdxRegOperand:
	case ARM_OP_GROUP_PostIdxImm8Operand:
	case ARM_OP_GROUP_BankedRegOperand:
	case ARM_OP_GROUP_MSRMaskOperand:
	case ARM_OP_GROUP_PKHLSLShiftImm:
	case ARM_OP_GROUP_PKHASRShiftImm:
	case ARM_OP_GROUP_ImmPlusOneOperand:
	case ARM_OP_GROUP_SetendOperand:
	case ARM_OP_GROUP_MveSaturateOp:
	case ARM_OP_GROUP_ShiftImmOperand:
	case ARM_OP_GROUP_RotImmOperand:
	case ARM_OP_GROUP_AddrModeTBB:
	case ARM_OP_GROUP_AddrModeTBH:
	case ARM_OP_GROUP_TraceSyncBOption:
	case ARM_OP_GROUP_VMOVModImmOperand:
	case ARM_OP_GROUP_FBits16:
	case ARM_OP_GROUP_FBits32:
	case ARM_OP_GROUP_VectorListTwoAllLanes:
	case ARM_OP_GROUP_AddrMode6Operand:
	case ARM_OP_GROUP_VectorListTwo:
	case ARM_OP_GROUP_VectorListFour:
	case ARM_OP_GROUP_VectorListOneAllLanes:
	case ARM_OP_GROUP_VectorListOne:
	case ARM_OP_GROUP_VectorListThree:
	case ARM_OP_GROUP_NoHashImmediate:
	case ARM_OP_GROUP_AddrMode6OffsetOperand:
	case ARM_OP_GROUP_VectorListTwoSpacedAllLanes:
	case ARM_OP_GROUP_VectorListTwoSpaced:
	case ARM_OP_GROUP_VectorListThreeAllLanes:
	case ARM_OP_GROUP_VectorListThreeSpacedAllLanes:
	case ARM_OP_GROUP_VectorListThreeSpaced:
	case ARM_OP_GROUP_VectorListFourAllLanes:
	case ARM_OP_GROUP_VectorListFourSpacedAllLanes:
	case ARM_OP_GROUP_VectorListFourSpaced:
	case ARM_OP_GROUP_VPTMask:
		return;
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which original printer function is a template
/// with one argument.
static void add_cs_detail_template_1(MCInst *MI, arm_op_group op_group, unsigned OpNum, uint64_t temp_arg_0) {
	switch(op_group) {
	default:
			printf("ERROR: Operand group %d not handled!\n", op_group);
			assert(0);
	case ARM_OP_GROUP_AdrLabelOperand_0:
	case ARM_OP_GROUP_AdrLabelOperand_2:
	case ARM_OP_GROUP_AddrMode5Operand_0:
	case ARM_OP_GROUP_AddrMode5Operand_1:
	case ARM_OP_GROUP_AddrModeImm12Operand_0:
	case ARM_OP_GROUP_T2AddrModeImm8Operand_0:
	case ARM_OP_GROUP_AddrModeImm12Operand_1:
	case ARM_OP_GROUP_T2AddrModeImm8Operand_1:
	case ARM_OP_GROUP_T2AddrModeImm8s4Operand_0:
	case ARM_OP_GROUP_AddrMode3Operand_0:
	case ARM_OP_GROUP_T2AddrModeImm8s4Operand_1:
	case ARM_OP_GROUP_MVEVectorList_2:
	case ARM_OP_GROUP_MVEVectorList_4:
	case ARM_OP_GROUP_AddrMode5FP16Operand_0:
	case ARM_OP_GROUP_MveAddrModeRQOperand_0:
	case ARM_OP_GROUP_MveAddrModeRQOperand_3:
	case ARM_OP_GROUP_MveAddrModeRQOperand_1:
	case ARM_OP_GROUP_MveAddrModeRQOperand_2:
		return;
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which's original printer function is a template
/// with two arguments.
static void add_cs_detail_template_2(MCInst *MI, arm_op_group op_group, unsigned OpNum, uint64_t temp_arg_0, uint64_t temp_arg_1) {
	switch (op_group) {
	default:
			printf("ERROR: Operand group %d not handled!\n", op_group);
			assert(0);
	case ARM_OP_GROUP_ComplexRotationOp_180_90:
	case ARM_OP_GROUP_ComplexRotationOp_90_0:
		return;
	}
}

/// Fills cs_detail with the data of the operand.
/// Calls to this function are should not be added by hand! Please checkout the
/// patch `AddCSDetail` of the CppTranslator.
void ARM_add_cs_detail(MCInst *MI, int /* arm_op_group */ op_group, va_list args) {
	switch (op_group) {
	case ARM_OP_GROUP_RegImmShift: {
		ARM_AM_ShiftOpc shift_opc = va_arg(args, ARM_AM_ShiftOpc);
		unsigned shift_imm = va_arg(args, unsigned);
		add_cs_detail_RegImmShift(MI, shift_opc, shift_imm);
		return;
	}
	case ARM_OP_GROUP_AdrLabelOperand_0:
	case ARM_OP_GROUP_AdrLabelOperand_2:
	case ARM_OP_GROUP_AddrMode5Operand_0:
	case ARM_OP_GROUP_AddrMode5Operand_1:
	case ARM_OP_GROUP_AddrModeImm12Operand_0:
	case ARM_OP_GROUP_T2AddrModeImm8Operand_0:
	case ARM_OP_GROUP_AddrModeImm12Operand_1:
	case ARM_OP_GROUP_T2AddrModeImm8Operand_1:
	case ARM_OP_GROUP_T2AddrModeImm8s4Operand_0:
	case ARM_OP_GROUP_AddrMode3Operand_0:
	case ARM_OP_GROUP_T2AddrModeImm8s4Operand_1:
	case ARM_OP_GROUP_MVEVectorList_2:
	case ARM_OP_GROUP_MVEVectorList_4:
	case ARM_OP_GROUP_AddrMode5FP16Operand_0:
	case ARM_OP_GROUP_MveAddrModeRQOperand_0:
	case ARM_OP_GROUP_MveAddrModeRQOperand_3:
	case ARM_OP_GROUP_MveAddrModeRQOperand_1:
	case ARM_OP_GROUP_MveAddrModeRQOperand_2: {
		unsigned op_num = va_arg(args, unsigned);
		uint64_t templ_arg_0 = va_arg(args, uint64_t);
		add_cs_detail_template_1(MI, op_group, op_num, templ_arg_0);
		return;
	}
	case ARM_OP_GROUP_ComplexRotationOp_180_90:
	case ARM_OP_GROUP_ComplexRotationOp_90_0: {
		unsigned op_num = va_arg(args, unsigned);
		uint64_t templ_arg_0 = va_arg(args, uint64_t);
		uint64_t templ_arg_1 = va_arg(args, uint64_t);
		add_cs_detail_template_2(MI, op_group, op_num, templ_arg_0, templ_arg_1);
		return;
	}
	}
	unsigned op_num = va_arg(args, unsigned);
	add_cs_detail_general(MI, op_group, op_num);
}

const cs_op_type ARM_get_op_type(MCInst *MI, unsigned OpNum) {
	assert(MI->Opcode < sizeof(insn_operands)/sizeof(insn_operands[0]));
	assert(OpNum < sizeof(insn_operands[MI->Opcode].ops)/sizeof(insn_operands[MI->Opcode].ops[0]));
	return insn_operands[MI->Opcode].ops[OpNum].type;
}

const cs_ac_type ARM_get_op_access(MCInst *MI, unsigned OpNum) {
	assert(MI->Opcode < sizeof(insn_operands)/sizeof(insn_operands[0]));
	assert(OpNum < sizeof(insn_operands[MI->Opcode].ops)/sizeof(insn_operands[MI->Opcode].ops[0]));
	return insn_operands[MI->Opcode].ops[OpNum].access;
}

/// Adds a register ARM operand at position OpNum and increases the op_count by one.
void ARM_set_detail_op_reg(MCInst *MI, unsigned OpNum) {
	assert(ARM_get_op_type(MI, OpNum) == CS_OP_REG);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, OpNum));

	MI->flat_insn->detail->arm.operands[OpNum].type = ARM_OP_REG;
	MI->flat_insn->detail->arm.operands[OpNum].reg = Reg;
	MI->flat_insn->detail->arm.operands[OpNum].access = ARM_get_op_access(MI, OpNum);
	MI->flat_insn->detail->arm.op_count++;
}

/// Adds an immediate ARM operand at position OpNum and increases the op_count by one.
void ARM_set_detail_op_imm(MCInst *MI, unsigned OpNum, arm_op_type imm_type) {
	assert(ARM_get_op_type(MI, OpNum) == CS_OP_IMM);
	assert(imm_type == ARM_OP_IMM || imm_type == ARM_OP_PIMM || imm_type == ARM_OP_CIMM);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, OpNum));

	MI->flat_insn->detail->arm.operands[OpNum].type = imm_type;
	MI->flat_insn->detail->arm.operands[OpNum].imm = Imm;
	MI->flat_insn->detail->arm.operands[OpNum].access = ARM_get_op_access(MI, OpNum);
	MI->flat_insn->detail->arm.op_count++;
}

/// Adds a memory ARM operand at position OpNum. op_count is *not* increase by one.
/// This is done by set_mem_access().
void ARM_set_detail_op_mem(MCInst *MI, unsigned OpNum, bool subtracted, bool is_base_reg, int scale, int lshift) {
	assert(ARM_get_op_type(MI, OpNum) & CS_OP_MEM);
	cs_op_type secondary_type = ARM_get_op_type(MI, OpNum) & ~CS_OP_MEM;
	switch(secondary_type) {
	default:
		assert(0 && "Secondary type not supported yet.");
	case CS_OP_REG: {
		unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
		if (is_base_reg) {
			MI->flat_insn->detail->arm.operands[OpNum].mem.base = Reg;
		} else {
			MI->flat_insn->detail->arm.operands[OpNum].mem.index = Reg;
			MI->flat_insn->detail->arm.operands[OpNum].mem.scale = scale;
			MI->flat_insn->detail->arm.operands[OpNum].mem.lshift = lshift;
		}
	}
	case CS_OP_IMM: {
		unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, OpNum));
		MI->flat_insn->detail->arm.operands[OpNum].mem.disp = Imm;
	}
	}

	MI->flat_insn->detail->arm.operands[OpNum].type = ARM_OP_MEM;
	MI->flat_insn->detail->arm.operands[OpNum].access = ARM_get_op_access(MI, OpNum);
	MI->flat_insn->detail->arm.operands[OpNum].subtracted = subtracted;
}

#endif
