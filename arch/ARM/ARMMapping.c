/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CAPSTONE_HAS_ARM

#include <stdio.h>	// debug
#include <string.h>

#include "../../cs_priv.h"

#include "ARMMapping.h"

#define GET_INSTRINFO_ENUM
#include "ARMGenInstrInfo.inc"

const char *ARM_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= ARR_SIZE(reg_name_maps))
		return NULL;

	return reg_name_maps[reg].name;
#else
	return NULL;
#endif
}

#include "ARMGenAsmWriter.inc"

const char *ARM_reg_name(csh handle, unsigned int reg) {
	if (handle.syntax & CS_OPT_SYNTAX_NOREGNAME) {
		return getRegisterName(reg, ARM_RegNamesRaw);
	}
	return getRegisterName(reg, ARM_NoRegAltName);
}

static const insn_map insns[] = {
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
	unsigned int max = ARR_SIZE(insns);

	right = max - 1;

	if (id < insns[0].id || id > insns[right].id)
		// not found
		return -1;

	left = 0;

	while(left <= right) {
		m = (left + right) / 2;
		if (id == insns[m].id) {
			return m;
		}

		if (id < insns[m].id)
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
		insn->id = insns[i].mapid;

		// printf("id = %u, mapid = %u\n", id, insn->id);

		if (h->detail) {
#ifndef CAPSTONE_DIET
			cs_struct handle;
			handle.detail = h->detail;

			memcpy(insn->detail->regs_read, insns[i].regs_use, sizeof(insns[i].regs_use));
			insn->detail->regs_read_count = (uint8_t)count_positive(insns[i].regs_use);

			memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
			insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);

			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
			insn->detail->groups_count = (uint8_t)count_positive8(insns[i].groups);

			insn->detail->arm.update_flags = cs_reg_write((csh)&handle, insn, ARM_REG_CPSR);

			if (insns[i].branch || insns[i].indirect_branch) {
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

#ifndef CAPSTONE_DIET
///< A LLVM<->CS Mapping entry of an operand.
typedef struct insn_op {
	uint8_t /* cs_op_type */ type; ///< Operand type (e.g.: reg, imm, mem)
	uint8_t /* cs_ac_type */ access; ///< The access type (read, write)
} insn_op;

///< Operands of an instruction.
typedef struct {
	insn_op ops[8]; ///< NULL terminated array of operands.
} insn_ops;

static const insn_ops insn_ops[] = {
	{
		// NULL item
		{ 0 }
	},

#include "ARMGenCSMappingInsnOp.inc"
};

// given internal insn id, return operand access info
const uint8_t *ARM_get_op_access(cs_struct *h, unsigned int id)
{
	int i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		return insn_ops[i].access;
	}

	return NULL;
}

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

#endif
