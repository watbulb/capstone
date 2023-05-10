/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_POWERPC

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "PPCMapping.h"
#include "PPCMCTargetDesc.h"

#define GET_REGINFO_MC_DESC
#include "PPCGenRegisterInfo.inc"

void PPC_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, PPCRegDesc, 289, 0, 0, PPCMCRegisterClasses, 103, 0, 0,
		PPCRegDiffLists, 0, PPCSubRegIdxLists, 57, PPCRegEncodingTable);
}

const char *PPC_reg_name(csh handle, unsigned int reg)
{
	// Not implemented yet.
	return getRegisterName(reg);
}

static const insn_map insns[] = {
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

#include "PPCGenCSMappingInsn.inc"
};

// given internal insn id, return public instruction info
void PPC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	int i;

	i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		insn->id = insns[i].mapid;

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

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = PPC_GRP_JUMP;
				insn->detail->groups_count++;
			}

			insn->detail->ppc.update_cr0 = cs_reg_write((csh)&handle, insn, PPC_REG_CR0);
#endif
		}
	}
}

static const char * const insn_name_maps[] = {
    NULL, // PPC_INS_BCT
#include "PPCMappingInsnName.inc"
};

const char *PPC_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= PPC_INS_ENDING)
		return NULL;

	return insn_name_maps[id];
#else
	return NULL;
#endif
}

// map instruction name to public instruction ID
ppc_insn PPC_map_insn(const char *name)
{
	unsigned int i;

	for(i = 1; i < ARR_SIZE(insn_name_maps); i++) {
		if (!strcmp(name, insn_name_maps[i]))
			return i;
	}

	// not found
	return PPC_INS_INVALID;
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ PPC_GRP_INVALID, NULL },
	{ PPC_GRP_JUMP,	"jump" },

	// architecture-specific groups
	#include "PPCGenCSFeatureName.inc"
};
#endif

const char *PPC_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

static const struct ppc_alias alias_insn_name_maps[] = {
	//{ PPC_INS_BTA, "bta" },
	{ PPC_INS_B, PPC_BC_LT, "blt" },
	{ PPC_INS_B, PPC_BC_LE, "ble" },
	{ PPC_INS_B, PPC_BC_EQ, "beq" },
	{ PPC_INS_B, PPC_BC_GE, "bge" },
	{ PPC_INS_B, PPC_BC_GT, "bgt" },
	{ PPC_INS_B, PPC_BC_NE, "bne" },
	{ PPC_INS_B, PPC_BC_UN, "bun" },
	{ PPC_INS_B, PPC_BC_NU, "bnu" },
	{ PPC_INS_B, PPC_BC_SO, "bso" },
	{ PPC_INS_B, PPC_BC_NS, "bns" },

	{ PPC_INS_BA, PPC_BC_LT, "blta" },
	{ PPC_INS_BA, PPC_BC_LE, "blea" },
	{ PPC_INS_BA, PPC_BC_EQ, "beqa" },
	{ PPC_INS_BA, PPC_BC_GE, "bgea" },
	{ PPC_INS_BA, PPC_BC_GT, "bgta" },
	{ PPC_INS_BA, PPC_BC_NE, "bnea" },
	{ PPC_INS_BA, PPC_BC_UN, "buna" },
	{ PPC_INS_BA, PPC_BC_NU, "bnua" },
	{ PPC_INS_BA, PPC_BC_SO, "bsoa" },
	{ PPC_INS_BA, PPC_BC_NS, "bnsa" },

	{ PPC_INS_BCTR, PPC_BC_LT, "bltctr" },
	{ PPC_INS_BCTR, PPC_BC_LE, "blectr" },
	{ PPC_INS_BCTR, PPC_BC_EQ, "beqctr" },
	{ PPC_INS_BCTR, PPC_BC_GE, "bgectr" },
	{ PPC_INS_BCTR, PPC_BC_GT, "bgtctr" },
	{ PPC_INS_BCTR, PPC_BC_NE, "bnectr" },
	{ PPC_INS_BCTR, PPC_BC_UN, "bunctr" },
	{ PPC_INS_BCTR, PPC_BC_NU, "bnuctr" },
	{ PPC_INS_BCTR, PPC_BC_SO, "bsoctr" },
	{ PPC_INS_BCTR, PPC_BC_NS, "bnsctr" },

	{ PPC_INS_BCTRL, PPC_BC_LT, "bltctrl" },
	{ PPC_INS_BCTRL, PPC_BC_LE, "blectrl" },
	{ PPC_INS_BCTRL, PPC_BC_EQ, "beqctrl" },
	{ PPC_INS_BCTRL, PPC_BC_GE, "bgectrl" },
	{ PPC_INS_BCTRL, PPC_BC_GT, "bgtctrl" },
	{ PPC_INS_BCTRL, PPC_BC_NE, "bnectrl" },
	{ PPC_INS_BCTRL, PPC_BC_UN, "bunctrl" },
	{ PPC_INS_BCTRL, PPC_BC_NU, "bnuctrl" },
	{ PPC_INS_BCTRL, PPC_BC_SO, "bsoctrl" },
	{ PPC_INS_BCTRL, PPC_BC_NS, "bnsctrl" },

	{ PPC_INS_BL, PPC_BC_LT, "bltl" },
	{ PPC_INS_BL, PPC_BC_LE, "blel" },
	{ PPC_INS_BL, PPC_BC_EQ, "beql" },
	{ PPC_INS_BL, PPC_BC_GE, "bgel" },
	{ PPC_INS_BL, PPC_BC_GT, "bgtl" },
	{ PPC_INS_BL, PPC_BC_NE, "bnel" },
	{ PPC_INS_BL, PPC_BC_UN, "bunl" },
	{ PPC_INS_BL, PPC_BC_NU, "bnul" },
	{ PPC_INS_BL, PPC_BC_SO, "bsol" },
	{ PPC_INS_BL, PPC_BC_NS, "bnsl" },

	{ PPC_INS_BLA, PPC_BC_LT, "bltla" },
	{ PPC_INS_BLA, PPC_BC_LE, "blela" },
	{ PPC_INS_BLA, PPC_BC_EQ, "beqla" },
	{ PPC_INS_BLA, PPC_BC_GE, "bgela" },
	{ PPC_INS_BLA, PPC_BC_GT, "bgtla" },
	{ PPC_INS_BLA, PPC_BC_NE, "bnela" },
	{ PPC_INS_BLA, PPC_BC_UN, "bunla" },
	{ PPC_INS_BLA, PPC_BC_NU, "bnula" },
	{ PPC_INS_BLA, PPC_BC_SO, "bsola" },
	{ PPC_INS_BLA, PPC_BC_NS, "bnsla" },

	{ PPC_INS_BLR, PPC_BC_LT, "bltlr" },
	{ PPC_INS_BLR, PPC_BC_LE, "blelr" },
	{ PPC_INS_BLR, PPC_BC_EQ, "beqlr" },
	{ PPC_INS_BLR, PPC_BC_GE, "bgelr" },
	{ PPC_INS_BLR, PPC_BC_GT, "bgtlr" },
	{ PPC_INS_BLR, PPC_BC_NE, "bnelr" },
	{ PPC_INS_BLR, PPC_BC_UN, "bunlr" },
	{ PPC_INS_BLR, PPC_BC_NU, "bnulr" },
	{ PPC_INS_BLR, PPC_BC_SO, "bsolr" },
	{ PPC_INS_BLR, PPC_BC_NS, "bnslr" },

	{ PPC_INS_BLRL, PPC_BC_LT, "bltlrl" },
	{ PPC_INS_BLRL, PPC_BC_LE, "blelrl" },
	{ PPC_INS_BLRL, PPC_BC_EQ, "beqlrl" },
	{ PPC_INS_BLRL, PPC_BC_GE, "bgelrl" },
	{ PPC_INS_BLRL, PPC_BC_GT, "bgtlrl" },
	{ PPC_INS_BLRL, PPC_BC_NE, "bnelrl" },
	{ PPC_INS_BLRL, PPC_BC_UN, "bunlrl" },
	{ PPC_INS_BLRL, PPC_BC_NU, "bnulrl" },
	{ PPC_INS_BLRL, PPC_BC_SO, "bsolrl" },
	{ PPC_INS_BLRL, PPC_BC_NS, "bnslrl" },
};

// given alias mnemonic, return instruction ID & CC
bool PPC_alias_insn(const char *name, struct ppc_alias *alias)
{
	size_t i;

	alias->cc = PPC_BC_INVALID;

	for(i = 0; i < ARR_SIZE(alias_insn_name_maps); i++) {
		if (!strcmp(name, alias_insn_name_maps[i].mnem)) {
			// alias->id = alias_insn_name_maps[i].id;
			alias->cc = alias_insn_name_maps[i].cc;
			return true;
		}
	}

	// not found
	return false;
}

// check if this insn is relative branch
bool PPC_abs_branch(cs_struct *h, unsigned int id)
{
	unsigned int i;
	// list all absolute branch instructions
	static const unsigned int insn_abs[] = {
		PPC_BA,
		PPC_BCCA,
		PPC_BCCLA,
		PPC_BDNZA,
		PPC_BDNZAm,
		PPC_BDNZAp,
		PPC_BDNZLA,
		PPC_BDNZLAm,
		PPC_BDNZLAp,
		PPC_BDZA,
		PPC_BDZAm,
		PPC_BDZAp,
		PPC_BDZLAm,
		PPC_BDZLAp,
		PPC_BLA,
		PPC_gBCA,
		PPC_gBCLA,
		PPC_BDZLA,
		0
	};

	// printf("opcode: %u\n", id);

	for (i = 0; insn_abs[i]; i++) {
		if (id == insn_abs[i]) {
			return true;
		}
	}

	// not found
	return false;
}

bool PPC_getFeatureBits(unsigned int mode, unsigned int feature) {
  if ((feature == PPC_FeatureQPX) && (mode & CS_MODE_QPX) == 0) {
    return false;
  } else if ((feature == PPC_FeatureSPE) && (mode & CS_MODE_SPE) == 0) {
    return false;
  } else if ((feature == PPC_FeatureBookE) && (mode & CS_MODE_BOOKE) == 0) {
    return false;
  }
  // TODO: CS_MODE_PS

	// No AIX support for now.
	if (feature == PPC_FeatureModernAIXAs)
		return false;

  // By default support everything
  return true;
}

/// Fills cs_detail with the data of the operand.
/// Calls to this function are should not be added by hand! Please checkout the
/// patch `AddCSDetail` of the CppTranslator.
void PPC_add_cs_detail(MCInst *MI, ppc_op_group op_group, va_list args)
{
	if (!MI->flat_insn->detail)
		return;
	switch (op_group) {
	default:
		printf("Operand group %d not handled!\n", op_group);
		return;
	case PPC_OP_GROUP_RegImmShift: {
		// ARM_AM_ShiftOpc shift_opc = va_arg(args, ARM_AM_ShiftOpc);
		// unsigned shift_imm = va_arg(args, unsigned);
		// add_cs_detail_RegImmShift(MI, shift_opc, shift_imm);
		return;
	}
	case PPC_OP_GROUP_LdStmModeOperand:
	case PPC_OP_GROUP_MandatoryInvertedPredicateOperand:
	case PPC_OP_GROUP_Operand:
	case PPC_OP_GROUP_MemRegReg:
	case PPC_OP_GROUP_U6ImmOperand:
	case PPC_OP_GROUP_U5ImmOperand:
	case PPC_OP_GROUP_MemRegImm:
	case PPC_OP_GROUP_S16ImmOperand:
	case PPC_OP_GROUP_U2ImmOperand:
	case PPC_OP_GROUP_U16ImmOperand:
	case PPC_OP_GROUP_BranchOperand:
	case PPC_OP_GROUP_AbsBranchOperand:
	case PPC_OP_GROUP_PredicateOperand:
	case PPC_OP_GROUP_U1ImmOperand:
	case PPC_OP_GROUP_TLSCall:
	case PPC_OP_GROUP_U3ImmOperand:
	case PPC_OP_GROUP_S5ImmOperand:
	case PPC_OP_GROUP_MemRegImmHash:
	case PPC_OP_GROUP_U4ImmOperand:
	case PPC_OP_GROUP_U10ImmOperand:
	case PPC_OP_GROUP_crbitm:
	case PPC_OP_GROUP_S34ImmOperand:
	case PPC_OP_GROUP_ImmZeroOperand:
	case PPC_OP_GROUP_MemRegImm34:
	case PPC_OP_GROUP_MemRegImm34PCRel:
	case PPC_OP_GROUP_U8ImmOperand:
	case PPC_OP_GROUP_U12ImmOperand:
	case PPC_OP_GROUP_U7ImmOperand:
	case PPC_OP_GROUP_ATBitsAsHint: {
		// unsigned op_num = va_arg(args, unsigned);
		// add_cs_detail_general(MI, op_group, op_num);
		return;
	}
	}
}

#endif
