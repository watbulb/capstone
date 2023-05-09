/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifndef CS_PPC_MAP_H
#define CS_PPC_MAP_H

#include "../../cs_priv.h"
#include "capstone/capstone.h"

typedef enum {
#include "PPCGenCSOpGroup.inc"
} ppc_op_group;

// return name of regiser in friendly string
const char *PPC_reg_name(csh handle, unsigned int reg);

// return register id, given register name
ppc_reg PPC_name_reg(const char *name);

// given internal insn id, return public instruction info
void PPC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *PPC_insn_name(csh handle, unsigned int id);
const char *PPC_group_name(csh handle, unsigned int id);

struct ppc_alias {
	unsigned int id;	// instruction id
	int cc;	// code condition
	const char *mnem;
};

// map instruction name to public instruction ID
ppc_insn PPC_map_insn(const char *name);

// check if this insn is relative branch
bool PPC_abs_branch(cs_struct *h, unsigned int id);

// map internal raw register to 'public' register
ppc_reg PPC_map_register(unsigned int r);

// given alias mnemonic, return instruction ID & CC
bool PPC_alias_insn(const char *name, struct ppc_alias *alias);

bool PPC_getFeatureBits(unsigned int mode, unsigned int feature);


void PPC_add_cs_detail(MCInst *MI, ppc_op_group op_group, va_list args);

static inline void add_cs_detail(MCInst *MI, ppc_op_group op_group, ...)
{
	if (!MI->flat_insn->detail)
		return;
	va_list args;
	va_start(args, op_group);
	PPC_add_cs_detail(MI, op_group, args);
	va_end(args);
}

#endif

