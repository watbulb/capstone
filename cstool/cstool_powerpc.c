/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>

#include <capstone/capstone.h>
#include "cstool.h"

static const char* get_bc_name(int bc)
{
	switch(bc) {
		default:
			return ("invalid");
		case PPC_PRED_LT:
			return ("lt");
		case PPC_PRED_LE:
			return ("le");
		case PPC_PRED_EQ:
			return ("eq");
		case PPC_PRED_GE:
			return ("ge");
		case PPC_PRED_GT:
			return ("gt");
		case PPC_PRED_NE:
			return ("ne");
		case PPC_PRED_UN:
			return ("un");
		case PPC_PRED_NU:
			return ("nu");
		case PPC_PRED_SO:
			return ("so");
		case PPC_PRED_NS:
			return ("ns");
	}
}

void print_insn_detail_ppc(csh handle, cs_insn *ins)
{
	cs_ppc *ppc;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	ppc = &(ins->detail->ppc);
	if (ppc->op_count)
		printf("\top_count: %u\n", ppc->op_count);

	for (i = 0; i < ppc->op_count; i++) {
		cs_ppc_op *op = &(ppc->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case PPC_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case PPC_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%"PRIx64"\n", i, op->imm);
				break;
			case PPC_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != PPC_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.offset != PPC_REG_INVALID)
					printf("\t\t\toperands[%u].mem.offset: REG = %s\n", i,
						cs_reg_name(handle, op->mem.offset));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
		}
		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				printf("\t\toperands[%u].access: READ\n", i);
				break;
			case CS_AC_WRITE:
				printf("\t\toperands[%u].access: WRITE\n", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				printf("\t\toperands[%u].access: READ | WRITE\n", i);
				break;
		}
	}

	if (ppc->bc.pred != PPC_PRED_INVALID) {
		printf("\tBranch hint: %u\n", ppc->bc.hint);
		printf("\tBranch bi: %u\n", ppc->bc.bi);
		printf("\tBranch bo: %u\n", ppc->bc.bo);
		printf("\tBranch bh: %u\n", ppc->bc.bh);
	}

	if (ppc->bc.hint != PPC_BR_NOT_GIVEN)
		printf("\tBranch hint: %u\n", ppc->bc.hint);

	if (ppc->update_cr0)
		printf("\tUpdate-CR0: True\n");
}
