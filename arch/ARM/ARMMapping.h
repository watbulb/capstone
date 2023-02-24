/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_ARM_MAPPING_H
#define CS_ARM_MAPPING_H

#include "../../include/capstone/capstone.h"
#include "../../utils.h"
#include "ARMBaseInfo.h"

// return name of regiser in friendly string
const char *ARM_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction ID
void ARM_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *ARM_insn_name(csh handle, unsigned int id);

const char *ARM_group_name(csh handle, unsigned int id);

// check if this insn is relative branch
bool ARM_rel_branch(cs_struct *h, unsigned int insn_id);

bool ARM_blx_to_arm_mode(cs_struct *h, unsigned int insn_id);

const uint8_t *ARM_get_op_access(cs_struct *h, unsigned int id);

void ARM_reg_access(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count);

const BankedReg *lookupBankedRegByEncoding(uint8_t encoding);

bool ARM_getInstruction(csh handle, const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *info);

void ARM_init_mri(MCRegisterInfo *MRI);

const char *
getRegisterName(unsigned RegNo, unsigned AltIdx);

// Definitions for functions in ARMGenSystemRegister.inc
const BankedReg *lookupBankedRegByEncoding(uint8_t encoding);
const MClassSysReg *lookupMClassSysRegByM2M3Encoding8(uint16_t encoding);
const MClassSysReg *lookupMClassSysRegByM1Encoding12(uint16_t encoding);

void ARM_init_cs_detail(MCInst *MI);

#endif // CS_ARM_MAPPING_H
