/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifndef CS_PPCDISASSEMBLER_H
#define CS_PPCDISASSEMBLER_H

#include "capstone/capstone.h"
#include "../../MCDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

void PPC_init(MCRegisterInfo *MRI);

#endif

