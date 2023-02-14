/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_ARMDISASSEMBLER_H
#define CS_ARMDISASSEMBLER_H

#include "capstone/capstone.h"
#include "../../MCDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

DecodeStatus getInstruction(csh handle, const uint8_t *Bytes, size_t ByteLen, MCInst *MI, uint16_t *Size, uint64_t Address, void *Info);

#endif
