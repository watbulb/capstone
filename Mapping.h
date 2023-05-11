/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_MAPPING_H
#define CS_MAPPING_H

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include "include/capstone/capstone.h"
#include <stddef.h>
#endif
#include "cs_priv.h"

// map instruction to its characteristics
typedef struct insn_map {
	unsigned short id;					// The LLVM instruction id
	unsigned short mapid;				// The Capstone instruction id
#ifndef CAPSTONE_DIET
	uint16_t regs_use[MAX_IMPL_R_REGS]; ///< list of implicit registers used by
										///< this instruction
	uint16_t regs_mod[MAX_IMPL_W_REGS]; ///< list of implicit registers modified
										///< by this instruction
	unsigned char
		groups[MAX_NUM_GROUPS]; ///< list of group this instruction belong to
	bool branch;				// branch instruction?
	bool indirect_branch;		// indirect branch instruction?
#endif
} insn_map;

// look for @id in @m, given its size in @max. first time call will update
// @cache. return 0 if not found
unsigned short insn_find(const insn_map *m, unsigned int max, unsigned int id,
						 unsigned short **cache);

unsigned int find_cs_id(unsigned MC_Opcode, const insn_map *imap,
						unsigned imap_size);

// map id to string
typedef struct name_map {
	unsigned int id;
	const char *name;
} name_map;

// map a name to its ID
// return 0 if not found
int name2id(const name_map *map, int max, const char *name);

// map ID to a name
// return NULL if not found
const char *id2name(const name_map *map, int max, const unsigned int id);

void map_add_implicit_write(MCInst *MI, uint32_t Reg);

void map_implicit_reads(MCInst *MI, const insn_map *imap);

void map_implicit_writes(MCInst *MI, const insn_map *imap);

void map_groups(MCInst *MI, const insn_map *imap);

void map_cs_id(MCInst *MI, const insn_map *imap, unsigned int imap_size);

#endif // CS_MAPPING_H