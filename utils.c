/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#include <libkern/libkern.h>
#else
#include <stdlib.h>
#endif
#include <string.h>

#include "utils.h"

// create a cache for fast id lookup
static unsigned short *make_id2insn(const insn_map *insns, unsigned int size)
{
	// NOTE: assume that the max id is always put at the end of insns array
	unsigned short max_id = insns[size - 1].id;
	unsigned short i;

	unsigned short *cache = (unsigned short *)cs_mem_calloc(max_id + 1, sizeof(*cache));

	for (i = 1; i < size; i++)
		cache[insns[i].id] = i;

	return cache;
}

// look for @id in @insns, given its size in @max. first time call will update @cache.
// return 0 if not found
unsigned short insn_find(const insn_map *insns, unsigned int max, unsigned int id, unsigned short **cache)
{
	if (id > insns[max - 1].id)
		return 0;

	if (*cache == NULL)
		*cache = make_id2insn(insns, max);

	return (*cache)[id];
}

int name2id(const name_map* map, int max, const char *name)
{
	int i;

	for (i = 0; i < max; i++) {
		if (!strcmp(map[i].name, name)) {
			return map[i].id;
		}
	}

	// nothing match
	return -1;
}

const char *id2name(const name_map* map, int max, const unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (map[i].id == id) {
			return map[i].name;
		}
	}

	// nothing match
	return NULL;
}

// count number of positive members in a list.
// NOTE: list must be guaranteed to end in 0
unsigned int count_positive(const uint16_t *list)
{
	unsigned int c;

	for (c = 0; list[c] > 0; c++);

	return c;
}

// count number of positive members in a list.
// NOTE: list must be guaranteed to end in 0
unsigned int count_positive8(const unsigned char *list)
{
	unsigned int c;

	for (c = 0; list[c] > 0; c++);

	return c;
}

char *cs_strdup(const char *str)
{
	size_t len = strlen(str) + 1;
	void *new = cs_mem_malloc(len);

	if (new == NULL)
		return NULL;

	return (char *)memmove(new, str, len);
}

// we need this since Windows doesn't have snprintf()
int cs_snprintf(char *buffer, size_t size, const char *fmt, ...)
{
	int ret;

	va_list ap;
	va_start(ap, fmt);
	ret = cs_vsnprintf(buffer, size, fmt, ap);
	va_end(ap);

	return ret;
}

bool arr_exist8(unsigned char *arr, unsigned char max, unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (arr[i] == id)
			return true;
	}

	return false;
}

bool arr_exist(uint16_t *arr, unsigned char max, unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (arr[i] == id)
			return true;
	}

	return false;
}

// binary search for encoding in IndexType array
// return -1 if not found, or index if found
unsigned int binsearch_IndexTypeEncoding(const struct IndexType *index, size_t size, uint16_t encoding)
{
	// binary searching since the index is sorted in encoding order
	size_t left, right, m;

	right = size - 1;

	if (encoding < index[0].encoding || encoding > index[right].encoding)
		// not found
		return -1;

	left = 0;

	while(left <= right) {
		m = (left + right) / 2;
		if (encoding == index[m].encoding) {
			return m;
		}

		if (encoding < index[m].encoding)
			right = m - 1;
		else
			left = m + 1;
	}

	// not found
	return -1;
}

/// Adds a register to the implicit write register list.
/// It will not add the same register twice.
void map_add_implicit_write(MCInst *MI, uint32_t Reg) {
	if (!MI->flat_insn->detail)
		return;

	uint16_t *regs_write = MI->flat_insn->detail->regs_write;
	for (int i = 0; i < MAX_IMPL_W_REGS; ++i) {
		if (i == MI->flat_insn->detail->regs_write_count) {
			regs_write[i] = Reg;
			MI->flat_insn->detail->regs_write_count++;
			return;
		}
		if (regs_write[i] == Reg)
			return;
	}
}

/// Copies the implicit read registers of @imap to @MI->flat_insn.
/// Already present registers will be preserved.
void map_implicit_reads(MCInst *MI, const insn_map *imap) {
#ifndef CAPSTONE_DIET
	if (!MI->flat_insn->detail)
		return;

	cs_detail *detail = MI->flat_insn->detail;
	unsigned Opcode = MCInst_getOpcode(MI);
	unsigned i = 0;
	uint16_t reg = imap[Opcode].regs_use[i];
	while (reg != 0) {
		if (i >= MAX_IMPL_R_REGS || detail->regs_read_count >= MAX_IMPL_R_REGS) {
			printf("ERROR: Too many implicit read register defined in instruction mapping.\n");
			return;
		}
		detail->regs_read[detail->regs_read_count++] = reg;
		reg = imap[Opcode].regs_use[++i];
	}
#endif // CAPSTONE_DIET
}

/// Copies the implicit write registers of @imap to @MI->flat_insn.
/// Already present registers will be preserved.
void map_implicit_writes(MCInst *MI, const insn_map *imap) {
#ifndef CAPSTONE_DIET
	if (!MI->flat_insn->detail)
		return;

	cs_detail *detail = MI->flat_insn->detail;
	unsigned Opcode = MCInst_getOpcode(MI);
	unsigned i = 0;
	uint16_t reg = imap[Opcode].regs_mod[i];
	while (reg != 0) {
		if (i >= MAX_IMPL_W_REGS || detail->regs_write_count >= MAX_IMPL_W_REGS) {
			printf("ERROR: Too many implicit write register defined in instruction mapping.\n");
			return;
		}
		detail->regs_write[detail->regs_write_count++] = reg;
		reg = imap[Opcode].regs_mod[++i];
	}
#endif // CAPSTONE_DIET
}

/// Copies the groups from @imap to @MI->flat_insn.
/// Already present groups will be preserved.
void map_groups(MCInst *MI, const insn_map *imap) {
#ifndef CAPSTONE_DIET
	if (!MI->flat_insn->detail)
		return;

	cs_detail *detail = MI->flat_insn->detail;
	unsigned Opcode = MCInst_getOpcode(MI);
	unsigned i = 0;
	uint16_t group = imap[Opcode].groups[i];
	while (group != 0) {
		if (i >= MAX_NUM_GROUPS || detail->regs_write_count >= MAX_NUM_GROUPS) {
			printf("ERROR: Too many groups defined in instruction mapping.\n");
			return;
		}
		detail->groups[detail->groups_count++] = group;
		group = imap[Opcode].groups[++i];
	}
#endif // CAPSTONE_DIET
}

// Search for the CS instruction id for the given @MC_Opcode in @imap.
// return -1 if none is found.
unsigned int find_cs_id(unsigned MC_Opcode, const insn_map *imap, unsigned imap_size)
{
	// binary searching since the IDs are sorted in order
	unsigned int left, right, m;
	unsigned int max = imap_size;

	right = max - 1;

	if (MC_Opcode < imap[0].id || MC_Opcode > imap[right].id)
		// not found
		return -1;

	left = 0;

	while(left <= right) {
		m = (left + right) / 2;
		if (MC_Opcode == imap[m].id) {
			return m;
		}

		if (MC_Opcode < imap[m].id)
			right = m - 1;
		else
			left = m + 1;
	}

	return -1;
}

/// Sets the Capstone instruction id which maps to the @MI opcode.
/// If no mapping is found the function returns and prints an error.
void map_cs_id(MCInst *MI, const insn_map *imap, unsigned int imap_size) {
	unsigned int i = find_cs_id(MCInst_getOpcode(MI), imap, imap_size);
	if (i != -1) {
		MI->flat_insn->id = imap[i].mapid;
		return;
	}
	printf("ERROR: Could not find CS id for MCInst opcode: %d\n", MCInst_getOpcode(MI));
	return;
}

/// Reads 4 bytes in the endian order specified in MI->cs->mode.
uint32_t readBytes32(MCInst *MI, const uint8_t *Bytes)
{
	assert(MI && Bytes);
	uint32_t Insn;
	if (MODE_IS_BIG_ENDIAN(MI->csh->mode))
		Insn = (Bytes[3] << 0) | (Bytes[2] << 8) | (Bytes[1] << 16) |
			   ((uint32_t)Bytes[0] << 24);
	else
		Insn = ((uint32_t)Bytes[3] << 24) | (Bytes[2] << 16) | (Bytes[1] << 8) |
			   (Bytes[0] << 0);
	return Insn;
}

/// Reads 2 bytes in the endian order specified in MI->cs->mode.
uint16_t readBytes16(MCInst *MI, const uint8_t *Bytes)
{
	assert(MI && Bytes);
	uint16_t Insn;
	if (MODE_IS_BIG_ENDIAN(MI->csh->mode))
		Insn = (Bytes[0] << 8) | Bytes[1];
	else
		Insn = (Bytes[1] << 8) | Bytes[0];

	return Insn;
}
