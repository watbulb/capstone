# V6 Release

With the `v6` release we added a new update mechanism called `auto-sync`.
This is a huge step for Capstone, because it allows for easy module updates, easier addition of new architectures, easy features addition and guarantees less faulty disassembly.

For `v6` we _updated_ the following architectures: `ARM`, `AArch64` and `PPC`.

These updates are significant! While in `v5` the most up-to-date module was based on `LLVM 7`,
the refactored modules will be based on `LLVM 17`!

As you see, does `auto-sync` solve the long existing problem that Capstone architecture modules were very hard to update.
For [`auto-sync` enabled modules](https://github.com/capstone-engine/capstone/issues/2015) this is no longer the case.

To achieve this we refactored some LLVM backends, so they emit directly the code we use in Capstone.
Additionally, we implemented many scripts, which automate a great number of manual steps during the update.

Because most of the update steps are automated now the architecture modules must fit this update mechanism.
For this the modules move closer to the original LLVM code.
On the flip site this brings many breaking changes.

You can find a list below with a description, justification and a possible way to revert this change locally.

With all the trouble this might bring for you, please keep in mind that this will only occur once for each architecture (when it gets refactored for `auto-sync`).
In the long term this will guarantee more stability, more correctness, more features and on top of this makes Capstone directly comparable to `llvm-obdjdump`.

We already added a handful of new features of which you can find a list below.

We hope you enjoy the new release!

## Breaking changes

General note about breaking changes.

**ARM**

| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| Post-index | Post-index memory access has the disponent now set int the `MEMORY` operand! No longer as separated `reg`/`imm` operand. |||
| Sign `mem.disp` | `mem.disp` is now always positive and the `subtracted` flag indicates if it should be subtracted. | It was inconsistent before. | Change behavior in `ARM_set_detail_op_imm()` |
| `ARM_CC` | `ARM_CC` → `ARMCC` and value change | | |
| System registers | System operands separated and in more detail. |||
| System operands | System operands have now the encoding of LLVM (SYSm value mostly) |||
| Instruction enum | Multiple instructions which were only alias were removed from the instruction enum. Exceptions are `POP`, `PUSH`, `VPOP`, `VPUSH` |||
| Instruction groups| Instruction groups, which actually were CU features, were renamed to reflect that. |||
| CPU features | CPU features get checked more strictly (`MCLASS`, `V8` etc.) |||
| `writeback` | `writeback` member was moved to detail. |||
| Register alias | Register alias (`r15 = pc`) are not printed if LLVM doesn't do it. Can be enabled by `CS_OPT_SYNTAX_CS_REG_ALIAS` |||
| Immediate | Immediate values (`arm_op.imm`) type changed to `int64_t` |||

**PPC**


| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| `PPC_BC` | The branch conditions were completely rewritten and save now all detail known about the bits. |||
| Instruction alias | Many instruction alias (e.g. `BF`) were removed from the instruction enum. |||
| Predicates | Predicate enums were renamed for this (values changed as well) |||
| `crx` | `ppc_ops_crx` was removed (because it was never set in the first place). |||


**AArch64**


| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| `ARM64` | `ARM64` renamed to `AArch64` everywhere |||
| `SME` operands | `SME` operands contain more detail now and member names are closer to the docs. |||
| System operands | System Operands are separated into different types now. |||


## New features

These features are only supported by `auto-sync` enabled architectures.

**Instruction Encoding**

TODO

**Instruction formats for PPC**

TODO

**Instruction Alias**

Instruction alias are now properly separated from real instructions.

The `cs_insn->is_alias` flag is set, if this instruction is an alias.

The real instruction `id` is still set in `cs_insn->id`.
The alias `id` is set in `cs_insn->alias_id`.

You can use as `cs_insn_name()` to retrieve the real and the alias name.

Additionally, you can now choose between the alias details and the real details.

You can set the option with (TODO: implement option. Otherwise, in `map_use_alias_details()` per arch).

If <OPTION IS SET>, you got the alias operands:

```
./cstool -d ppc32be 7a8a20007d4d42a6
 0  7a 8a 20 00  	rotldi	r10, r20, 4
	ID: 905 (rldicl)
	Is alias: 2138 (rotldi) with ALIAS operand set
	op_count: 4
		operands[0].type: REG = r10
		operands[0].access: WRITE
		operands[1].type: REG = r20
		operands[1].access: READ
		operands[2].type: IMM = 0x4
		operands[2].access: READ
```

If <OPTION IS DISABLED> you get the `real` operand set:

```
./cstool -d ppc32be 7a8a20007d4d42a6
 0  7a 8a 20 00  	rotldi	r10, r20, 4
	ID: 905 (rldicl)
	Is alias: 2138 (rotldi) with REAL operand set
	op_count: 4
		operands[0].type: REG = r10
		operands[0].access: WRITE
		operands[1].type: REG = r20
		operands[1].access: READ
		operands[2].type: IMM = 0x4
		operands[2].access: READ
		operands[3].type: IMM = 0x0
		operands[3].access: READ

```
