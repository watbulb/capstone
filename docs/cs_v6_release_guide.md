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
| `ARM_CC` | `ARM_CC` → `ARMCC` and value change | They match the same LLVM enum. Better for LLVM compatibility and code generation. | Change it manually. |
| System registers | System registers are no longer saved in `cs_arm->reg`, but are separated and have more detail. |||
| System operands | System operands have now the encoding of LLVM (SYSm value mostly) |||
| Instruction enum | Multiple instructions which were only alias were removed from the instruction enum. |||
| Instruction groups| Instruction groups, which actually were CPU features, were renamed to reflect that. | Names now match the ones in LLVM. Better for code generation. ||
| CPU features | CPU features get checked more strictly (`MCLASS`, `V8` etc.) |||
| `writeback` | `writeback` member was moved to detail. |||
| Register alias | Register alias (`r15 = pc`) are not printed if LLVM doesn't do it. Can be enabled by `CS_OPT_SYNTAX_CS_REG_ALIAS` |||
| Immediate | Immediate values (`arm_op.imm`) type changed to `int64_t` |||

**PPC**


| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| `PPC_BC` | The branch conditions were completely rewritten and save now all detail known about the bits. |||
| Instruction alias | Many instruction alias (e.g. `BF`) were removed from the instruction enum (see new alias feature below). |||
| Predicates | Predicate enums were renamed for the point above (values changed as well) |||
| `crx` | `ppc_ops_crx` was removed. | It was never set in the first place). ||
| `(RA|0)` | The `(RA|0)` cases (see ISA for details) for which `0` is used, the `PPC_REG_ZERO` register is used. The register name of it is `0`. | Mimics LLVM behavior. ||


**AArch64**


| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| `ARM64` | `ARM64` renamed to `AArch64` everywhere |||
| `SME` operands | `SME` operands contain more detail now and member names are closer to the docs. |||
| System operands | System Operands are separated into different types now. |||
| `writeback` | `writeback` member was moved to detail. |||
| `arm64_vas` | `arm64_vas` renamed to `AArch64Layout_VectorLayout` | LLVM compatibility. ||

**Note:**

Because of the name change from `ARM64` to `AArch64` several macros for meta programming were added.
If you need to support the previous version of Capstone you can use those macros.
They select the right name depending on `CS_NEXT_VERSION`.

The following `sed` commands in a sh script should ease the renaming from `ARM64` to `AArch64` a lot.

Replacing with version sensitive macros:

```sh
#!/bin/sh
echo "Replace enum names"

sed -i -E "s/CS_ARCH_ARM64/CS_AARCH64pre(CS_ARCH_)/g" $1
sed -i -E "s/ARM64_INS_(\\w+)/CS_AARCH64(_INS_\\1)/g" $1
sed -i -E "s/ARM64_REG_(\\w+)/CS_AARCH64(_REG_\\1)/g" $1
sed -i -E "s/ARM64_OP_(\\w+)/CS_AARCH64(_OP_\\1)/g" $1
sed -i -E "s/ARM64_EXT_(\\w+)/CS_AARCH64(_EXT_\\1)/g" $1
sed -i -E "s/ARM64_SFT_(\\w+)/CS_AARCH64(_SFT_\\1)/g" $1
sed -i -E "s/ARM64_VAS_(\\w+)/CS_AARCH64_VL_(\\1)/g" $1

sed -i -E "s/ARM64_CC_(\\w+)/CS_AARCH64CC(_\\1)/g" $1

echo "Replace type identifiers"

sed -i -E "s/cs_arm64_op /CS_aarch64_op() /g" $1
sed -i -E "s/arm64_reg /CS_aarch64_reg() /g" $1
sed -i -E "s/arm64_cc /CS_aarch64_cc() /g" $1
sed -i -E "s/cs_arm64 /CS_cs_aarch64() /g" $1
sed -i -E "s/arm64_extender /CS_aarch64_extender() /g" $1
sed -i -E "s/arm64_shifter /CS_aarch64_shifter() /g" $1
sed -i -E "s/arm64_vas /CS_aarch64_vas() /g" $1

echo "Replace detail->arm64"
sed -i -E "s/detail->arm64/detail->CS_aarch64()/g" $1	
```

Simple renaming from `ARM64` to `AArch64`:

```sh
#!/bin/sh
echo "Replace enum names"

sed -i "s|CS_ARCH_ARM64|CS_ARCH_AARCH64|g" $1
sed -i "s|ARM64_INS_|AArch64_INS_|g" $1
sed -i "s|ARM64_REG_|AArch64_REG_|g" $1
sed -i "s|ARM64_OP_|AArch64_OP_|g" $1
sed -i "s|ARM64_EXT_|AArch64_EXT_|g" $1
sed -i "s|ARM64_SFT_|AArch64_SFT_|g" $1
sed -i "s|ARM64_CC_|AArch64CC_|g" $1

echo "Replace type identifiers"

sed -i "s|arm64_reg|aarch64_reg|g" $1
sed -i "s|arm64_cc |AArch64CC_CondCode |g" $1
sed -i "s|cs_arm64|cs_aarch64|g" $1
sed -i "s|arm64_extender |aarch64_extender |g" $1
sed -i "s|arm64_shifter |aarch64_shifter |g" $1
sed -i "s|arm64_vas |AArch64Layout_VectorLayout |g" $1

echo "Replace detail->arm64"

sed -i "s|detail->arm64|detail->aarch64|g" $1
```

Write it into `rename_arm64.sh` and run it on files with `sh rename_arm64.sh <src-file>`

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
