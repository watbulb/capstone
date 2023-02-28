/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/* By Rot127 <unisono@quyllur.org>, 2023 */

/* Auto generated file. Do not edit. */
/* Code generator: https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */

{{ /* ARM_ASRi - ARM_INS_ASR - asr${s}${p} $Rd, $Rm, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_ASRr - ARM_INS_ASR - asr${s}${p} $Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_ITasm - ARM_INS_IT - it$mask $cc */
  { CS_OP_IMM, CS_AC_READ }, /* cc */
  { CS_OP_IMM, CS_AC_READ }, /* mask */
  { 0 }
}},
{{ /* ARM_LDRBT_POST - ARM_INS_LDRBT - ldrbt${q} $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRConstPool - ARM_INS_LDR - ldr${q} $Rt, $immediate */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* immediate */
  { 0 }
}},
{{ /* ARM_LDRHTii - ARM_INS_LDRHT - ldrht${p} $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRSBTii - ARM_INS_LDRSBT - ldrsbt${p} $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRSHTii - ARM_INS_LDRSHT - ldrsht${p} $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRT_POST - ARM_INS_LDRT - ldrt${q} $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LSLi - ARM_INS_LSL - lsl${s}${p} $Rd, $Rm, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_LSLr - ARM_INS_LSL - lsl${s}${p} $Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_LSRi - ARM_INS_LSR - lsr${s}${p} $Rd, $Rm, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_LSRr - ARM_INS_LSR - lsr${s}${p} $Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_RORi - ARM_INS_ROR - ror${s}${p} $Rd, $Rm, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_RORr - ARM_INS_ROR - ror${s}${p} $Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_RRXi - ARM_INS_RRX - rrx${s}${p} $Rd, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_STRBT_POST - ARM_INS_STRBT - strbt${q} $Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRT_POST - ARM_INS_STRT - strt${q} $Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD1LNdAsm_16 - ARM_INS_VLD1 - vld1${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD1LNdAsm_32 - ARM_INS_VLD1 - vld1${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD1LNdAsm_8 - ARM_INS_VLD1 - vld1${p}.8	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD1LNdWB_fixed_Asm_16 - ARM_INS_VLD1 - vld1${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD1LNdWB_fixed_Asm_32 - ARM_INS_VLD1 - vld1${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD1LNdWB_fixed_Asm_8 - ARM_INS_VLD1 - vld1${p}.8	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD1LNdWB_register_Asm_16 - ARM_INS_VLD1 - vld1${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1LNdWB_register_Asm_32 - ARM_INS_VLD1 - vld1${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1LNdWB_register_Asm_8 - ARM_INS_VLD1 - vld1${p}.8	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2LNdAsm_16 - ARM_INS_VLD2 - vld2${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNdAsm_32 - ARM_INS_VLD2 - vld2${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNdAsm_8 - ARM_INS_VLD2 - vld2${p}.8	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNdWB_fixed_Asm_16 - ARM_INS_VLD2 - vld2${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNdWB_fixed_Asm_32 - ARM_INS_VLD2 - vld2${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNdWB_fixed_Asm_8 - ARM_INS_VLD2 - vld2${p}.8	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNdWB_register_Asm_16 - ARM_INS_VLD2 - vld2${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2LNdWB_register_Asm_32 - ARM_INS_VLD2 - vld2${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2LNdWB_register_Asm_8 - ARM_INS_VLD2 - vld2${p}.8	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2LNqAsm_16 - ARM_INS_VLD2 - vld2${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNqAsm_32 - ARM_INS_VLD2 - vld2${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNqWB_fixed_Asm_16 - ARM_INS_VLD2 - vld2${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNqWB_fixed_Asm_32 - ARM_INS_VLD2 - vld2${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD2LNqWB_register_Asm_16 - ARM_INS_VLD2 - vld2${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2LNqWB_register_Asm_32 - ARM_INS_VLD2 - vld2${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPdAsm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPdAsm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPdAsm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPdWB_fixed_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPdWB_fixed_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPdWB_fixed_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPdWB_register_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPdWB_register_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPdWB_register_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPqAsm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPqAsm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPqAsm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPqWB_fixed_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPqWB_fixed_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPqWB_fixed_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3DUPqWB_register_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPqWB_register_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPqWB_register_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3LNdAsm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNdAsm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNdAsm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNdWB_fixed_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNdWB_fixed_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNdWB_fixed_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNdWB_register_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3LNdWB_register_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3LNdWB_register_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3LNqAsm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNqAsm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNqWB_fixed_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNqWB_fixed_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3LNqWB_register_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3LNqWB_register_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3dAsm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3dAsm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3dAsm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3dWB_fixed_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3dWB_fixed_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3dWB_fixed_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3dWB_register_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3dWB_register_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3dWB_register_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3qAsm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3qAsm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3qAsm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3qWB_fixed_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3qWB_fixed_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3qWB_fixed_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD3qWB_register_Asm_16 - ARM_INS_VLD3 - vld3${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3qWB_register_Asm_32 - ARM_INS_VLD3 - vld3${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3qWB_register_Asm_8 - ARM_INS_VLD3 - vld3${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPdAsm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPdAsm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPdAsm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPdWB_fixed_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPdWB_fixed_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPdWB_fixed_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPdWB_register_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPdWB_register_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPdWB_register_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPqAsm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPqAsm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPqAsm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPqWB_fixed_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPqWB_fixed_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPqWB_fixed_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4DUPqWB_register_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPqWB_register_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPqWB_register_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4LNdAsm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNdAsm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNdAsm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNdWB_fixed_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNdWB_fixed_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNdWB_fixed_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNdWB_register_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4LNdWB_register_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4LNdWB_register_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4LNqAsm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNqAsm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNqWB_fixed_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNqWB_fixed_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4LNqWB_register_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4LNqWB_register_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4dAsm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4dAsm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4dAsm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4dWB_fixed_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4dWB_fixed_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4dWB_fixed_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4dWB_register_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4dWB_register_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4dWB_register_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4qAsm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4qAsm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4qAsm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4qWB_fixed_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4qWB_fixed_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4qWB_fixed_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLD4qWB_register_Asm_16 - ARM_INS_VLD4 - vld4${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4qWB_register_Asm_32 - ARM_INS_VLD4 - vld4${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4qWB_register_Asm_8 - ARM_INS_VLD4 - vld4${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST1LNdAsm_16 - ARM_INS_VST1 - vst1${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST1LNdAsm_32 - ARM_INS_VST1 - vst1${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST1LNdAsm_8 - ARM_INS_VST1 - vst1${p}.8	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST1LNdWB_fixed_Asm_16 - ARM_INS_VST1 - vst1${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST1LNdWB_fixed_Asm_32 - ARM_INS_VST1 - vst1${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST1LNdWB_fixed_Asm_8 - ARM_INS_VST1 - vst1${p}.8	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST1LNdWB_register_Asm_16 - ARM_INS_VST1 - vst1${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST1LNdWB_register_Asm_32 - ARM_INS_VST1 - vst1${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST1LNdWB_register_Asm_8 - ARM_INS_VST1 - vst1${p}.8	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST2LNdAsm_16 - ARM_INS_VST2 - vst2${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNdAsm_32 - ARM_INS_VST2 - vst2${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNdAsm_8 - ARM_INS_VST2 - vst2${p}.8	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNdWB_fixed_Asm_16 - ARM_INS_VST2 - vst2${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNdWB_fixed_Asm_32 - ARM_INS_VST2 - vst2${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNdWB_fixed_Asm_8 - ARM_INS_VST2 - vst2${p}.8	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNdWB_register_Asm_16 - ARM_INS_VST2 - vst2${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST2LNdWB_register_Asm_32 - ARM_INS_VST2 - vst2${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST2LNdWB_register_Asm_8 - ARM_INS_VST2 - vst2${p}.8	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST2LNqAsm_16 - ARM_INS_VST2 - vst2${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNqAsm_32 - ARM_INS_VST2 - vst2${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNqWB_fixed_Asm_16 - ARM_INS_VST2 - vst2${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNqWB_fixed_Asm_32 - ARM_INS_VST2 - vst2${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST2LNqWB_register_Asm_16 - ARM_INS_VST2 - vst2${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST2LNqWB_register_Asm_32 - ARM_INS_VST2 - vst2${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3LNdAsm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNdAsm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNdAsm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNdWB_fixed_Asm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNdWB_fixed_Asm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNdWB_fixed_Asm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNdWB_register_Asm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3LNdWB_register_Asm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3LNdWB_register_Asm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3LNqAsm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNqAsm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNqWB_fixed_Asm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNqWB_fixed_Asm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3LNqWB_register_Asm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3LNqWB_register_Asm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3dAsm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3dAsm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3dAsm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3dWB_fixed_Asm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3dWB_fixed_Asm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3dWB_fixed_Asm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3dWB_register_Asm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3dWB_register_Asm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3dWB_register_Asm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3qAsm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3qAsm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3qAsm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3qWB_fixed_Asm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3qWB_fixed_Asm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3qWB_fixed_Asm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST3qWB_register_Asm_16 - ARM_INS_VST3 - vst3${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3qWB_register_Asm_32 - ARM_INS_VST3 - vst3${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST3qWB_register_Asm_8 - ARM_INS_VST3 - vst3${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4LNdAsm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNdAsm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNdAsm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNdWB_fixed_Asm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNdWB_fixed_Asm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNdWB_fixed_Asm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNdWB_register_Asm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4LNdWB_register_Asm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4LNdWB_register_Asm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4LNqAsm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNqAsm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNqWB_fixed_Asm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNqWB_fixed_Asm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4LNqWB_register_Asm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4LNqWB_register_Asm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4dAsm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4dAsm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4dAsm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4dWB_fixed_Asm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4dWB_fixed_Asm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4dWB_fixed_Asm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4dWB_register_Asm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4dWB_register_Asm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4dWB_register_Asm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4qAsm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4qAsm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4qAsm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4qWB_fixed_Asm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4qWB_fixed_Asm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4qWB_fixed_Asm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VST4qWB_register_Asm_16 - ARM_INS_VST4 - vst4${p}.16	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4qWB_register_Asm_32 - ARM_INS_VST4 - vst4${p}.32	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VST4qWB_register_Asm_8 - ARM_INS_VST4 - vst4${p}.8	$list, $addr, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* list */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2LDRBpcrel - ARM_INS_LDRB - ldrb${p} $Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRConstPool - ARM_INS_LDR - ldr${p} $Rt, $immediate */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* immediate */
  { 0 }
}},
{{ /* ARM_t2LDRHpcrel - ARM_INS_LDRH - ldrh${p} $Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSBpcrel - ARM_INS_LDRSB - ldrsb${p} $Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSHpcrel - ARM_INS_LDRSH - ldrsh${p} $Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDR_POST_imm - ARM_INS_LDR - ldr${p}.w $Rt, $Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2LDR_PRE_imm - ARM_INS_LDR - ldr${p}.w $Rt, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRpcrel - ARM_INS_LDR - ldr${p} $Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2MOVSsi - ARM_INS_MOVS - movs${p} $Rd, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_t2MOVSsr - ARM_INS_MOVS - movs${p} $Rd, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_t2MOVsi - ARM_INS_MOV - mov${p} $Rd, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_t2MOVsr - ARM_INS_MOV - mov${p} $Rd, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_t2STR_POST_imm - ARM_INS_STR - str${p}.w $Rt, $Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2STR_PRE_imm - ARM_INS_STR - str${p}.w $Rt, $addr! */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRConstPool - ARM_INS_LDR - ldr${p} $Rt, $immediate */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* immediate */
  { 0 }
}},
{{ /* ARM_ADCri - ARM_INS_ADC - adc${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_ADCrr - ARM_INS_ADC - adc${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_ADCrsi - ARM_INS_ADC - adc${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_ADCrsr - ARM_INS_ADC - adc${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_ADDri - ARM_INS_ADD - add${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_ADDrr - ARM_INS_ADD - add${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_ADDrsi - ARM_INS_ADD - add${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_ADDrsr - ARM_INS_ADD - add${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_ADR - ARM_INS_ADR - adr${p}	$Rd, $label */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_AESD - ARM_INS_AESD - aesd.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_AESE - ARM_INS_AESE - aese.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_AESIMC - ARM_INS_AESIMC - aesimc.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_AESMC - ARM_INS_AESMC - aesmc.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_ANDri - ARM_INS_AND - and${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_ANDrr - ARM_INS_AND - and${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_ANDrsi - ARM_INS_AND - and${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_ANDrsr - ARM_INS_AND - and${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_BF16VDOTI_VDOTD - ARM_INS_VDOT - vdot.bf16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_BF16VDOTI_VDOTQ - ARM_INS_VDOT - vdot.bf16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_BF16VDOTS_VDOTD - ARM_INS_VDOT - vdot.bf16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_BF16VDOTS_VDOTQ - ARM_INS_VDOT - vdot.bf16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_BF16_VCVT - ARM_INS_VCVT - vcvt${p}.bf16.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_BF16_VCVTB - ARM_INS_VCVTB - vcvtb${p}.bf16.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_BF16_VCVTT - ARM_INS_VCVTT - vcvtt${p}.bf16.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_BFC - ARM_INS_BFC - bfc${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_BFI - ARM_INS_BFI - bfi${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_BICri - ARM_INS_BIC - bic${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_BICrr - ARM_INS_BIC - bic${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_BICrsi - ARM_INS_BIC - bic${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_BICrsr - ARM_INS_BIC - bic${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_BKPT - ARM_INS_BKPT - bkpt	$val */
  { CS_OP_IMM, CS_AC_READ }, /* val */
  { 0 }
}},
{{ /* ARM_BL - ARM_INS_BL - bl	$func */
  { CS_OP_IMM, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_BLX - ARM_INS_BLX - blx	$func */
  { CS_OP_REG, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_BLX_pred - ARM_INS_BLX - blx${p}	$func */
  { CS_OP_REG, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_BLXi - ARM_INS_BLX - blx	$target */
  { CS_OP_IMM, CS_AC_READ }, /* target */
  { 0 }
}},
{{ /* ARM_BL_pred - ARM_INS_BL - bl${p}	$func */
  { CS_OP_IMM, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_BX - ARM_INS_BX - bx	$dst */
  { CS_OP_REG, CS_AC_READ }, /* dst */
  { 0 }
}},
{{ /* ARM_BXJ - ARM_INS_BXJ - bxj${p}	$func */
  { CS_OP_REG, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_BX_RET - ARM_INS_BX - bx${p}	lr */
  { 0 }
}},
{{ /* ARM_BX_pred - ARM_INS_BX - bx${p}	$dst */
  { CS_OP_REG, CS_AC_READ }, /* dst */
  { 0 }
}},
{{ /* ARM_Bcc - ARM_INS_B - b${p}	$target */
  { CS_OP_IMM, CS_AC_READ }, /* target */
  { 0 }
}},
{{ /* ARM_CDE_CX1 - ARM_INS_CX1 - cx1	$coproc, $Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX1A - ARM_INS_CX1A - cx1a${p}	$coproc, $Rd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX1D - ARM_INS_CX1D - cx1d	$coproc, $Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX1DA - ARM_INS_CX1DA - cx1da${p}	$coproc, $Rd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX2 - ARM_INS_CX2 - cx2	$coproc, $Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX2A - ARM_INS_CX2A - cx2a${p}	$coproc, $Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX2D - ARM_INS_CX2D - cx2d	$coproc, $Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX2DA - ARM_INS_CX2DA - cx2da${p}	$coproc, $Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX3 - ARM_INS_CX3 - cx3	$coproc, $Rd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX3A - ARM_INS_CX3A - cx3a${p}	$coproc, $Rd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX3D - ARM_INS_CX3D - cx3d	$coproc, $Rd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_CX3DA - ARM_INS_CX3DA - cx3da${p}	$coproc, $Rd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX1A_fpdp - ARM_INS_VCX1A - vcx1a	$coproc, $Vd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX1A_fpsp - ARM_INS_VCX1A - vcx1a	$coproc, $Vd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX1A_vec - ARM_INS_VCX1A - vcx1a${vp}	$coproc, $Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX1_fpdp - ARM_INS_VCX1 - vcx1	$coproc, $Vd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX1_fpsp - ARM_INS_VCX1 - vcx1	$coproc, $Vd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX1_vec - ARM_INS_VCX1 - vcx1${vp}	$coproc, $Qd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX2A_fpdp - ARM_INS_VCX2A - vcx2a	$coproc, $Vd, $Vm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX2A_fpsp - ARM_INS_VCX2A - vcx2a	$coproc, $Vd, $Vm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX2A_vec - ARM_INS_VCX2A - vcx2a${vp}	$coproc, $Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX2_fpdp - ARM_INS_VCX2 - vcx2	$coproc, $Vd, $Vm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX2_fpsp - ARM_INS_VCX2 - vcx2	$coproc, $Vd, $Vm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX2_vec - ARM_INS_VCX2 - vcx2${vp}	$coproc, $Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX3A_fpdp - ARM_INS_VCX3A - vcx3a	$coproc, $Vd, $Vn, $Vm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX3A_fpsp - ARM_INS_VCX3A - vcx3a	$coproc, $Vd, $Vn, $Vm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX3A_vec - ARM_INS_VCX3A - vcx3a${vp}	$coproc, $Qd, $Qn, $Qm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX3_fpdp - ARM_INS_VCX3 - vcx3	$coproc, $Vd, $Vn, $Vm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX3_fpsp - ARM_INS_VCX3 - vcx3	$coproc, $Vd, $Vn, $Vm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDE_VCX3_vec - ARM_INS_VCX3 - vcx3${vp}	$coproc, $Qd, $Qn, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* coproc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CDP - ARM_INS_CDP - cdp${p}	$cop, $opc1, $CRd, $CRn, $CRm, $opc2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_CDP2 - ARM_INS_CDP2 - cdp2	$cop, $opc1, $CRd, $CRn, $CRm, $opc2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_CLREX - ARM_INS_CLREX - clrex */
  { 0 }
}},
{{ /* ARM_CLZ - ARM_INS_CLZ - clz${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_CMNri - ARM_INS_CMN - cmn${p}	$Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CMNzrr - ARM_INS_CMN - cmn${p}	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_CMNzrsi - ARM_INS_CMN - cmn${p}	$Rn, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_CMNzrsr - ARM_INS_CMN - cmn${p}	$Rn, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_CMPri - ARM_INS_CMP - cmp${p}	$Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_CMPrr - ARM_INS_CMP - cmp${p}	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_CMPrsi - ARM_INS_CMP - cmp${p}	$Rn, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_CMPrsr - ARM_INS_CMP - cmp${p}	$Rn, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_CPS1p - ARM_INS_CPS - cps	$mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_CPS2p - ARM_INS_CPS - cps$imod	$iflags */
  { CS_OP_IMM, CS_AC_READ }, /* imod */
  { CS_OP_IMM, CS_AC_READ }, /* iflags */
  { 0 }
}},
{{ /* ARM_CPS3p - ARM_INS_CPS - cps$imod	$iflags, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* imod */
  { CS_OP_IMM, CS_AC_READ }, /* iflags */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_CRC32B - ARM_INS_CRC32B - crc32b	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_CRC32CB - ARM_INS_CRC32CB - crc32cb	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_CRC32CH - ARM_INS_CRC32CH - crc32ch	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_CRC32CW - ARM_INS_CRC32CW - crc32cw	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_CRC32H - ARM_INS_CRC32H - crc32h	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_CRC32W - ARM_INS_CRC32W - crc32w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_DBG - ARM_INS_DBG - dbg${p}	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_DMB - ARM_INS_DMB - dmb	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_DSB - ARM_INS_DSB - dsb	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_EORri - ARM_INS_EOR - eor${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_EORrr - ARM_INS_EOR - eor${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_EORrsi - ARM_INS_EOR - eor${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_EORrsr - ARM_INS_EOR - eor${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_ERET - ARM_INS_ERET - eret${p} */
  { 0 }
}},
{{ /* ARM_FCONSTD - ARM_INS_VMOV - vmov${p}.f64	$Dd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_FCONSTH - ARM_INS_VMOV - vmov${p}.f16	$Sd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_FCONSTS - ARM_INS_VMOV - vmov${p}.f32	$Sd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_FLDMXDB_UPD - ARM_INS_FLDMDBX - fldmdbx${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_FLDMXIA - ARM_INS_FLDMIAX - fldmiax${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_FLDMXIA_UPD - ARM_INS_FLDMIAX - fldmiax${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_FMSTAT - ARM_INS_VMRS - vmrs${p}	APSR_nzcv, fpscr */
  { 0 }
}},
{{ /* ARM_FSTMXDB_UPD - ARM_INS_FSTMDBX - fstmdbx${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_FSTMXIA - ARM_INS_FSTMIAX - fstmiax${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_FSTMXIA_UPD - ARM_INS_FSTMIAX - fstmiax${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_HINT - ARM_INS_HINT - hint${p}	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_HINT - ARM_INS_YIELD - hint${p}	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_HLT - ARM_INS_HLT - hlt	$val */
  { CS_OP_IMM, CS_AC_READ }, /* val */
  { 0 }
}},
{{ /* ARM_HVC - ARM_INS_HVC - hvc	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_ISB - ARM_INS_ISB - isb	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_LDA - ARM_INS_LDA - lda${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDAB - ARM_INS_LDAB - ldab${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDAEX - ARM_INS_LDAEX - ldaex${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDAEXB - ARM_INS_LDAEXB - ldaexb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDAEXD - ARM_INS_LDAEXD - ldaexd${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDAEXH - ARM_INS_LDAEXH - ldaexh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDAH - ARM_INS_LDAH - ldah${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDC2L_OFFSET - ARM_INS_LDC2L - ldc2l	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDC2L_OPTION - ARM_INS_LDC2L - ldc2l	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_LDC2L_POST - ARM_INS_LDC2L - ldc2l	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDC2L_PRE - ARM_INS_LDC2L - ldc2l	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDC2_OFFSET - ARM_INS_LDC2 - ldc2	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDC2_OPTION - ARM_INS_LDC2 - ldc2	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_LDC2_POST - ARM_INS_LDC2 - ldc2	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDC2_PRE - ARM_INS_LDC2 - ldc2	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDCL_OFFSET - ARM_INS_LDCL - ldcl${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDCL_OPTION - ARM_INS_LDCL - ldcl${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_LDCL_POST - ARM_INS_LDCL - ldcl${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDCL_PRE - ARM_INS_LDCL - ldcl${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDC_OFFSET - ARM_INS_LDC - ldc${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDC_OPTION - ARM_INS_LDC - ldc${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_LDC_POST - ARM_INS_LDC - ldc${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDC_PRE - ARM_INS_LDC - ldc${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDMDA - ARM_INS_LDMDA - ldmda${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_LDMDA_UPD - ARM_INS_LDMDA - ldmda${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_LDMDB - ARM_INS_LDMDB - ldmdb${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_LDMDB_UPD - ARM_INS_LDMDB - ldmdb${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_LDMIA - ARM_INS_LDM - ldm${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_LDMIA_UPD - ARM_INS_LDM - ldm${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_LDMIB - ARM_INS_LDMIB - ldmib${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_LDMIB_UPD - ARM_INS_LDMIB - ldmib${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_LDRBT_POST_IMM - ARM_INS_LDRBT - ldrbt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRBT_POST_REG - ARM_INS_LDRBT - ldrbt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRB_POST_IMM - ARM_INS_LDRB - ldrb${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRB_POST_REG - ARM_INS_LDRB - ldrb${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRB_PRE_IMM - ARM_INS_LDRB - ldrb${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRB_PRE_REG - ARM_INS_LDRB - ldrb${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRBi12 - ARM_INS_LDRB - ldrb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRBrs - ARM_INS_LDRB - ldrb${p}	$Rt, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_LDRD - ARM_INS_LDRD - ldrd${p}	$Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRD_POST - ARM_INS_LDRD - ldrd${p}	$Rt, $Rt2, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRD_PRE - ARM_INS_LDRD - ldrd${p}	$Rt, $Rt2, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDREX - ARM_INS_LDREX - ldrex${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDREXB - ARM_INS_LDREXB - ldrexb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDREXD - ARM_INS_LDREXD - ldrexd${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDREXH - ARM_INS_LDREXH - ldrexh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRH - ARM_INS_LDRH - ldrh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRHTi - ARM_INS_LDRHT - ldrht${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* base_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRHTr - ARM_INS_LDRHT - ldrht${p}	$Rt, $addr, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* base_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_LDRH_POST - ARM_INS_LDRH - ldrh${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRH_PRE - ARM_INS_LDRH - ldrh${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRSB - ARM_INS_LDRSB - ldrsb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRSBTi - ARM_INS_LDRSBT - ldrsbt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* base_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRSBTr - ARM_INS_LDRSBT - ldrsbt${p}	$Rt, $addr, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* base_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_LDRSB_POST - ARM_INS_LDRSB - ldrsb${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRSB_PRE - ARM_INS_LDRSB - ldrsb${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRSH - ARM_INS_LDRSH - ldrsh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRSHTi - ARM_INS_LDRSHT - ldrsht${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* base_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRSHTr - ARM_INS_LDRSHT - ldrsht${p}	$Rt, $addr, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* base_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_LDRSH_POST - ARM_INS_LDRSH - ldrsh${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRSH_PRE - ARM_INS_LDRSH - ldrsh${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRT_POST_IMM - ARM_INS_LDRT - ldrt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDRT_POST_REG - ARM_INS_LDRT - ldrt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDR_POST_IMM - ARM_INS_LDR - ldr${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDR_POST_REG - ARM_INS_LDR - ldr${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_LDR_PRE_IMM - ARM_INS_LDR - ldr${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDR_PRE_REG - ARM_INS_LDR - ldr${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRi12 - ARM_INS_LDR - ldr${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_LDRrs - ARM_INS_LDR - ldr${p}	$Rt, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_MCR - ARM_INS_MCR - mcr${p}	$cop, $opc1, $Rt, $CRn, $CRm, $opc2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_MCR2 - ARM_INS_MCR2 - mcr2	$cop, $opc1, $Rt, $CRn, $CRm, $opc2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_MCRR - ARM_INS_MCRR - mcrr${p}	$cop, $opc1, $Rt, $Rt2, $CRm */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { 0 }
}},
{{ /* ARM_MCRR2 - ARM_INS_MCRR2 - mcrr2	$cop, $opc1, $Rt, $Rt2, $CRm */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { 0 }
}},
{{ /* ARM_MLA - ARM_INS_MLA - mla${s}${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_MLS - ARM_INS_MLS - mls${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_MOVPCLR - ARM_INS_MOV - mov${p}	pc, lr */
  { 0 }
}},
{{ /* ARM_MOVTi16 - ARM_INS_MOVT - movt${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MOVi - ARM_INS_MOV - mov${s}${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MOVi16 - ARM_INS_MOVW - movw${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MOVr - ARM_INS_MOV - mov${s}${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MOVr_TC - ARM_INS_MOV - mov${s}${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MOVsi - ARM_INS_MOV - mov${s}${p}	$Rd, $src */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_MOVsr - ARM_INS_MOV - mov${s}${p}	$Rd, $src */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_MRC - ARM_INS_MRC - mrc${p}	$cop, $opc1, $Rt, $CRn, $CRm, $opc2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_MRC2 - ARM_INS_MRC2 - mrc2	$cop, $opc1, $Rt, $CRn, $CRm, $opc2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_MRRC - ARM_INS_MRRC - mrrc${p}	$cop, $opc1, $Rt, $Rt2, $CRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { 0 }
}},
{{ /* ARM_MRRC2 - ARM_INS_MRRC2 - mrrc2	$cop, $opc1, $Rt, $Rt2, $CRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { 0 }
}},
{{ /* ARM_MRS - ARM_INS_MRS - mrs${p}	$Rd, apsr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { 0 }
}},
{{ /* ARM_MRSbanked - ARM_INS_MRS - mrs${p}	$Rd, $banked */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* banked */
  { 0 }
}},
{{ /* ARM_MRSsys - ARM_INS_MRS - mrs${p}	$Rd, spsr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { 0 }
}},
{{ /* ARM_MSR - ARM_INS_MSR - msr${p}	$mask, $Rn */
  { CS_OP_IMM, CS_AC_READ }, /* mask */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MSRbanked - ARM_INS_MSR - msr${p}	$banked, $Rn */
  { CS_OP_IMM, CS_AC_READ }, /* banked */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MSRi - ARM_INS_MSR - msr${p}	$mask, $imm */
  { CS_OP_IMM, CS_AC_READ }, /* mask */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MUL - ARM_INS_MUL - mul${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_ASRLi - ARM_INS_ASRL - asrl${p}	$RdaLo, $RdaHi, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_ASRLr - ARM_INS_ASRL - asrl${p}	$RdaLo, $RdaHi, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_DLSTP_16 - ARM_INS_DLSTP - dlstp.16	$LR, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_DLSTP_32 - ARM_INS_DLSTP - dlstp.32	$LR, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_DLSTP_64 - ARM_INS_DLSTP - dlstp.64	$LR, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_DLSTP_8 - ARM_INS_DLSTP - dlstp.8	$LR, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_LCTP - ARM_INS_LCTP - lctp${p}	 */
  { 0 }
}},
{{ /* ARM_MVE_LETP - ARM_INS_LETP - letp	$LRin, $label */
  { CS_OP_REG, CS_AC_WRITE }, /* LRout */
  { CS_OP_REG, CS_AC_READ }, /* LRin */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_MVE_LSLLi - ARM_INS_LSLL - lsll${p}	$RdaLo, $RdaHi, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_LSLLr - ARM_INS_LSLL - lsll${p}	$RdaLo, $RdaHi, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_LSRL - ARM_INS_LSRL - lsrl${p}	$RdaLo, $RdaHi, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_SQRSHR - ARM_INS_SQRSHR - sqrshr${p}	$RdaSrc, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_SQRSHRL - ARM_INS_SQRSHRL - sqrshrl${p}	$RdaLo, $RdaHi, $sat, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* sat */
  { 0 }
}},
{{ /* ARM_MVE_SQSHL - ARM_INS_SQSHL - sqshl${p}	$RdaSrc, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_SQSHLL - ARM_INS_SQSHLL - sqshll${p}	$RdaLo, $RdaHi, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_SRSHR - ARM_INS_SRSHR - srshr${p}	$RdaSrc, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_SRSHRL - ARM_INS_SRSHRL - srshrl${p}	$RdaLo, $RdaHi, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_UQRSHL - ARM_INS_UQRSHL - uqrshl${p}	$RdaSrc, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_UQRSHLL - ARM_INS_UQRSHLL - uqrshll${p}	$RdaLo, $RdaHi, $sat, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* sat */
  { 0 }
}},
{{ /* ARM_MVE_UQSHL - ARM_INS_UQSHL - uqshl${p}	$RdaSrc, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_UQSHLL - ARM_INS_UQSHLL - uqshll${p}	$RdaLo, $RdaHi, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_URSHR - ARM_INS_URSHR - urshr${p}	$RdaSrc, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_URSHRL - ARM_INS_URSHRL - urshrl${p}	$RdaLo, $RdaHi, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VABAVs16 - ARM_INS_VABAV - vabav${vp}.s16	$Rda, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABAVs32 - ARM_INS_VABAV - vabav${vp}.s32	$Rda, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABAVs8 - ARM_INS_VABAV - vabav${vp}.s8	$Rda, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABAVu16 - ARM_INS_VABAV - vabav${vp}.u16	$Rda, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABAVu32 - ARM_INS_VABAV - vabav${vp}.u32	$Rda, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABAVu8 - ARM_INS_VABAV - vabav${vp}.u8	$Rda, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABDf16 - ARM_INS_VABD - vabd${vp}.f16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABDf32 - ARM_INS_VABD - vabd${vp}.f32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABDs16 - ARM_INS_VABD - vabd${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABDs32 - ARM_INS_VABD - vabd${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABDs8 - ARM_INS_VABD - vabd${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABDu16 - ARM_INS_VABD - vabd${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABDu32 - ARM_INS_VABD - vabd${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABDu8 - ARM_INS_VABD - vabd${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABSf16 - ARM_INS_VABS - vabs${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABSf32 - ARM_INS_VABS - vabs${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABSs16 - ARM_INS_VABS - vabs${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABSs32 - ARM_INS_VABS - vabs${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VABSs8 - ARM_INS_VABS - vabs${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADC - ARM_INS_VADC - vadc${vp}.i32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_WRITE }, /* carryout */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* carryin */
  { 0 }
}},
{{ /* ARM_MVE_VADCI - ARM_INS_VADCI - vadci${vp}.i32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_WRITE }, /* carryout */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDLVs32acc - ARM_INS_VADDLVA - vaddlva${vp}.s32	$RdaLo, $RdaHi, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDLVs32no_acc - ARM_INS_VADDLV - vaddlv${vp}.s32	$RdaLo, $RdaHi, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHi */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDLVu32acc - ARM_INS_VADDLVA - vaddlva${vp}.u32	$RdaLo, $RdaHi, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* RdaHi */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDLVu32no_acc - ARM_INS_VADDLV - vaddlv${vp}.u32	$RdaLo, $RdaHi, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHi */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVs16acc - ARM_INS_VADDVA - vaddva${vp}.s16	$Rda, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVs16no_acc - ARM_INS_VADDV - vaddv${vp}.s16	$Rda, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVs32acc - ARM_INS_VADDVA - vaddva${vp}.s32	$Rda, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVs32no_acc - ARM_INS_VADDV - vaddv${vp}.s32	$Rda, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVs8acc - ARM_INS_VADDVA - vaddva${vp}.s8	$Rda, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVs8no_acc - ARM_INS_VADDV - vaddv${vp}.s8	$Rda, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVu16acc - ARM_INS_VADDVA - vaddva${vp}.u16	$Rda, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVu16no_acc - ARM_INS_VADDV - vaddv${vp}.u16	$Rda, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVu32acc - ARM_INS_VADDVA - vaddva${vp}.u32	$Rda, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVu32no_acc - ARM_INS_VADDV - vaddv${vp}.u32	$Rda, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVu8acc - ARM_INS_VADDVA - vaddva${vp}.u8	$Rda, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDVu8no_acc - ARM_INS_VADDV - vaddv${vp}.u8	$Rda, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rda */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADD_qr_f16 - ARM_INS_VADD - vadd${vp}.f16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VADD_qr_f32 - ARM_INS_VADD - vadd${vp}.f32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VADD_qr_i16 - ARM_INS_VADD - vadd${vp}.i16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VADD_qr_i32 - ARM_INS_VADD - vadd${vp}.i32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VADD_qr_i8 - ARM_INS_VADD - vadd${vp}.i8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VADDf16 - ARM_INS_VADD - vadd${vp}.f16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDf32 - ARM_INS_VADD - vadd${vp}.f32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDi16 - ARM_INS_VADD - vadd${vp}.i16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDi32 - ARM_INS_VADD - vadd${vp}.i32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VADDi8 - ARM_INS_VADD - vadd${vp}.i8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VAND - ARM_INS_VAND - vand${vp}	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VBIC - ARM_INS_VBIC - vbic${vp}	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VBICimmi16 - ARM_INS_VAND - vbic${vp}.i16	$Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VBICimmi16 - ARM_INS_VBIC - vbic${vp}.i16	$Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VBICimmi32 - ARM_INS_VBIC - vbic${vp}.i32	$Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VBICimmi32 - ARM_INS_VAND - vbic${vp}.i32	$Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VBRSR16 - ARM_INS_VBRSR - vbrsr${vp}.16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VBRSR32 - ARM_INS_VBRSR - vbrsr${vp}.32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VBRSR8 - ARM_INS_VBRSR - vbrsr${vp}.8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VCADDf16 - ARM_INS_VCADD - vcadd${vp}.f16	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCADDf32 - ARM_INS_VCADD - vcadd${vp}.f32	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCADDi16 - ARM_INS_VCADD - vcadd${vp}.i16	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCADDi32 - ARM_INS_VCADD - vcadd${vp}.i32	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCADDi8 - ARM_INS_VCADD - vcadd${vp}.i8	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCLSs16 - ARM_INS_VCLS - vcls${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCLSs32 - ARM_INS_VCLS - vcls${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCLSs8 - ARM_INS_VCLS - vcls${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCLZs16 - ARM_INS_VCLZ - vclz${vp}.i16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCLZs32 - ARM_INS_VCLZ - vclz${vp}.i32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCLZs8 - ARM_INS_VCLZ - vclz${vp}.i8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCMLAf16 - ARM_INS_VCMLA - vcmla${vp}.f16	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCMLAf32 - ARM_INS_VCMLA - vcmla${vp}.f32	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCMPf16 - ARM_INS_VCMP - vcmp${vp}.f16	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPf16r - ARM_INS_VCMP - vcmp${vp}.f16	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPf32 - ARM_INS_VCMP - vcmp${vp}.f32	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPf32r - ARM_INS_VCMP - vcmp${vp}.f32	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPi16 - ARM_INS_VCMP - vcmp${vp}.i16	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPi16r - ARM_INS_VCMP - vcmp${vp}.i16	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPi32 - ARM_INS_VCMP - vcmp${vp}.i32	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPi32r - ARM_INS_VCMP - vcmp${vp}.i32	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPi8 - ARM_INS_VCMP - vcmp${vp}.i8	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPi8r - ARM_INS_VCMP - vcmp${vp}.i8	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPs16 - ARM_INS_VCMP - vcmp${vp}.s16	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPs16r - ARM_INS_VCMP - vcmp${vp}.s16	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPs32 - ARM_INS_VCMP - vcmp${vp}.s32	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPs32r - ARM_INS_VCMP - vcmp${vp}.s32	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPs8 - ARM_INS_VCMP - vcmp${vp}.s8	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPs8r - ARM_INS_VCMP - vcmp${vp}.s8	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPu16 - ARM_INS_VCMP - vcmp${vp}.u16	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPu16r - ARM_INS_VCMP - vcmp${vp}.u16	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPu32 - ARM_INS_VCMP - vcmp${vp}.u32	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPu32r - ARM_INS_VCMP - vcmp${vp}.u32	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPu8 - ARM_INS_VCMP - vcmp${vp}.u8	$fc, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMPu8r - ARM_INS_VCMP - vcmp${vp}.u8	$fc, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VCMULf16 - ARM_INS_VCMUL - vcmul${vp}.f16	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCMULf32 - ARM_INS_VCMUL - vcmul${vp}.f32	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VCTP16 - ARM_INS_VCTP - vctp${vp}.16	$Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VCTP32 - ARM_INS_VCTP - vctp${vp}.32	$Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VCTP64 - ARM_INS_VCTP - vctp${vp}.64	$Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VCTP8 - ARM_INS_VCTP - vctp${vp}.8	$Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf16f32bh - ARM_INS_VCVTB - vcvtb${vp}.f16.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf16f32th - ARM_INS_VCVTT - vcvtt${vp}.f16.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf16s16_fix - ARM_INS_VCVT - vcvt${vp}.f16.s16	$Qd, $Qm, $imm6 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm6 */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf16s16n - ARM_INS_VCVT - vcvt${vp}.f16.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf16u16_fix - ARM_INS_VCVT - vcvt${vp}.f16.u16	$Qd, $Qm, $imm6 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm6 */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf16u16n - ARM_INS_VCVT - vcvt${vp}.f16.u16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf32f16bh - ARM_INS_VCVTB - vcvtb${vp}.f32.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf32f16th - ARM_INS_VCVTT - vcvtt${vp}.f32.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf32s32_fix - ARM_INS_VCVT - vcvt${vp}.f32.s32	$Qd, $Qm, $imm6 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm6 */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf32s32n - ARM_INS_VCVT - vcvt${vp}.f32.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf32u32_fix - ARM_INS_VCVT - vcvt${vp}.f32.u32	$Qd, $Qm, $imm6 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm6 */
  { 0 }
}},
{{ /* ARM_MVE_VCVTf32u32n - ARM_INS_VCVT - vcvt${vp}.f32.u32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs16f16_fix - ARM_INS_VCVT - vcvt${vp}.s16.f16	$Qd, $Qm, $imm6 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm6 */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs16f16a - ARM_INS_VCVTA - vcvta${vp}.s16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs16f16m - ARM_INS_VCVTM - vcvtm${vp}.s16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs16f16n - ARM_INS_VCVTN - vcvtn${vp}.s16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs16f16p - ARM_INS_VCVTP - vcvtp${vp}.s16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs16f16z - ARM_INS_VCVT - vcvt${vp}.s16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs32f32_fix - ARM_INS_VCVT - vcvt${vp}.s32.f32	$Qd, $Qm, $imm6 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm6 */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs32f32a - ARM_INS_VCVTA - vcvta${vp}.s32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs32f32m - ARM_INS_VCVTM - vcvtm${vp}.s32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs32f32n - ARM_INS_VCVTN - vcvtn${vp}.s32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs32f32p - ARM_INS_VCVTP - vcvtp${vp}.s32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTs32f32z - ARM_INS_VCVT - vcvt${vp}.s32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu16f16_fix - ARM_INS_VCVT - vcvt${vp}.u16.f16	$Qd, $Qm, $imm6 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm6 */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu16f16a - ARM_INS_VCVTA - vcvta${vp}.u16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu16f16m - ARM_INS_VCVTM - vcvtm${vp}.u16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu16f16n - ARM_INS_VCVTN - vcvtn${vp}.u16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu16f16p - ARM_INS_VCVTP - vcvtp${vp}.u16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu16f16z - ARM_INS_VCVT - vcvt${vp}.u16.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu32f32_fix - ARM_INS_VCVT - vcvt${vp}.u32.f32	$Qd, $Qm, $imm6 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm6 */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu32f32a - ARM_INS_VCVTA - vcvta${vp}.u32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu32f32m - ARM_INS_VCVTM - vcvtm${vp}.u32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu32f32n - ARM_INS_VCVTN - vcvtn${vp}.u32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu32f32p - ARM_INS_VCVTP - vcvtp${vp}.u32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VCVTu32f32z - ARM_INS_VCVT - vcvt${vp}.u32.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VDDUPu16 - ARM_INS_VDDUP - vddup${vp}.u16	$Qd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VDDUPu32 - ARM_INS_VDDUP - vddup${vp}.u32	$Qd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VDDUPu8 - ARM_INS_VDDUP - vddup${vp}.u8	$Qd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VDUP16 - ARM_INS_VDUP - vdup${vp}.16	$Qd, $Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_MVE_VDUP32 - ARM_INS_VDUP - vdup${vp}.32	$Qd, $Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_MVE_VDUP8 - ARM_INS_VDUP - vdup${vp}.8	$Qd, $Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_MVE_VDWDUPu16 - ARM_INS_VDWDUP - vdwdup${vp}.u16	$Qd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VDWDUPu32 - ARM_INS_VDWDUP - vdwdup${vp}.u32	$Qd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VDWDUPu8 - ARM_INS_VDWDUP - vdwdup${vp}.u8	$Qd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VEOR - ARM_INS_VEOR - veor${vp}	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VFMA_qr_Sf16 - ARM_INS_VFMAS - vfmas${vp}.f16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VFMA_qr_Sf32 - ARM_INS_VFMAS - vfmas${vp}.f32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VFMA_qr_f16 - ARM_INS_VFMA - vfma${vp}.f16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VFMA_qr_f32 - ARM_INS_VFMA - vfma${vp}.f32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VFMAf16 - ARM_INS_VFMA - vfma${vp}.f16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VFMAf32 - ARM_INS_VFMA - vfma${vp}.f32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VFMSf16 - ARM_INS_VFMS - vfms${vp}.f16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VFMSf32 - ARM_INS_VFMS - vfms${vp}.f32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHADD_qr_s16 - ARM_INS_VHADD - vhadd${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHADD_qr_s32 - ARM_INS_VHADD - vhadd${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHADD_qr_s8 - ARM_INS_VHADD - vhadd${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHADD_qr_u16 - ARM_INS_VHADD - vhadd${vp}.u16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHADD_qr_u32 - ARM_INS_VHADD - vhadd${vp}.u32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHADD_qr_u8 - ARM_INS_VHADD - vhadd${vp}.u8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHADDs16 - ARM_INS_VHADD - vhadd${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHADDs32 - ARM_INS_VHADD - vhadd${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHADDs8 - ARM_INS_VHADD - vhadd${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHADDu16 - ARM_INS_VHADD - vhadd${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHADDu32 - ARM_INS_VHADD - vhadd${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHADDu8 - ARM_INS_VHADD - vhadd${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHCADDs16 - ARM_INS_VHCADD - vhcadd${vp}.s16	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VHCADDs32 - ARM_INS_VHCADD - vhcadd${vp}.s32	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VHCADDs8 - ARM_INS_VHCADD - vhcadd${vp}.s8	$Qd, $Qn, $Qm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_MVE_VHSUB_qr_s16 - ARM_INS_VHSUB - vhsub${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUB_qr_s32 - ARM_INS_VHSUB - vhsub${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUB_qr_s8 - ARM_INS_VHSUB - vhsub${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUB_qr_u16 - ARM_INS_VHSUB - vhsub${vp}.u16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUB_qr_u32 - ARM_INS_VHSUB - vhsub${vp}.u32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUB_qr_u8 - ARM_INS_VHSUB - vhsub${vp}.u8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUBs16 - ARM_INS_VHSUB - vhsub${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUBs32 - ARM_INS_VHSUB - vhsub${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUBs8 - ARM_INS_VHSUB - vhsub${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUBu16 - ARM_INS_VHSUB - vhsub${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUBu32 - ARM_INS_VHSUB - vhsub${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VHSUBu8 - ARM_INS_VHSUB - vhsub${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VIDUPu16 - ARM_INS_VIDUP - vidup${vp}.u16	$Qd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VIDUPu32 - ARM_INS_VIDUP - vidup${vp}.u32	$Qd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VIDUPu8 - ARM_INS_VIDUP - vidup${vp}.u8	$Qd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VIWDUPu16 - ARM_INS_VIWDUP - viwdup${vp}.u16	$Qd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VIWDUPu32 - ARM_INS_VIWDUP - viwdup${vp}.u32	$Qd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VIWDUPu8 - ARM_INS_VIWDUP - viwdup${vp}.u8	$Qd, $Rn, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VLD20_16 - ARM_INS_VLD20 - vld20.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD20_16_wb - ARM_INS_VLD20 - vld20.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD20_32 - ARM_INS_VLD20 - vld20.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD20_32_wb - ARM_INS_VLD20 - vld20.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD20_8 - ARM_INS_VLD20 - vld20.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD20_8_wb - ARM_INS_VLD20 - vld20.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD21_16 - ARM_INS_VLD21 - vld21.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD21_16_wb - ARM_INS_VLD21 - vld21.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD21_32 - ARM_INS_VLD21 - vld21.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD21_32_wb - ARM_INS_VLD21 - vld21.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD21_8 - ARM_INS_VLD21 - vld21.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD21_8_wb - ARM_INS_VLD21 - vld21.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD40_16 - ARM_INS_VLD40 - vld40.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD40_16_wb - ARM_INS_VLD40 - vld40.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD40_32 - ARM_INS_VLD40 - vld40.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD40_32_wb - ARM_INS_VLD40 - vld40.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD40_8 - ARM_INS_VLD40 - vld40.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD40_8_wb - ARM_INS_VLD40 - vld40.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD41_16 - ARM_INS_VLD41 - vld41.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD41_16_wb - ARM_INS_VLD41 - vld41.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD41_32 - ARM_INS_VLD41 - vld41.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD41_32_wb - ARM_INS_VLD41 - vld41.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD41_8 - ARM_INS_VLD41 - vld41.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD41_8_wb - ARM_INS_VLD41 - vld41.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD42_16 - ARM_INS_VLD42 - vld42.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD42_16_wb - ARM_INS_VLD42 - vld42.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD42_32 - ARM_INS_VLD42 - vld42.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD42_32_wb - ARM_INS_VLD42 - vld42.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD42_8 - ARM_INS_VLD42 - vld42.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD42_8_wb - ARM_INS_VLD42 - vld42.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD43_16 - ARM_INS_VLD43 - vld43.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD43_16_wb - ARM_INS_VLD43 - vld43.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD43_32 - ARM_INS_VLD43 - vld43.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD43_32_wb - ARM_INS_VLD43 - vld43.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD43_8 - ARM_INS_VLD43 - vld43.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLD43_8_wb - ARM_INS_VLD43 - vld43.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* VQd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQdSrc */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBS16 - ARM_INS_VLDRB - vldrb${vp}.s16	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBS16_post - ARM_INS_VLDRB - vldrb${vp}.s16	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBS16_pre - ARM_INS_VLDRB - vldrb${vp}.s16	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBS16_rq - ARM_INS_VLDRB - vldrb${vp}.s16	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBS32 - ARM_INS_VLDRB - vldrb${vp}.s32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBS32_post - ARM_INS_VLDRB - vldrb${vp}.s32	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBS32_pre - ARM_INS_VLDRB - vldrb${vp}.s32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBS32_rq - ARM_INS_VLDRB - vldrb${vp}.s32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU16 - ARM_INS_VLDRB - vldrb${vp}.u16	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU16_post - ARM_INS_VLDRB - vldrb${vp}.u16	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU16_pre - ARM_INS_VLDRB - vldrb${vp}.u16	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU16_rq - ARM_INS_VLDRB - vldrb${vp}.u16	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU32 - ARM_INS_VLDRB - vldrb${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU32_post - ARM_INS_VLDRB - vldrb${vp}.u32	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU32_pre - ARM_INS_VLDRB - vldrb${vp}.u32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU32_rq - ARM_INS_VLDRB - vldrb${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU8 - ARM_INS_VLDRB - vldrb${vp}.u8	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU8_post - ARM_INS_VLDRB - vldrb${vp}.u8	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU8_pre - ARM_INS_VLDRB - vldrb${vp}.u8	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRBU8_rq - ARM_INS_VLDRB - vldrb${vp}.u8	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRDU64_qi - ARM_INS_VLDRD - vldrd${vp}.u64	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRDU64_qi_pre - ARM_INS_VLDRD - vldrd${vp}.u64	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRDU64_rq - ARM_INS_VLDRD - vldrd${vp}.u64	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRDU64_rq_u - ARM_INS_VLDRD - vldrd${vp}.u64	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHS32 - ARM_INS_VLDRH - vldrh${vp}.s32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHS32_post - ARM_INS_VLDRH - vldrh${vp}.s32	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHS32_pre - ARM_INS_VLDRH - vldrh${vp}.s32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHS32_rq - ARM_INS_VLDRH - vldrh${vp}.s32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHS32_rq_u - ARM_INS_VLDRH - vldrh${vp}.s32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU16 - ARM_INS_VLDRH - vldrh${vp}.u16	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU16_post - ARM_INS_VLDRH - vldrh${vp}.u16	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU16_pre - ARM_INS_VLDRH - vldrh${vp}.u16	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU16_rq - ARM_INS_VLDRH - vldrh${vp}.u16	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU16_rq_u - ARM_INS_VLDRH - vldrh${vp}.u16	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU32 - ARM_INS_VLDRH - vldrh${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU32_post - ARM_INS_VLDRH - vldrh${vp}.u32	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU32_pre - ARM_INS_VLDRH - vldrh${vp}.u32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU32_rq - ARM_INS_VLDRH - vldrh${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRHU32_rq_u - ARM_INS_VLDRH - vldrh${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRWU32 - ARM_INS_VLDRW - vldrw${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRWU32_post - ARM_INS_VLDRW - vldrw${vp}.u32	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRWU32_pre - ARM_INS_VLDRW - vldrw${vp}.u32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRWU32_qi - ARM_INS_VLDRW - vldrw${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRWU32_qi_pre - ARM_INS_VLDRW - vldrw${vp}.u32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRWU32_rq - ARM_INS_VLDRW - vldrw${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VLDRWU32_rq_u - ARM_INS_VLDRW - vldrw${vp}.u32	$Qd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VMAXAVs16 - ARM_INS_VMAXAV - vmaxav${vp}.s16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXAVs32 - ARM_INS_VMAXAV - vmaxav${vp}.s32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXAVs8 - ARM_INS_VMAXAV - vmaxav${vp}.s8	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXAs16 - ARM_INS_VMAXA - vmaxa${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXAs32 - ARM_INS_VMAXA - vmaxa${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXAs8 - ARM_INS_VMAXA - vmaxa${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXNMAVf16 - ARM_INS_VMAXNMAV - vmaxnmav${vp}.f16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXNMAVf32 - ARM_INS_VMAXNMAV - vmaxnmav${vp}.f32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXNMAf16 - ARM_INS_VMAXNMA - vmaxnma${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXNMAf32 - ARM_INS_VMAXNMA - vmaxnma${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXNMVf16 - ARM_INS_VMAXNMV - vmaxnmv${vp}.f16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXNMVf32 - ARM_INS_VMAXNMV - vmaxnmv${vp}.f32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXNMf16 - ARM_INS_VMAXNM - vmaxnm${vp}.f16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXNMf32 - ARM_INS_VMAXNM - vmaxnm${vp}.f32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXVs16 - ARM_INS_VMAXV - vmaxv${vp}.s16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXVs32 - ARM_INS_VMAXV - vmaxv${vp}.s32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXVs8 - ARM_INS_VMAXV - vmaxv${vp}.s8	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXVu16 - ARM_INS_VMAXV - vmaxv${vp}.u16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXVu32 - ARM_INS_VMAXV - vmaxv${vp}.u32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXVu8 - ARM_INS_VMAXV - vmaxv${vp}.u8	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXs16 - ARM_INS_VMAX - vmax${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXs32 - ARM_INS_VMAX - vmax${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXs8 - ARM_INS_VMAX - vmax${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXu16 - ARM_INS_VMAX - vmax${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXu32 - ARM_INS_VMAX - vmax${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMAXu8 - ARM_INS_VMAX - vmax${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINAVs16 - ARM_INS_VMINAV - vminav${vp}.s16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINAVs32 - ARM_INS_VMINAV - vminav${vp}.s32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINAVs8 - ARM_INS_VMINAV - vminav${vp}.s8	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINAs16 - ARM_INS_VMINA - vmina${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINAs32 - ARM_INS_VMINA - vmina${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINAs8 - ARM_INS_VMINA - vmina${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINNMAVf16 - ARM_INS_VMINNMAV - vminnmav${vp}.f16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINNMAVf32 - ARM_INS_VMINNMAV - vminnmav${vp}.f32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINNMAf16 - ARM_INS_VMINNMA - vminnma${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINNMAf32 - ARM_INS_VMINNMA - vminnma${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINNMVf16 - ARM_INS_VMINNMV - vminnmv${vp}.f16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINNMVf32 - ARM_INS_VMINNMV - vminnmv${vp}.f32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINNMf16 - ARM_INS_VMINNM - vminnm${vp}.f16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINNMf32 - ARM_INS_VMINNM - vminnm${vp}.f32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINVs16 - ARM_INS_VMINV - vminv${vp}.s16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINVs32 - ARM_INS_VMINV - vminv${vp}.s32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINVs8 - ARM_INS_VMINV - vminv${vp}.s8	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINVu16 - ARM_INS_VMINV - vminv${vp}.u16	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINVu32 - ARM_INS_VMINV - vminv${vp}.u32	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINVu8 - ARM_INS_VMINV - vminv${vp}.u8	$RdaSrc, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINs16 - ARM_INS_VMIN - vmin${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINs32 - ARM_INS_VMIN - vmin${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINs8 - ARM_INS_VMIN - vmin${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINu16 - ARM_INS_VMIN - vmin${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINu32 - ARM_INS_VMIN - vmin${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMINu8 - ARM_INS_VMIN - vmin${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVas16 - ARM_INS_VMLADAVA - vmladava${vp}.s16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVas32 - ARM_INS_VMLADAVA - vmladava${vp}.s32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVas8 - ARM_INS_VMLADAVA - vmladava${vp}.s8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVau16 - ARM_INS_VMLADAVA - vmladava${vp}.u16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVau32 - ARM_INS_VMLADAVA - vmladava${vp}.u32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVau8 - ARM_INS_VMLADAVA - vmladava${vp}.u8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVaxs16 - ARM_INS_VMLADAVAX - vmladavax${vp}.s16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVaxs32 - ARM_INS_VMLADAVAX - vmladavax${vp}.s32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVaxs8 - ARM_INS_VMLADAVAX - vmladavax${vp}.s8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVs16 - ARM_INS_VMLADAV - vmladav${vp}.s16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVs32 - ARM_INS_VMLADAV - vmladav${vp}.s32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVs8 - ARM_INS_VMLADAV - vmladav${vp}.s8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVu16 - ARM_INS_VMLADAV - vmladav${vp}.u16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVu32 - ARM_INS_VMLADAV - vmladav${vp}.u32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVu8 - ARM_INS_VMLADAV - vmladav${vp}.u8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVxs16 - ARM_INS_VMLADAVX - vmladavx${vp}.s16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVxs32 - ARM_INS_VMLADAVX - vmladavx${vp}.s32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLADAVxs8 - ARM_INS_VMLADAVX - vmladavx${vp}.s8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVas16 - ARM_INS_VMLALDAVA - vmlaldava${vp}.s16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVas32 - ARM_INS_VMLALDAVA - vmlaldava${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVau16 - ARM_INS_VMLALDAVA - vmlaldava${vp}.u16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVau32 - ARM_INS_VMLALDAVA - vmlaldava${vp}.u32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVaxs16 - ARM_INS_VMLALDAVAX - vmlaldavax${vp}.s16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVaxs32 - ARM_INS_VMLALDAVAX - vmlaldavax${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVs16 - ARM_INS_VMLALDAV - vmlaldav${vp}.s16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVs32 - ARM_INS_VMLALDAV - vmlaldav${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVu16 - ARM_INS_VMLALDAV - vmlaldav${vp}.u16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVu32 - ARM_INS_VMLALDAV - vmlaldav${vp}.u32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVxs16 - ARM_INS_VMLALDAVX - vmlaldavx${vp}.s16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLALDAVxs32 - ARM_INS_VMLALDAVX - vmlaldavx${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLAS_qr_i16 - ARM_INS_VMLAS - vmlas${vp}.i16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMLAS_qr_i32 - ARM_INS_VMLAS - vmlas${vp}.i32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMLAS_qr_i8 - ARM_INS_VMLAS - vmlas${vp}.i8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMLA_qr_i16 - ARM_INS_VMLA - vmla${vp}.i16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMLA_qr_i32 - ARM_INS_VMLA - vmla${vp}.i32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMLA_qr_i8 - ARM_INS_VMLA - vmla${vp}.i8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVas16 - ARM_INS_VMLSDAVA - vmlsdava${vp}.s16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVas32 - ARM_INS_VMLSDAVA - vmlsdava${vp}.s32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVas8 - ARM_INS_VMLSDAVA - vmlsdava${vp}.s8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVaxs16 - ARM_INS_VMLSDAVAX - vmlsdavax${vp}.s16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVaxs32 - ARM_INS_VMLSDAVAX - vmlsdavax${vp}.s32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVaxs8 - ARM_INS_VMLSDAVAX - vmlsdavax${vp}.s8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVs16 - ARM_INS_VMLSDAV - vmlsdav${vp}.s16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVs32 - ARM_INS_VMLSDAV - vmlsdav${vp}.s32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVs8 - ARM_INS_VMLSDAV - vmlsdav${vp}.s8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVxs16 - ARM_INS_VMLSDAVX - vmlsdavx${vp}.s16	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVxs32 - ARM_INS_VMLSDAVX - vmlsdavx${vp}.s32	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSDAVxs8 - ARM_INS_VMLSDAVX - vmlsdavx${vp}.s8	$RdaDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSLDAVas16 - ARM_INS_VMLSLDAVA - vmlsldava${vp}.s16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSLDAVas32 - ARM_INS_VMLSLDAVA - vmlsldava${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSLDAVaxs16 - ARM_INS_VMLSLDAVAX - vmlsldavax${vp}.s16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSLDAVaxs32 - ARM_INS_VMLSLDAVAX - vmlsldavax${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSLDAVs16 - ARM_INS_VMLSLDAV - vmlsldav${vp}.s16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSLDAVs32 - ARM_INS_VMLSLDAV - vmlsldav${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSLDAVxs16 - ARM_INS_VMLSLDAVX - vmlsldavx${vp}.s16	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMLSLDAVxs32 - ARM_INS_VMLSLDAVX - vmlsldavx${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVLs16bh - ARM_INS_VMOVLB - vmovlb${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVLs16th - ARM_INS_VMOVLT - vmovlt${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVLs8bh - ARM_INS_VMOVLB - vmovlb${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVLs8th - ARM_INS_VMOVLT - vmovlt${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVLu16bh - ARM_INS_VMOVLB - vmovlb${vp}.u16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVLu16th - ARM_INS_VMOVLT - vmovlt${vp}.u16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVLu8bh - ARM_INS_VMOVLB - vmovlb${vp}.u8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVLu8th - ARM_INS_VMOVLT - vmovlt${vp}.u8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVNi16bh - ARM_INS_VMOVNB - vmovnb${vp}.i16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVNi16th - ARM_INS_VMOVNT - vmovnt${vp}.i16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVNi32bh - ARM_INS_VMOVNB - vmovnb${vp}.i32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVNi32th - ARM_INS_VMOVNT - vmovnt${vp}.i32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_from_lane_32 - ARM_INS_VMOV - vmov${p}.32	$Rt, $Qd$Idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* Idx */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_from_lane_s16 - ARM_INS_VMOV - vmov${p}.s16	$Rt, $Qd$Idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* Idx */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_from_lane_s8 - ARM_INS_VMOV - vmov${p}.s8	$Rt, $Qd$Idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* Idx */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_from_lane_u16 - ARM_INS_VMOV - vmov${p}.u16	$Rt, $Qd$Idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* Idx */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_from_lane_u8 - ARM_INS_VMOV - vmov${p}.u8	$Rt, $Qd$Idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* Idx */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_q_rr - ARM_INS_VMOV - vmov${p}	$Qd$idx, $QdSrc$idx2, $Rt, $Rt2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* idx */
  { CS_OP_IMM, CS_AC_READ }, /* idx2 */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_rr_q - ARM_INS_VMOV - vmov${p}	$Rt, $Rt2, $Qd$idx, $Qd$idx2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* idx */
  { CS_OP_IMM, CS_AC_READ }, /* idx2 */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_to_lane_16 - ARM_INS_VMOV - vmov${p}.16	$Qd$Idx, $Rt */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* Idx */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_to_lane_32 - ARM_INS_VMOV - vmov${p}.32	$Qd$Idx, $Rt */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* Idx */
  { 0 }
}},
{{ /* ARM_MVE_VMOV_to_lane_8 - ARM_INS_VMOV - vmov${p}.8	$Qd$Idx, $Rt */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* Idx */
  { 0 }
}},
{{ /* ARM_MVE_VMOVimmf32 - ARM_INS_VMOV - vmov${vp}.f32	$Qd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVimmi16 - ARM_INS_VMOV - vmov${vp}.i16	$Qd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVimmi32 - ARM_INS_VMOV - vmov${vp}.i32	$Qd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVimmi64 - ARM_INS_VMOV - vmov${vp}.i64	$Qd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VMOVimmi8 - ARM_INS_VMOV - vmov${vp}.i8	$Qd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VMULHs16 - ARM_INS_VMULH - vmulh${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULHs32 - ARM_INS_VMULH - vmulh${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULHs8 - ARM_INS_VMULH - vmulh${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULHu16 - ARM_INS_VMULH - vmulh${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULHu32 - ARM_INS_VMULH - vmulh${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULHu8 - ARM_INS_VMULH - vmulh${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLBp16 - ARM_INS_VMULLB - vmullb${vp}.p16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLBp8 - ARM_INS_VMULLB - vmullb${vp}.p8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLBs16 - ARM_INS_VMULLB - vmullb${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLBs32 - ARM_INS_VMULLB - vmullb${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLBs8 - ARM_INS_VMULLB - vmullb${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLBu16 - ARM_INS_VMULLB - vmullb${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLBu32 - ARM_INS_VMULLB - vmullb${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLBu8 - ARM_INS_VMULLB - vmullb${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLTp16 - ARM_INS_VMULLT - vmullt${vp}.p16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLTp8 - ARM_INS_VMULLT - vmullt${vp}.p8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLTs16 - ARM_INS_VMULLT - vmullt${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLTs32 - ARM_INS_VMULLT - vmullt${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLTs8 - ARM_INS_VMULLT - vmullt${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLTu16 - ARM_INS_VMULLT - vmullt${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLTu32 - ARM_INS_VMULLT - vmullt${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULLTu8 - ARM_INS_VMULLT - vmullt${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMUL_qr_f16 - ARM_INS_VMUL - vmul${vp}.f16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMUL_qr_f32 - ARM_INS_VMUL - vmul${vp}.f32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMUL_qr_i16 - ARM_INS_VMUL - vmul${vp}.i16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMUL_qr_i32 - ARM_INS_VMUL - vmul${vp}.i32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMUL_qr_i8 - ARM_INS_VMUL - vmul${vp}.i8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VMULf16 - ARM_INS_VMUL - vmul${vp}.f16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULf32 - ARM_INS_VMUL - vmul${vp}.f32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULi16 - ARM_INS_VMUL - vmul${vp}.i16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULi32 - ARM_INS_VMUL - vmul${vp}.i32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMULi8 - ARM_INS_VMUL - vmul${vp}.i8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMVN - ARM_INS_VMVN - vmvn${vp}	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VMVNimmi16 - ARM_INS_VMVN - vmvn${vp}.i16	$Qd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VMVNimmi32 - ARM_INS_VMVN - vmvn${vp}.i32	$Qd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VNEGf16 - ARM_INS_VNEG - vneg${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VNEGf32 - ARM_INS_VNEG - vneg${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VNEGs16 - ARM_INS_VNEG - vneg${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VNEGs32 - ARM_INS_VNEG - vneg${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VNEGs8 - ARM_INS_VNEG - vneg${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VORN - ARM_INS_VORN - vorn${vp}	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VORR - ARM_INS_VMOV - vorr${vp}	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VORR - ARM_INS_VORR - vorr${vp}	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VORRimmi16 - ARM_INS_VORN - vorr${vp}.i16	$Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VORRimmi16 - ARM_INS_VORR - vorr${vp}.i16	$Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VORRimmi32 - ARM_INS_VORN - vorr${vp}.i32	$Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VORRimmi32 - ARM_INS_VORR - vorr${vp}.i32	$Qd, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VPNOT - ARM_INS_VPNOT - vpnot${vp}	 */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_READ }, /* P0_in */
  { 0 }
}},
{{ /* ARM_MVE_VPSEL - ARM_INS_VPSEL - vpsel${vp}	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VPST - ARM_INS_VPST - vpst${Mk}	 */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { 0 }
}},
{{ /* ARM_MVE_VPTv16i8 - ARM_INS_VPT - vpt${Mk}.i8	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv16i8r - ARM_INS_VPT - vpt${Mk}.i8	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv16s8 - ARM_INS_VPT - vpt${Mk}.s8	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv16s8r - ARM_INS_VPT - vpt${Mk}.s8	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv16u8 - ARM_INS_VPT - vpt${Mk}.u8	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv16u8r - ARM_INS_VPT - vpt${Mk}.u8	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv4f32 - ARM_INS_VPT - vpt${Mk}.f32	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv4f32r - ARM_INS_VPT - vpt${Mk}.f32	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv4i32 - ARM_INS_VPT - vpt${Mk}.i32	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv4i32r - ARM_INS_VPT - vpt${Mk}.i32	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv4s32 - ARM_INS_VPT - vpt${Mk}.s32	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv4s32r - ARM_INS_VPT - vpt${Mk}.s32	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv4u32 - ARM_INS_VPT - vpt${Mk}.u32	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv4u32r - ARM_INS_VPT - vpt${Mk}.u32	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv8f16 - ARM_INS_VPT - vpt${Mk}.f16	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv8f16r - ARM_INS_VPT - vpt${Mk}.f16	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv8i16 - ARM_INS_VPT - vpt${Mk}.i16	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv8i16r - ARM_INS_VPT - vpt${Mk}.i16	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv8s16 - ARM_INS_VPT - vpt${Mk}.s16	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv8s16r - ARM_INS_VPT - vpt${Mk}.s16	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv8u16 - ARM_INS_VPT - vpt${Mk}.u16	$fc, $Qn, $Qm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VPTv8u16r - ARM_INS_VPT - vpt${Mk}.u16	$fc, $Qn, $Rm */
  { CS_OP_IMM, CS_AC_READ }, /* Mk */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fc */
  { 0 }
}},
{{ /* ARM_MVE_VQABSs16 - ARM_INS_VQABS - vqabs${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQABSs32 - ARM_INS_VQABS - vqabs${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQABSs8 - ARM_INS_VQABS - vqabs${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQADD_qr_s16 - ARM_INS_VQADD - vqadd${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQADD_qr_s32 - ARM_INS_VQADD - vqadd${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQADD_qr_s8 - ARM_INS_VQADD - vqadd${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQADD_qr_u16 - ARM_INS_VQADD - vqadd${vp}.u16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQADD_qr_u32 - ARM_INS_VQADD - vqadd${vp}.u32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQADD_qr_u8 - ARM_INS_VQADD - vqadd${vp}.u8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQADDs16 - ARM_INS_VQADD - vqadd${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQADDs32 - ARM_INS_VQADD - vqadd${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQADDs8 - ARM_INS_VQADD - vqadd${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQADDu16 - ARM_INS_VQADD - vqadd${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQADDu32 - ARM_INS_VQADD - vqadd${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQADDu8 - ARM_INS_VQADD - vqadd${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLADHXs16 - ARM_INS_VQDMLADHX - vqdmladhx${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLADHXs32 - ARM_INS_VQDMLADHX - vqdmladhx${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLADHXs8 - ARM_INS_VQDMLADHX - vqdmladhx${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLADHs16 - ARM_INS_VQDMLADH - vqdmladh${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLADHs32 - ARM_INS_VQDMLADH - vqdmladh${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLADHs8 - ARM_INS_VQDMLADH - vqdmladh${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLAH_qrs16 - ARM_INS_VQDMLAH - vqdmlah${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLAH_qrs32 - ARM_INS_VQDMLAH - vqdmlah${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLAH_qrs8 - ARM_INS_VQDMLAH - vqdmlah${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLASH_qrs16 - ARM_INS_VQDMLASH - vqdmlash${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLASH_qrs32 - ARM_INS_VQDMLASH - vqdmlash${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLASH_qrs8 - ARM_INS_VQDMLASH - vqdmlash${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLSDHXs16 - ARM_INS_VQDMLSDHX - vqdmlsdhx${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLSDHXs32 - ARM_INS_VQDMLSDHX - vqdmlsdhx${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLSDHXs8 - ARM_INS_VQDMLSDHX - vqdmlsdhx${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLSDHs16 - ARM_INS_VQDMLSDH - vqdmlsdh${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLSDHs32 - ARM_INS_VQDMLSDH - vqdmlsdh${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMLSDHs8 - ARM_INS_VQDMLSDH - vqdmlsdh${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULH_qr_s16 - ARM_INS_VQDMULH - vqdmulh${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULH_qr_s32 - ARM_INS_VQDMULH - vqdmulh${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULH_qr_s8 - ARM_INS_VQDMULH - vqdmulh${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULHi16 - ARM_INS_VQDMULH - vqdmulh${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULHi32 - ARM_INS_VQDMULH - vqdmulh${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULHi8 - ARM_INS_VQDMULH - vqdmulh${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULL_qr_s16bh - ARM_INS_VQDMULLB - vqdmullb${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULL_qr_s16th - ARM_INS_VQDMULLT - vqdmullt${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULL_qr_s32bh - ARM_INS_VQDMULLB - vqdmullb${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULL_qr_s32th - ARM_INS_VQDMULLT - vqdmullt${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULLs16bh - ARM_INS_VQDMULLB - vqdmullb${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULLs16th - ARM_INS_VQDMULLT - vqdmullt${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULLs32bh - ARM_INS_VQDMULLB - vqdmullb${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQDMULLs32th - ARM_INS_VQDMULLT - vqdmullt${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVNs16bh - ARM_INS_VQMOVNB - vqmovnb${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVNs16th - ARM_INS_VQMOVNT - vqmovnt${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVNs32bh - ARM_INS_VQMOVNB - vqmovnb${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVNs32th - ARM_INS_VQMOVNT - vqmovnt${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVNu16bh - ARM_INS_VQMOVNB - vqmovnb${vp}.u16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVNu16th - ARM_INS_VQMOVNT - vqmovnt${vp}.u16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVNu32bh - ARM_INS_VQMOVNB - vqmovnb${vp}.u32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVNu32th - ARM_INS_VQMOVNT - vqmovnt${vp}.u32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVUNs16bh - ARM_INS_VQMOVUNB - vqmovunb${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVUNs16th - ARM_INS_VQMOVUNT - vqmovunt${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVUNs32bh - ARM_INS_VQMOVUNB - vqmovunb${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQMOVUNs32th - ARM_INS_VQMOVUNT - vqmovunt${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQNEGs16 - ARM_INS_VQNEG - vqneg${vp}.s16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQNEGs32 - ARM_INS_VQNEG - vqneg${vp}.s32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQNEGs8 - ARM_INS_VQNEG - vqneg${vp}.s8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLADHXs16 - ARM_INS_VQRDMLADHX - vqrdmladhx${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLADHXs32 - ARM_INS_VQRDMLADHX - vqrdmladhx${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLADHXs8 - ARM_INS_VQRDMLADHX - vqrdmladhx${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLADHs16 - ARM_INS_VQRDMLADH - vqrdmladh${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLADHs32 - ARM_INS_VQRDMLADH - vqrdmladh${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLADHs8 - ARM_INS_VQRDMLADH - vqrdmladh${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLAH_qrs16 - ARM_INS_VQRDMLAH - vqrdmlah${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLAH_qrs32 - ARM_INS_VQRDMLAH - vqrdmlah${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLAH_qrs8 - ARM_INS_VQRDMLAH - vqrdmlah${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLASH_qrs16 - ARM_INS_VQRDMLASH - vqrdmlash${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLASH_qrs32 - ARM_INS_VQRDMLASH - vqrdmlash${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLASH_qrs8 - ARM_INS_VQRDMLASH - vqrdmlash${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLSDHXs16 - ARM_INS_VQRDMLSDHX - vqrdmlsdhx${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLSDHXs32 - ARM_INS_VQRDMLSDHX - vqrdmlsdhx${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLSDHXs8 - ARM_INS_VQRDMLSDHX - vqrdmlsdhx${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLSDHs16 - ARM_INS_VQRDMLSDH - vqrdmlsdh${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLSDHs32 - ARM_INS_VQRDMLSDH - vqrdmlsdh${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMLSDHs8 - ARM_INS_VQRDMLSDH - vqrdmlsdh${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMULH_qr_s16 - ARM_INS_VQRDMULH - vqrdmulh${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMULH_qr_s32 - ARM_INS_VQRDMULH - vqrdmulh${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMULH_qr_s8 - ARM_INS_VQRDMULH - vqrdmulh${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMULHi16 - ARM_INS_VQRDMULH - vqrdmulh${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMULHi32 - ARM_INS_VQRDMULH - vqrdmulh${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRDMULHi8 - ARM_INS_VQRDMULH - vqrdmulh${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_by_vecs16 - ARM_INS_VQRSHL - vqrshl${vp}.s16	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_by_vecs32 - ARM_INS_VQRSHL - vqrshl${vp}.s32	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_by_vecs8 - ARM_INS_VQRSHL - vqrshl${vp}.s8	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_by_vecu16 - ARM_INS_VQRSHL - vqrshl${vp}.u16	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_by_vecu32 - ARM_INS_VQRSHL - vqrshl${vp}.u32	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_by_vecu8 - ARM_INS_VQRSHL - vqrshl${vp}.u8	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_qrs16 - ARM_INS_VQRSHL - vqrshl${vp}.s16	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_qrs32 - ARM_INS_VQRSHL - vqrshl${vp}.s32	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_qrs8 - ARM_INS_VQRSHL - vqrshl${vp}.s8	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_qru16 - ARM_INS_VQRSHL - vqrshl${vp}.u16	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_qru32 - ARM_INS_VQRSHL - vqrshl${vp}.u32	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHL_qru8 - ARM_INS_VQRSHL - vqrshl${vp}.u8	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRNbhs16 - ARM_INS_VQRSHRNB - vqrshrnb${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRNbhs32 - ARM_INS_VQRSHRNB - vqrshrnb${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRNbhu16 - ARM_INS_VQRSHRNB - vqrshrnb${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRNbhu32 - ARM_INS_VQRSHRNB - vqrshrnb${vp}.u32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRNths16 - ARM_INS_VQRSHRNT - vqrshrnt${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRNths32 - ARM_INS_VQRSHRNT - vqrshrnt${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRNthu16 - ARM_INS_VQRSHRNT - vqrshrnt${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRNthu32 - ARM_INS_VQRSHRNT - vqrshrnt${vp}.u32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRUNs16bh - ARM_INS_VQRSHRUNB - vqrshrunb${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRUNs16th - ARM_INS_VQRSHRUNT - vqrshrunt${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRUNs32bh - ARM_INS_VQRSHRUNB - vqrshrunb${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQRSHRUNs32th - ARM_INS_VQRSHRUNT - vqrshrunt${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLU_imms16 - ARM_INS_VQSHLU - vqshlu${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLU_imms32 - ARM_INS_VQSHLU - vqshlu${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLU_imms8 - ARM_INS_VQSHLU - vqshlu${vp}.s8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_by_vecs16 - ARM_INS_VQSHL - vqshl${vp}.s16	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_by_vecs32 - ARM_INS_VQSHL - vqshl${vp}.s32	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_by_vecs8 - ARM_INS_VQSHL - vqshl${vp}.s8	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_by_vecu16 - ARM_INS_VQSHL - vqshl${vp}.u16	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_by_vecu32 - ARM_INS_VQSHL - vqshl${vp}.u32	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_by_vecu8 - ARM_INS_VQSHL - vqshl${vp}.u8	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_qrs16 - ARM_INS_VQSHL - vqshl${vp}.s16	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_qrs32 - ARM_INS_VQSHL - vqshl${vp}.s32	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_qrs8 - ARM_INS_VQSHL - vqshl${vp}.s8	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_qru16 - ARM_INS_VQSHL - vqshl${vp}.u16	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_qru32 - ARM_INS_VQSHL - vqshl${vp}.u32	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHL_qru8 - ARM_INS_VQSHL - vqshl${vp}.u8	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLimms16 - ARM_INS_VQSHL - vqshl${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLimms32 - ARM_INS_VQSHL - vqshl${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLimms8 - ARM_INS_VQSHL - vqshl${vp}.s8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLimmu16 - ARM_INS_VQSHL - vqshl${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLimmu32 - ARM_INS_VQSHL - vqshl${vp}.u32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHLimmu8 - ARM_INS_VQSHL - vqshl${vp}.u8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRNbhs16 - ARM_INS_VQSHRNB - vqshrnb${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRNbhs32 - ARM_INS_VQSHRNB - vqshrnb${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRNbhu16 - ARM_INS_VQSHRNB - vqshrnb${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRNbhu32 - ARM_INS_VQSHRNB - vqshrnb${vp}.u32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRNths16 - ARM_INS_VQSHRNT - vqshrnt${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRNths32 - ARM_INS_VQSHRNT - vqshrnt${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRNthu16 - ARM_INS_VQSHRNT - vqshrnt${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRNthu32 - ARM_INS_VQSHRNT - vqshrnt${vp}.u32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRUNs16bh - ARM_INS_VQSHRUNB - vqshrunb${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRUNs16th - ARM_INS_VQSHRUNT - vqshrunt${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRUNs32bh - ARM_INS_VQSHRUNB - vqshrunb${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSHRUNs32th - ARM_INS_VQSHRUNT - vqshrunt${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUB_qr_s16 - ARM_INS_VQSUB - vqsub${vp}.s16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUB_qr_s32 - ARM_INS_VQSUB - vqsub${vp}.s32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUB_qr_s8 - ARM_INS_VQSUB - vqsub${vp}.s8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUB_qr_u16 - ARM_INS_VQSUB - vqsub${vp}.u16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUB_qr_u32 - ARM_INS_VQSUB - vqsub${vp}.u32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUB_qr_u8 - ARM_INS_VQSUB - vqsub${vp}.u8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUBs16 - ARM_INS_VQSUB - vqsub${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUBs32 - ARM_INS_VQSUB - vqsub${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUBs8 - ARM_INS_VQSUB - vqsub${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUBu16 - ARM_INS_VQSUB - vqsub${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUBu32 - ARM_INS_VQSUB - vqsub${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VQSUBu8 - ARM_INS_VQSUB - vqsub${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VREV16_8 - ARM_INS_VREV16 - vrev16${vp}.8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VREV32_16 - ARM_INS_VREV32 - vrev32${vp}.16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VREV32_8 - ARM_INS_VREV32 - vrev32${vp}.8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VREV64_16 - ARM_INS_VREV64 - vrev64${vp}.16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VREV64_32 - ARM_INS_VREV64 - vrev64${vp}.32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VREV64_8 - ARM_INS_VREV64 - vrev64${vp}.8	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRHADDs16 - ARM_INS_VRHADD - vrhadd${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRHADDs32 - ARM_INS_VRHADD - vrhadd${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRHADDs8 - ARM_INS_VRHADD - vrhadd${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRHADDu16 - ARM_INS_VRHADD - vrhadd${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRHADDu32 - ARM_INS_VRHADD - vrhadd${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRHADDu8 - ARM_INS_VRHADD - vrhadd${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf16A - ARM_INS_VRINTA - vrinta${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf16M - ARM_INS_VRINTM - vrintm${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf16N - ARM_INS_VRINTN - vrintn${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf16P - ARM_INS_VRINTP - vrintp${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf16X - ARM_INS_VRINTX - vrintx${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf16Z - ARM_INS_VRINTZ - vrintz${vp}.f16	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf32A - ARM_INS_VRINTA - vrinta${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf32M - ARM_INS_VRINTM - vrintm${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf32N - ARM_INS_VRINTN - vrintn${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf32P - ARM_INS_VRINTP - vrintp${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf32X - ARM_INS_VRINTX - vrintx${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRINTf32Z - ARM_INS_VRINTZ - vrintz${vp}.f32	$Qd, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLALDAVHas32 - ARM_INS_VRMLALDAVHA - vrmlaldavha${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLALDAVHau32 - ARM_INS_VRMLALDAVHA - vrmlaldavha${vp}.u32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLALDAVHaxs32 - ARM_INS_VRMLALDAVHAX - vrmlaldavhax${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLALDAVHs32 - ARM_INS_VRMLALDAVH - vrmlaldavh${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLALDAVHu32 - ARM_INS_VRMLALDAVH - vrmlaldavh${vp}.u32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLALDAVHxs32 - ARM_INS_VRMLALDAVHX - vrmlaldavhx${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLSLDAVHas32 - ARM_INS_VRMLSLDAVHA - vrmlsldavha${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLSLDAVHaxs32 - ARM_INS_VRMLSLDAVHAX - vrmlsldavhax${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* RdaLoSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdaHiSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLSLDAVHs32 - ARM_INS_VRMLSLDAVH - vrmlsldavh${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMLSLDAVHxs32 - ARM_INS_VRMLSLDAVHX - vrmlsldavhx${vp}.s32	$RdaLoDest, $RdaHiDest, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaLoDest */
  { CS_OP_REG, CS_AC_WRITE }, /* RdaHiDest */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMULHs16 - ARM_INS_VRMULH - vrmulh${vp}.s16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMULHs32 - ARM_INS_VRMULH - vrmulh${vp}.s32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMULHs8 - ARM_INS_VRMULH - vrmulh${vp}.s8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMULHu16 - ARM_INS_VRMULH - vrmulh${vp}.u16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMULHu32 - ARM_INS_VRMULH - vrmulh${vp}.u32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRMULHu8 - ARM_INS_VRMULH - vrmulh${vp}.u8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_by_vecs16 - ARM_INS_VRSHL - vrshl${vp}.s16	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_by_vecs32 - ARM_INS_VRSHL - vrshl${vp}.s32	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_by_vecs8 - ARM_INS_VRSHL - vrshl${vp}.s8	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_by_vecu16 - ARM_INS_VRSHL - vrshl${vp}.u16	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_by_vecu32 - ARM_INS_VRSHL - vrshl${vp}.u32	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_by_vecu8 - ARM_INS_VRSHL - vrshl${vp}.u8	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_qrs16 - ARM_INS_VRSHL - vrshl${vp}.s16	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_qrs32 - ARM_INS_VRSHL - vrshl${vp}.s32	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_qrs8 - ARM_INS_VRSHL - vrshl${vp}.s8	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_qru16 - ARM_INS_VRSHL - vrshl${vp}.u16	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_qru32 - ARM_INS_VRSHL - vrshl${vp}.u32	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHL_qru8 - ARM_INS_VRSHL - vrshl${vp}.u8	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHRNi16bh - ARM_INS_VRSHRNB - vrshrnb${vp}.i16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHRNi16th - ARM_INS_VRSHRNT - vrshrnt${vp}.i16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHRNi32bh - ARM_INS_VRSHRNB - vrshrnb${vp}.i32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHRNi32th - ARM_INS_VRSHRNT - vrshrnt${vp}.i32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHR_imms16 - ARM_INS_VRSHR - vrshr${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHR_imms32 - ARM_INS_VRSHR - vrshr${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHR_imms8 - ARM_INS_VRSHR - vrshr${vp}.s8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHR_immu16 - ARM_INS_VRSHR - vrshr${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHR_immu32 - ARM_INS_VRSHR - vrshr${vp}.u32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VRSHR_immu8 - ARM_INS_VRSHR - vrshr${vp}.u8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSBC - ARM_INS_VSBC - vsbc${vp}.i32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_WRITE }, /* carryout */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* carryin */
  { 0 }
}},
{{ /* ARM_MVE_VSBCI - ARM_INS_VSBCI - vsbci${vp}.i32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_WRITE }, /* carryout */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLC - ARM_INS_VSHLC - vshlc${vp}	$QdSrc, $RdmSrc, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdmDest */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* RdmSrc */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_imms16bh - ARM_INS_VSHLLB - vshllb${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_imms16th - ARM_INS_VSHLLT - vshllt${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_imms8bh - ARM_INS_VSHLLB - vshllb${vp}.s8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_imms8th - ARM_INS_VSHLLT - vshllt${vp}.s8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_immu16bh - ARM_INS_VSHLLB - vshllb${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_immu16th - ARM_INS_VSHLLT - vshllt${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_immu8bh - ARM_INS_VSHLLB - vshllb${vp}.u8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_immu8th - ARM_INS_VSHLLT - vshllt${vp}.u8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_lws16bh - ARM_INS_VSHLLB - vshllb${vp}.s16	$Qd, $Qm, #16 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_lws16th - ARM_INS_VSHLLT - vshllt${vp}.s16	$Qd, $Qm, #16 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_lws8bh - ARM_INS_VSHLLB - vshllb${vp}.s8	$Qd, $Qm, #8 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_lws8th - ARM_INS_VSHLLT - vshllt${vp}.s8	$Qd, $Qm, #8 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_lwu16bh - ARM_INS_VSHLLB - vshllb${vp}.u16	$Qd, $Qm, #16 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_lwu16th - ARM_INS_VSHLLT - vshllt${vp}.u16	$Qd, $Qm, #16 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_lwu8bh - ARM_INS_VSHLLB - vshllb${vp}.u8	$Qd, $Qm, #8 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHLL_lwu8th - ARM_INS_VSHLLT - vshllt${vp}.u8	$Qd, $Qm, #8 */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_by_vecs16 - ARM_INS_VSHL - vshl${vp}.s16	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_by_vecs32 - ARM_INS_VSHL - vshl${vp}.s32	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_by_vecs8 - ARM_INS_VSHL - vshl${vp}.s8	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_by_vecu16 - ARM_INS_VSHL - vshl${vp}.u16	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_by_vecu32 - ARM_INS_VSHL - vshl${vp}.u32	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_by_vecu8 - ARM_INS_VSHL - vshl${vp}.u8	$Qd, $Qm, $Qn */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_immi16 - ARM_INS_VSHL - vshl${vp}.i16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_immi32 - ARM_INS_VSHL - vshl${vp}.i32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_immi8 - ARM_INS_VSHL - vshl${vp}.i8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_qrs16 - ARM_INS_VSHL - vshl${vp}.s16	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_qrs32 - ARM_INS_VSHL - vshl${vp}.s32	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_qrs8 - ARM_INS_VSHL - vshl${vp}.s8	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_qru16 - ARM_INS_VSHL - vshl${vp}.u16	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_qru32 - ARM_INS_VSHL - vshl${vp}.u32	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSHL_qru8 - ARM_INS_VSHL - vshl${vp}.u8	$Qd, $Rm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSHRNi16bh - ARM_INS_VSHRNB - vshrnb${vp}.i16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHRNi16th - ARM_INS_VSHRNT - vshrnt${vp}.i16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHRNi32bh - ARM_INS_VSHRNB - vshrnb${vp}.i32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHRNi32th - ARM_INS_VSHRNT - vshrnt${vp}.i32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* QdSrc */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHR_imms16 - ARM_INS_VSHR - vshr${vp}.s16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHR_imms32 - ARM_INS_VSHR - vshr${vp}.s32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHR_imms8 - ARM_INS_VSHR - vshr${vp}.s8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHR_immu16 - ARM_INS_VSHR - vshr${vp}.u16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHR_immu32 - ARM_INS_VSHR - vshr${vp}.u32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSHR_immu8 - ARM_INS_VSHR - vshr${vp}.u8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSLIimm16 - ARM_INS_VSLI - vsli${vp}.16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSLIimm32 - ARM_INS_VSLI - vsli${vp}.32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSLIimm8 - ARM_INS_VSLI - vsli${vp}.8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSRIimm16 - ARM_INS_VSRI - vsri${vp}.16	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSRIimm32 - ARM_INS_VSRI - vsri${vp}.32	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VSRIimm8 - ARM_INS_VSRI - vsri${vp}.8	$Qd, $Qm, $imm */
  { CS_OP_REG, CS_AC_READ | CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVE_VST20_16 - ARM_INS_VST20 - vst20.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST20_16_wb - ARM_INS_VST20 - vst20.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST20_32 - ARM_INS_VST20 - vst20.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST20_32_wb - ARM_INS_VST20 - vst20.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST20_8 - ARM_INS_VST20 - vst20.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST20_8_wb - ARM_INS_VST20 - vst20.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST21_16 - ARM_INS_VST21 - vst21.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST21_16_wb - ARM_INS_VST21 - vst21.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST21_32 - ARM_INS_VST21 - vst21.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST21_32_wb - ARM_INS_VST21 - vst21.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST21_8 - ARM_INS_VST21 - vst21.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST21_8_wb - ARM_INS_VST21 - vst21.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST40_16 - ARM_INS_VST40 - vst40.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST40_16_wb - ARM_INS_VST40 - vst40.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST40_32 - ARM_INS_VST40 - vst40.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST40_32_wb - ARM_INS_VST40 - vst40.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST40_8 - ARM_INS_VST40 - vst40.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST40_8_wb - ARM_INS_VST40 - vst40.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST41_16 - ARM_INS_VST41 - vst41.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST41_16_wb - ARM_INS_VST41 - vst41.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST41_32 - ARM_INS_VST41 - vst41.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST41_32_wb - ARM_INS_VST41 - vst41.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST41_8 - ARM_INS_VST41 - vst41.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST41_8_wb - ARM_INS_VST41 - vst41.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST42_16 - ARM_INS_VST42 - vst42.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST42_16_wb - ARM_INS_VST42 - vst42.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST42_32 - ARM_INS_VST42 - vst42.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST42_32_wb - ARM_INS_VST42 - vst42.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST42_8 - ARM_INS_VST42 - vst42.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST42_8_wb - ARM_INS_VST42 - vst42.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST43_16 - ARM_INS_VST43 - vst43.16	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST43_16_wb - ARM_INS_VST43 - vst43.16	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST43_32 - ARM_INS_VST43 - vst43.32	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST43_32_wb - ARM_INS_VST43 - vst43.32	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST43_8 - ARM_INS_VST43 - vst43.8	$VQd, $Rn */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VST43_8_wb - ARM_INS_VST43 - vst43.8	$VQd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* VQd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB16 - ARM_INS_VSTRB - vstrb${vp}.16	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB16_post - ARM_INS_VSTRB - vstrb${vp}.16	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB16_pre - ARM_INS_VSTRB - vstrb${vp}.16	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB16_rq - ARM_INS_VSTRB - vstrb${vp}.16	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB32 - ARM_INS_VSTRB - vstrb${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB32_post - ARM_INS_VSTRB - vstrb${vp}.32	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB32_pre - ARM_INS_VSTRB - vstrb${vp}.32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB32_rq - ARM_INS_VSTRB - vstrb${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRB8_rq - ARM_INS_VSTRB - vstrb${vp}.8	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRBU8 - ARM_INS_VSTRB - vstrb${vp}.8	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRBU8_post - ARM_INS_VSTRB - vstrb${vp}.8	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRBU8_pre - ARM_INS_VSTRB - vstrb${vp}.8	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRD64_qi - ARM_INS_VSTRD - vstrd${vp}.64	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRD64_qi_pre - ARM_INS_VSTRD - vstrd${vp}.64	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRD64_rq - ARM_INS_VSTRD - vstrd${vp}.64	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRD64_rq_u - ARM_INS_VSTRD - vstrd${vp}.64	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRH16_rq - ARM_INS_VSTRH - vstrh${vp}.16	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRH16_rq_u - ARM_INS_VSTRH - vstrh${vp}.16	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRH32 - ARM_INS_VSTRH - vstrh${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRH32_post - ARM_INS_VSTRH - vstrh${vp}.32	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRH32_pre - ARM_INS_VSTRH - vstrh${vp}.32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRH32_rq - ARM_INS_VSTRH - vstrh${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRH32_rq_u - ARM_INS_VSTRH - vstrh${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRHU16 - ARM_INS_VSTRH - vstrh${vp}.16	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRHU16_post - ARM_INS_VSTRH - vstrh${vp}.16	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRHU16_pre - ARM_INS_VSTRH - vstrh${vp}.16	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRW32_qi - ARM_INS_VSTRW - vstrw${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRW32_qi_pre - ARM_INS_VSTRW - vstrw${vp}.32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRW32_rq - ARM_INS_VSTRW - vstrw${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRW32_rq_u - ARM_INS_VSTRW - vstrw${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRWU32 - ARM_INS_VSTRW - vstrw${vp}.32	$Qd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRWU32_post - ARM_INS_VSTRW - vstrw${vp}.32	$Qd, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSTRWU32_pre - ARM_INS_VSTRW - vstrw${vp}.32	$Qd, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Qd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_MVE_VSUB_qr_f16 - ARM_INS_VSUB - vsub${vp}.f16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSUB_qr_f32 - ARM_INS_VSUB - vsub${vp}.f32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSUB_qr_i16 - ARM_INS_VSUB - vsub${vp}.i16	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSUB_qr_i32 - ARM_INS_VSUB - vsub${vp}.i32	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSUB_qr_i8 - ARM_INS_VSUB - vsub${vp}.i8	$Qd, $Qn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVE_VSUBf16 - ARM_INS_VSUB - vsub${vp}.f16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSUBf32 - ARM_INS_VSUB - vsub${vp}.f32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSUBi16 - ARM_INS_VSUB - vsub${vp}.i16	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSUBi32 - ARM_INS_VSUB - vsub${vp}.i32	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_VSUBi8 - ARM_INS_VSUB - vsub${vp}.i8	$Qd, $Qn, $Qm */
  { CS_OP_REG, CS_AC_WRITE }, /* Qd */
  { CS_OP_REG, CS_AC_READ }, /* Qn */
  { CS_OP_REG, CS_AC_READ }, /* Qm */
  { 0 }
}},
{{ /* ARM_MVE_WLSTP_16 - ARM_INS_WLSTP - wlstp.16	$LR, $Rn, $label */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_MVE_WLSTP_32 - ARM_INS_WLSTP - wlstp.32	$LR, $Rn, $label */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_MVE_WLSTP_64 - ARM_INS_WLSTP - wlstp.64	$LR, $Rn, $label */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_MVE_WLSTP_8 - ARM_INS_WLSTP - wlstp.8	$LR, $Rn, $label */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_MVNi - ARM_INS_MVN - mvn${s}${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_MVNr - ARM_INS_MVN - mvn${s}${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_MVNsi - ARM_INS_MVN - mvn${s}${p}	$Rd, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_MVNsr - ARM_INS_MVN - mvn${s}${p}	$Rd, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_NEON_VMAXNMNDf - ARM_INS_VMAXNM - vmaxnm.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_NEON_VMAXNMNDh - ARM_INS_VMAXNM - vmaxnm.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_NEON_VMAXNMNQf - ARM_INS_VMAXNM - vmaxnm.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_NEON_VMAXNMNQh - ARM_INS_VMAXNM - vmaxnm.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_NEON_VMINNMNDf - ARM_INS_VMINNM - vminnm.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_NEON_VMINNMNDh - ARM_INS_VMINNM - vminnm.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_NEON_VMINNMNQf - ARM_INS_VMINNM - vminnm.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_NEON_VMINNMNQh - ARM_INS_VMINNM - vminnm.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_ORRri - ARM_INS_ORR - orr${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_ORRrr - ARM_INS_ORR - orr${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_ORRrsi - ARM_INS_ORR - orr${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_ORRrsr - ARM_INS_ORR - orr${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_PKHBT - ARM_INS_PKHBT - pkhbt${p}	$Rd, $Rn, $Rm$sh */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* sh */
  { 0 }
}},
{{ /* ARM_PKHTB - ARM_INS_PKHTB - pkhtb${p}	$Rd, $Rn, $Rm$sh */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* sh */
  { 0 }
}},
{{ /* ARM_PLDWi12 - ARM_INS_PLDW - pldw	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_PLDWrs - ARM_INS_PLDW - pldw	$shift */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_PLDi12 - ARM_INS_PLD - pld	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_PLDrs - ARM_INS_PLD - pld	$shift */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_PLIi12 - ARM_INS_PLI - pli	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_PLIrs - ARM_INS_PLI - pli	$shift */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_QADD - ARM_INS_QADD - qadd${p}	$Rd, $Rm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_QADD16 - ARM_INS_QADD16 - qadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_QADD8 - ARM_INS_QADD8 - qadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_QASX - ARM_INS_QASX - qasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_QDADD - ARM_INS_QDADD - qdadd${p}	$Rd, $Rm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_QDSUB - ARM_INS_QDSUB - qdsub${p}	$Rd, $Rm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_QSAX - ARM_INS_QSAX - qsax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_QSUB - ARM_INS_QSUB - qsub${p}	$Rd, $Rm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_QSUB16 - ARM_INS_QSUB16 - qsub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_QSUB8 - ARM_INS_QSUB8 - qsub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_RBIT - ARM_INS_RBIT - rbit${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_REV - ARM_INS_REV - rev${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_REV16 - ARM_INS_REV16 - rev16${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_REVSH - ARM_INS_REVSH - revsh${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_RFEDA - ARM_INS_RFEDA - rfeda	$Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_RFEDA_UPD - ARM_INS_RFEDA - rfeda	$Rn! */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_RFEDB - ARM_INS_RFEDB - rfedb	$Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_RFEDB_UPD - ARM_INS_RFEDB - rfedb	$Rn! */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_RFEIA - ARM_INS_RFEIA - rfeia	$Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_RFEIA_UPD - ARM_INS_RFEIA - rfeia	$Rn! */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_RFEIB - ARM_INS_RFEIB - rfeib	$Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_RFEIB_UPD - ARM_INS_RFEIB - rfeib	$Rn! */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_RSBri - ARM_INS_RSB - rsb${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_RSBrr - ARM_INS_RSB - rsb${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_RSBrsi - ARM_INS_RSB - rsb${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_RSBrsr - ARM_INS_RSB - rsb${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_RSCri - ARM_INS_RSC - rsc${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_RSCrr - ARM_INS_RSC - rsc${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_RSCrsi - ARM_INS_RSC - rsc${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_RSCrsr - ARM_INS_RSC - rsc${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_SADD16 - ARM_INS_SADD16 - sadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SADD8 - ARM_INS_SADD8 - sadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SASX - ARM_INS_SASX - sasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SB - ARM_INS_SB - sb */
  { 0 }
}},
{{ /* ARM_SBCri - ARM_INS_SBC - sbc${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_SBCrr - ARM_INS_SBC - sbc${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SBCrsi - ARM_INS_SBC - sbc${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_SBCrsr - ARM_INS_SBC - sbc${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_SBFX - ARM_INS_SBFX - sbfx${p}	$Rd, $Rn, $lsb, $width */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* lsb */
  { CS_OP_IMM, CS_AC_READ }, /* width */
  { 0 }
}},
{{ /* ARM_SDIV - ARM_INS_SDIV - sdiv${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SEL - ARM_INS_SEL - sel${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SETEND - ARM_INS_SETEND - setend	$end */
  { CS_OP_IMM, CS_AC_READ }, /* end */
  { 0 }
}},
{{ /* ARM_SETPAN - ARM_INS_SETPAN - setpan	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_SHA1C - ARM_INS_SHA1C - sha1c.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA1H - ARM_INS_SHA1H - sha1h.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA1M - ARM_INS_SHA1M - sha1m.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA1P - ARM_INS_SHA1P - sha1p.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA1SU0 - ARM_INS_SHA1SU0 - sha1su0.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA1SU1 - ARM_INS_SHA1SU1 - sha1su1.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA256H - ARM_INS_SHA256H - sha256h.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA256H2 - ARM_INS_SHA256H2 - sha256h2.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA256SU0 - ARM_INS_SHA256SU0 - sha256su0.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHA256SU1 - ARM_INS_SHA256SU1 - sha256su1.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_SHADD16 - ARM_INS_SHADD16 - shadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SHADD8 - ARM_INS_SHADD8 - shadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SHASX - ARM_INS_SHASX - shasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SHSAX - ARM_INS_SHSAX - shsax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SHSUB16 - ARM_INS_SHSUB16 - shsub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SHSUB8 - ARM_INS_SHSUB8 - shsub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMC - ARM_INS_SMC - smc${p}	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_SMLABB - ARM_INS_SMLABB - smlabb${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLABT - ARM_INS_SMLABT - smlabt${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLAD - ARM_INS_SMLAD - smlad${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLADX - ARM_INS_SMLADX - smladx${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLAL - ARM_INS_SMLAL - smlal${s}${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMLALBB - ARM_INS_SMLALBB - smlalbb${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMLALBT - ARM_INS_SMLALBT - smlalbt${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMLALD - ARM_INS_SMLALD - smlald${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMLALDX - ARM_INS_SMLALDX - smlaldx${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMLALTB - ARM_INS_SMLALTB - smlaltb${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMLALTT - ARM_INS_SMLALTT - smlaltt${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMLATB - ARM_INS_SMLATB - smlatb${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLATT - ARM_INS_SMLATT - smlatt${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLAWB - ARM_INS_SMLAWB - smlawb${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLAWT - ARM_INS_SMLAWT - smlawt${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLSD - ARM_INS_SMLSD - smlsd${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLSDX - ARM_INS_SMLSDX - smlsdx${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMLSLD - ARM_INS_SMLSLD - smlsld${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMLSLDX - ARM_INS_SMLSLDX - smlsldx${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_SMMLA - ARM_INS_SMMLA - smmla${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMMLAR - ARM_INS_SMMLAR - smmlar${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMMLS - ARM_INS_SMMLS - smmls${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMMLSR - ARM_INS_SMMLSR - smmlsr${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_SMMUL - ARM_INS_SMMUL - smmul${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMMULR - ARM_INS_SMMULR - smmulr${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMUAD - ARM_INS_SMUAD - smuad${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMUADX - ARM_INS_SMUADX - smuadx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMULBB - ARM_INS_SMULBB - smulbb${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMULBT - ARM_INS_SMULBT - smulbt${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMULL - ARM_INS_SMULL - smull${s}${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMULTB - ARM_INS_SMULTB - smultb${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMULTT - ARM_INS_SMULTT - smultt${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMULWB - ARM_INS_SMULWB - smulwb${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMULWT - ARM_INS_SMULWT - smulwt${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMUSD - ARM_INS_SMUSD - smusd${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SMUSDX - ARM_INS_SMUSDX - smusdx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SRSDA - ARM_INS_SRSDA - srsda	sp, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_SRSDA_UPD - ARM_INS_SRSDA - srsda	sp!, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_SRSDB - ARM_INS_SRSDB - srsdb	sp, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_SRSDB_UPD - ARM_INS_SRSDB - srsdb	sp!, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_SRSIA - ARM_INS_SRSIA - srsia	sp, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_SRSIA_UPD - ARM_INS_SRSIA - srsia	sp!, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_SRSIB - ARM_INS_SRSIB - srsib	sp, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_SRSIB_UPD - ARM_INS_SRSIB - srsib	sp!, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_SSAT - ARM_INS_SSAT - ssat${p}	$Rd, $sat_imm, $Rn$sh */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* sat_imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* sh */
  { 0 }
}},
{{ /* ARM_SSAT16 - ARM_INS_SSAT16 - ssat16${p}	$Rd, $sat_imm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* sat_imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_SSAX - ARM_INS_SSAX - ssax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SSUB16 - ARM_INS_SSUB16 - ssub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SSUB8 - ARM_INS_SSUB8 - ssub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_STC2L_OFFSET - ARM_INS_STC2L - stc2l	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STC2L_OPTION - ARM_INS_STC2L - stc2l	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_STC2L_POST - ARM_INS_STC2L - stc2l	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STC2L_PRE - ARM_INS_STC2L - stc2l	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STC2_OFFSET - ARM_INS_STC2 - stc2	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STC2_OPTION - ARM_INS_STC2 - stc2	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_STC2_POST - ARM_INS_STC2 - stc2	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STC2_PRE - ARM_INS_STC2 - stc2	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STCL_OFFSET - ARM_INS_STCL - stcl${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STCL_OPTION - ARM_INS_STCL - stcl${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_STCL_POST - ARM_INS_STCL - stcl${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STCL_PRE - ARM_INS_STCL - stcl${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STC_OFFSET - ARM_INS_STC - stc${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STC_OPTION - ARM_INS_STC - stc${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_STC_POST - ARM_INS_STC - stc${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STC_PRE - ARM_INS_STC - stc${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STL - ARM_INS_STL - stl${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STLB - ARM_INS_STLB - stlb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STLEX - ARM_INS_STLEX - stlex${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STLEXB - ARM_INS_STLEXB - stlexb${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STLEXD - ARM_INS_STLEXD - stlexd${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STLEXH - ARM_INS_STLEXH - stlexh${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STLH - ARM_INS_STLH - stlh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STMDA - ARM_INS_STMDA - stmda${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_STMDA_UPD - ARM_INS_STMDA - stmda${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_STMDB - ARM_INS_STMDB - stmdb${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_STMDB_UPD - ARM_INS_STMDB - stmdb${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_STMIA - ARM_INS_STM - stm${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_STMIA_UPD - ARM_INS_STM - stm${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_STMIB - ARM_INS_STMIB - stmib${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_STMIB_UPD - ARM_INS_STMIB - stmib${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_STRBT_POST_IMM - ARM_INS_STRBT - strbt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STRBT_POST_REG - ARM_INS_STRBT - strbt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STRB_POST_IMM - ARM_INS_STRB - strb${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STRB_POST_REG - ARM_INS_STRB - strb${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STRB_PRE_IMM - ARM_INS_STRB - strb${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRB_PRE_REG - ARM_INS_STRB - strb${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRBi12 - ARM_INS_STRB - strb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRBrs - ARM_INS_STRB - strb${p}	$Rt, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_STRD - ARM_INS_STRD - strd${p}	$Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRD_POST - ARM_INS_STRD - strd${p}	$Rt, $Rt2, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STRD_PRE - ARM_INS_STRD - strd${p}	$Rt, $Rt2, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STREX - ARM_INS_STREX - strex${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STREXB - ARM_INS_STREXB - strexb${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STREXD - ARM_INS_STREXD - strexd${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STREXH - ARM_INS_STREXH - strexh${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRH - ARM_INS_STRH - strh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRHTi - ARM_INS_STRHT - strht${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* base_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STRHTr - ARM_INS_STRHT - strht${p}	$Rt, $addr, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* base_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_STRH_POST - ARM_INS_STRH - strh${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STRH_PRE - ARM_INS_STRH - strh${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRT_POST_IMM - ARM_INS_STRT - strt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STRT_POST_REG - ARM_INS_STRT - strt${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STR_POST_IMM - ARM_INS_STR - str${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STR_POST_REG - ARM_INS_STR - str${p}	$Rt, $addr, $offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_STR_PRE_IMM - ARM_INS_STR - str${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STR_PRE_REG - ARM_INS_STR - str${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRi12 - ARM_INS_STR - str${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_STRrs - ARM_INS_STR - str${p}	$Rt, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_SUBri - ARM_INS_SUB - sub${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_SUBrr - ARM_INS_SUB - sub${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_SUBrsi - ARM_INS_SUB - sub${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_SUBrsr - ARM_INS_SUB - sub${s}${p}	$Rd, $Rn, $shift */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_SVC - ARM_INS_SVC - svc${p}	$svc */
  { CS_OP_IMM, CS_AC_READ }, /* svc */
  { 0 }
}},
{{ /* ARM_SWP - ARM_INS_SWP - swp${p}	$Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_SWPB - ARM_INS_SWPB - swpb${p}	$Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_SXTAB - ARM_INS_SXTAB - sxtab${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_SXTAB16 - ARM_INS_SXTAB16 - sxtab16${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_SXTAH - ARM_INS_SXTAH - sxtah${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_SXTB - ARM_INS_SXTB - sxtb${p}	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_SXTB16 - ARM_INS_SXTB16 - sxtb16${p}	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_SXTH - ARM_INS_SXTH - sxth${p}	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_TEQri - ARM_INS_TEQ - teq${p}	$Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_TEQrr - ARM_INS_TEQ - teq${p}	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_TEQrsi - ARM_INS_TEQ - teq${p}	$Rn, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_TEQrsr - ARM_INS_TEQ - teq${p}	$Rn, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_TRAP - ARM_INS_TRAP - trap */
  { 0 }
}},
{{ /* ARM_TRAPNaCl - ARM_INS_TRAP - trap */
  { 0 }
}},
{{ /* ARM_TSB - ARM_INS_TSB - tsb	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_TSTri - ARM_INS_TST - tst${p}	$Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_TSTrr - ARM_INS_TST - tst${p}	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_TSTrsi - ARM_INS_TST - tst${p}	$Rn, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_TSTrsr - ARM_INS_TST - tst${p}	$Rn, $shift */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* shift */
  { 0 }
}},
{{ /* ARM_UADD16 - ARM_INS_UADD16 - uadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UADD8 - ARM_INS_UADD8 - uadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UASX - ARM_INS_UASX - uasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UBFX - ARM_INS_UBFX - ubfx${p}	$Rd, $Rn, $lsb, $width */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* lsb */
  { CS_OP_IMM, CS_AC_READ }, /* width */
  { 0 }
}},
{{ /* ARM_UDF - ARM_INS_UDF - udf	$imm16 */
  { CS_OP_IMM, CS_AC_READ }, /* imm16 */
  { 0 }
}},
{{ /* ARM_UDIV - ARM_INS_UDIV - udiv${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UHADD16 - ARM_INS_UHADD16 - uhadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UHADD8 - ARM_INS_UHADD8 - uhadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UHASX - ARM_INS_UHASX - uhasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UHSAX - ARM_INS_UHSAX - uhsax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UHSUB16 - ARM_INS_UHSUB16 - uhsub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UHSUB8 - ARM_INS_UHSUB8 - uhsub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UMAAL - ARM_INS_UMAAL - umaal${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_UMLAL - ARM_INS_UMLAL - umlal${s}${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_UMULL - ARM_INS_UMULL - umull${s}${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UQADD16 - ARM_INS_UQADD16 - uqadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UQADD8 - ARM_INS_UQADD8 - uqadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UQASX - ARM_INS_UQASX - uqasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UQSAX - ARM_INS_UQSAX - uqsax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UQSUB16 - ARM_INS_UQSUB16 - uqsub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UQSUB8 - ARM_INS_UQSUB8 - uqsub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_USAD8 - ARM_INS_USAD8 - usad8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_USADA8 - ARM_INS_USADA8 - usada8${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_USAT - ARM_INS_USAT - usat${p}	$Rd, $sat_imm, $Rn$sh */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* sat_imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* sh */
  { 0 }
}},
{{ /* ARM_USAT16 - ARM_INS_USAT16 - usat16${p}	$Rd, $sat_imm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* sat_imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_USAX - ARM_INS_USAX - usax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_USUB16 - ARM_INS_USUB16 - usub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_USUB8 - ARM_INS_USUB8 - usub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_UXTAB - ARM_INS_UXTAB - uxtab${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_UXTAB16 - ARM_INS_UXTAB16 - uxtab16${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_UXTAH - ARM_INS_UXTAH - uxtah${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_UXTB - ARM_INS_UXTB - uxtb${p}	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_UXTB16 - ARM_INS_UXTB16 - uxtb16${p}	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_UXTH - ARM_INS_UXTH - uxth${p}	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VABALsv2i64 - ARM_INS_VABAL - vabal${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABALsv4i32 - ARM_INS_VABAL - vabal${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABALsv8i16 - ARM_INS_VABAL - vabal${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABALuv2i64 - ARM_INS_VABAL - vabal${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABALuv4i32 - ARM_INS_VABAL - vabal${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABALuv8i16 - ARM_INS_VABAL - vabal${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAsv16i8 - ARM_INS_VABA - vaba${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAsv2i32 - ARM_INS_VABA - vaba${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAsv4i16 - ARM_INS_VABA - vaba${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAsv4i32 - ARM_INS_VABA - vaba${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAsv8i16 - ARM_INS_VABA - vaba${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAsv8i8 - ARM_INS_VABA - vaba${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAuv16i8 - ARM_INS_VABA - vaba${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAuv2i32 - ARM_INS_VABA - vaba${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAuv4i16 - ARM_INS_VABA - vaba${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAuv4i32 - ARM_INS_VABA - vaba${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAuv8i16 - ARM_INS_VABA - vaba${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABAuv8i8 - ARM_INS_VABA - vaba${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDLsv2i64 - ARM_INS_VABDL - vabdl${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDLsv4i32 - ARM_INS_VABDL - vabdl${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDLsv8i16 - ARM_INS_VABDL - vabdl${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDLuv2i64 - ARM_INS_VABDL - vabdl${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDLuv4i32 - ARM_INS_VABDL - vabdl${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDLuv8i16 - ARM_INS_VABDL - vabdl${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDfd - ARM_INS_VABD - vabd${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDfq - ARM_INS_VABD - vabd${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDhd - ARM_INS_VABD - vabd${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDhq - ARM_INS_VABD - vabd${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDsv16i8 - ARM_INS_VABD - vabd${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDsv2i32 - ARM_INS_VABD - vabd${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDsv4i16 - ARM_INS_VABD - vabd${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDsv4i32 - ARM_INS_VABD - vabd${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDsv8i16 - ARM_INS_VABD - vabd${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDsv8i8 - ARM_INS_VABD - vabd${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDuv16i8 - ARM_INS_VABD - vabd${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDuv2i32 - ARM_INS_VABD - vabd${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDuv4i16 - ARM_INS_VABD - vabd${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDuv4i32 - ARM_INS_VABD - vabd${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDuv8i16 - ARM_INS_VABD - vabd${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABDuv8i8 - ARM_INS_VABD - vabd${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABSD - ARM_INS_VABS - vabs${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VABSH - ARM_INS_VABS - vabs${p}.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VABSS - ARM_INS_VABS - vabs${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VABSfd - ARM_INS_VABS - vabs${p}.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABSfq - ARM_INS_VABS - vabs${p}.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABShd - ARM_INS_VABS - vabs${p}.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABShq - ARM_INS_VABS - vabs${p}.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABSv16i8 - ARM_INS_VABS - vabs${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABSv2i32 - ARM_INS_VABS - vabs${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABSv4i16 - ARM_INS_VABS - vabs${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABSv4i32 - ARM_INS_VABS - vabs${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABSv8i16 - ARM_INS_VABS - vabs${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VABSv8i8 - ARM_INS_VABS - vabs${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VACGEfd - ARM_INS_VACGE - vacge${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VACGEfq - ARM_INS_VACGE - vacge${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VACGEhd - ARM_INS_VACGE - vacge${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VACGEhq - ARM_INS_VACGE - vacge${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VACGTfd - ARM_INS_VACGT - vacgt${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VACGTfq - ARM_INS_VACGT - vacgt${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VACGThd - ARM_INS_VACGT - vacgt${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VACGThq - ARM_INS_VACGT - vacgt${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDD - ARM_INS_VADD - vadd${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VADDH - ARM_INS_VADD - vadd${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VADDHNv2i32 - ARM_INS_VADDHN - vaddhn${p}.i64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDHNv4i16 - ARM_INS_VADDHN - vaddhn${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDHNv8i8 - ARM_INS_VADDHN - vaddhn${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDLsv2i64 - ARM_INS_VADDL - vaddl${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDLsv4i32 - ARM_INS_VADDL - vaddl${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDLsv8i16 - ARM_INS_VADDL - vaddl${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDLuv2i64 - ARM_INS_VADDL - vaddl${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDLuv4i32 - ARM_INS_VADDL - vaddl${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDLuv8i16 - ARM_INS_VADDL - vaddl${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDS - ARM_INS_VADD - vadd${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VADDWsv2i64 - ARM_INS_VADDW - vaddw${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDWsv4i32 - ARM_INS_VADDW - vaddw${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDWsv8i16 - ARM_INS_VADDW - vaddw${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDWuv2i64 - ARM_INS_VADDW - vaddw${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDWuv4i32 - ARM_INS_VADDW - vaddw${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDWuv8i16 - ARM_INS_VADDW - vaddw${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDfd - ARM_INS_VADD - vadd${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDfq - ARM_INS_VADD - vadd${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDhd - ARM_INS_VADD - vadd${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDhq - ARM_INS_VADD - vadd${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDv16i8 - ARM_INS_VADD - vadd${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDv1i64 - ARM_INS_VADD - vadd${p}.i64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDv2i32 - ARM_INS_VADD - vadd${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDv2i64 - ARM_INS_VADD - vadd${p}.i64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDv4i16 - ARM_INS_VADD - vadd${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDv4i32 - ARM_INS_VADD - vadd${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDv8i16 - ARM_INS_VADD - vadd${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VADDv8i8 - ARM_INS_VADD - vadd${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VANDd - ARM_INS_VAND - vand${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VANDq - ARM_INS_VAND - vand${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBF16MALBQ - ARM_INS_VFMAB - vfmab.bf16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBF16MALBQI - ARM_INS_VFMAB - vfmab.bf16	$Vd, $Vn, $Vm$idx */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* idx */
  { 0 }
}},
{{ /* ARM_VBF16MALTQ - ARM_INS_VFMAT - vfmat.bf16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBF16MALTQI - ARM_INS_VFMAT - vfmat.bf16	$Vd, $Vn, $Vm$idx */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* idx */
  { 0 }
}},
{{ /* ARM_VBICd - ARM_INS_VBIC - vbic${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBICiv2i32 - ARM_INS_VBIC - vbic${p}.i32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_VBICiv4i16 - ARM_INS_VBIC - vbic${p}.i16	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_VBICiv4i32 - ARM_INS_VBIC - vbic${p}.i32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_VBICiv8i16 - ARM_INS_VBIC - vbic${p}.i16	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_VBICq - ARM_INS_VBIC - vbic${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBIFd - ARM_INS_VBIF - vbif${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBIFq - ARM_INS_VBIF - vbif${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBITd - ARM_INS_VBIT - vbit${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBITq - ARM_INS_VBIT - vbit${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBSLd - ARM_INS_VBSL - vbsl${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VBSLq - ARM_INS_VBSL - vbsl${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCADDv2f32 - ARM_INS_VCADD - vcadd.f32	$Vd, $Vn, $Vm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCADDv4f16 - ARM_INS_VCADD - vcadd.f16	$Vd, $Vn, $Vm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCADDv4f32 - ARM_INS_VCADD - vcadd.f32	$Vd, $Vn, $Vm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCADDv8f16 - ARM_INS_VCADD - vcadd.f16	$Vd, $Vn, $Vm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCEQfd - ARM_INS_VCEQ - vceq${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQfq - ARM_INS_VCEQ - vceq${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQhd - ARM_INS_VCEQ - vceq${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQhq - ARM_INS_VCEQ - vceq${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQv16i8 - ARM_INS_VCEQ - vceq${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQv2i32 - ARM_INS_VCEQ - vceq${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQv4i16 - ARM_INS_VCEQ - vceq${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQv4i32 - ARM_INS_VCEQ - vceq${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQv8i16 - ARM_INS_VCEQ - vceq${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQv8i8 - ARM_INS_VCEQ - vceq${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv16i8 - ARM_INS_VCEQ - vceq${p}.i8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv2f32 - ARM_INS_VCEQ - vceq${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv2i32 - ARM_INS_VCEQ - vceq${p}.i32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv4f16 - ARM_INS_VCEQ - vceq${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv4f32 - ARM_INS_VCEQ - vceq${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv4i16 - ARM_INS_VCEQ - vceq${p}.i16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv4i32 - ARM_INS_VCEQ - vceq${p}.i32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv8f16 - ARM_INS_VCEQ - vceq${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv8i16 - ARM_INS_VCEQ - vceq${p}.i16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCEQzv8i8 - ARM_INS_VCEQ - vceq${p}.i8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEfd - ARM_INS_VCGE - vcge${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEfq - ARM_INS_VCGE - vcge${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEhd - ARM_INS_VCGE - vcge${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEhq - ARM_INS_VCGE - vcge${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEsv16i8 - ARM_INS_VCGE - vcge${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEsv2i32 - ARM_INS_VCGE - vcge${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEsv4i16 - ARM_INS_VCGE - vcge${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEsv4i32 - ARM_INS_VCGE - vcge${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEsv8i16 - ARM_INS_VCGE - vcge${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEsv8i8 - ARM_INS_VCGE - vcge${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEuv16i8 - ARM_INS_VCGE - vcge${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEuv2i32 - ARM_INS_VCGE - vcge${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEuv4i16 - ARM_INS_VCGE - vcge${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEuv4i32 - ARM_INS_VCGE - vcge${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEuv8i16 - ARM_INS_VCGE - vcge${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEuv8i8 - ARM_INS_VCGE - vcge${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv16i8 - ARM_INS_VCGE - vcge${p}.s8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv2f32 - ARM_INS_VCGE - vcge${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv2i32 - ARM_INS_VCGE - vcge${p}.s32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv4f16 - ARM_INS_VCGE - vcge${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv4f32 - ARM_INS_VCGE - vcge${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv4i16 - ARM_INS_VCGE - vcge${p}.s16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv4i32 - ARM_INS_VCGE - vcge${p}.s32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv8f16 - ARM_INS_VCGE - vcge${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv8i16 - ARM_INS_VCGE - vcge${p}.s16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGEzv8i8 - ARM_INS_VCGE - vcge${p}.s8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTfd - ARM_INS_VCGT - vcgt${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTfq - ARM_INS_VCGT - vcgt${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGThd - ARM_INS_VCGT - vcgt${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGThq - ARM_INS_VCGT - vcgt${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTsv16i8 - ARM_INS_VCGT - vcgt${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTsv2i32 - ARM_INS_VCGT - vcgt${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTsv4i16 - ARM_INS_VCGT - vcgt${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTsv4i32 - ARM_INS_VCGT - vcgt${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTsv8i16 - ARM_INS_VCGT - vcgt${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTsv8i8 - ARM_INS_VCGT - vcgt${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTuv16i8 - ARM_INS_VCGT - vcgt${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTuv2i32 - ARM_INS_VCGT - vcgt${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTuv4i16 - ARM_INS_VCGT - vcgt${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTuv4i32 - ARM_INS_VCGT - vcgt${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTuv8i16 - ARM_INS_VCGT - vcgt${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTuv8i8 - ARM_INS_VCGT - vcgt${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv16i8 - ARM_INS_VCGT - vcgt${p}.s8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv2f32 - ARM_INS_VCGT - vcgt${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv2i32 - ARM_INS_VCGT - vcgt${p}.s32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv4f16 - ARM_INS_VCGT - vcgt${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv4f32 - ARM_INS_VCGT - vcgt${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv4i16 - ARM_INS_VCGT - vcgt${p}.s16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv4i32 - ARM_INS_VCGT - vcgt${p}.s32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv8f16 - ARM_INS_VCGT - vcgt${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv8i16 - ARM_INS_VCGT - vcgt${p}.s16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCGTzv8i8 - ARM_INS_VCGT - vcgt${p}.s8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv16i8 - ARM_INS_VCLE - vcle${p}.s8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv2f32 - ARM_INS_VCLE - vcle${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv2i32 - ARM_INS_VCLE - vcle${p}.s32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv4f16 - ARM_INS_VCLE - vcle${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv4f32 - ARM_INS_VCLE - vcle${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv4i16 - ARM_INS_VCLE - vcle${p}.s16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv4i32 - ARM_INS_VCLE - vcle${p}.s32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv8f16 - ARM_INS_VCLE - vcle${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv8i16 - ARM_INS_VCLE - vcle${p}.s16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLEzv8i8 - ARM_INS_VCLE - vcle${p}.s8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLSv16i8 - ARM_INS_VCLS - vcls${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLSv2i32 - ARM_INS_VCLS - vcls${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLSv4i16 - ARM_INS_VCLS - vcls${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLSv4i32 - ARM_INS_VCLS - vcls${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLSv8i16 - ARM_INS_VCLS - vcls${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLSv8i8 - ARM_INS_VCLS - vcls${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv16i8 - ARM_INS_VCLT - vclt${p}.s8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv2f32 - ARM_INS_VCLT - vclt${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv2i32 - ARM_INS_VCLT - vclt${p}.s32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv4f16 - ARM_INS_VCLT - vclt${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv4f32 - ARM_INS_VCLT - vclt${p}.f32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv4i16 - ARM_INS_VCLT - vclt${p}.s16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv4i32 - ARM_INS_VCLT - vclt${p}.s32	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv8f16 - ARM_INS_VCLT - vclt${p}.f16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv8i16 - ARM_INS_VCLT - vclt${p}.s16	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLTzv8i8 - ARM_INS_VCLT - vclt${p}.s8	$Vd, $Vm, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLZv16i8 - ARM_INS_VCLZ - vclz${p}.i8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLZv2i32 - ARM_INS_VCLZ - vclz${p}.i32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLZv4i16 - ARM_INS_VCLZ - vclz${p}.i16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLZv4i32 - ARM_INS_VCLZ - vclz${p}.i32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLZv8i16 - ARM_INS_VCLZ - vclz${p}.i16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCLZv8i8 - ARM_INS_VCLZ - vclz${p}.i8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCMLAv2f32 - ARM_INS_VCMLA - vcmla.f32	$Vd, $Vn, $Vm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCMLAv2f32_indexed - ARM_INS_VCMLA - vcmla.f32	$Vd, $Vn, $Vm$lane, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCMLAv4f16 - ARM_INS_VCMLA - vcmla.f16	$Vd, $Vn, $Vm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCMLAv4f16_indexed - ARM_INS_VCMLA - vcmla.f16	$Vd, $Vn, $Vm$lane, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCMLAv4f32 - ARM_INS_VCMLA - vcmla.f32	$Vd, $Vn, $Vm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCMLAv4f32_indexed - ARM_INS_VCMLA - vcmla.f32	$Vd, $Vn, $Vm$lane, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCMLAv8f16 - ARM_INS_VCMLA - vcmla.f16	$Vd, $Vn, $Vm, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCMLAv8f16_indexed - ARM_INS_VCMLA - vcmla.f16	$Vd, $Vn, $Vm$lane, $rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_VCMPD - ARM_INS_VCMP - vcmp${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_READ }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCMPED - ARM_INS_VCMPE - vcmpe${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_READ }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCMPEH - ARM_INS_VCMPE - vcmpe${p}.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCMPES - ARM_INS_VCMPE - vcmpe${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCMPEZD - ARM_INS_VCMPE - vcmpe${p}.f64	$Dd, #0 */
  { CS_OP_REG, CS_AC_READ }, /* Dd */
  { 0 }
}},
{{ /* ARM_VCMPEZH - ARM_INS_VCMPE - vcmpe${p}.f16	$Sd, #0 */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { 0 }
}},
{{ /* ARM_VCMPEZS - ARM_INS_VCMPE - vcmpe${p}.f32	$Sd, #0 */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { 0 }
}},
{{ /* ARM_VCMPH - ARM_INS_VCMP - vcmp${p}.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCMPS - ARM_INS_VCMP - vcmp${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCMPZD - ARM_INS_VCMP - vcmp${p}.f64	$Dd, #0 */
  { CS_OP_REG, CS_AC_READ }, /* Dd */
  { 0 }
}},
{{ /* ARM_VCMPZH - ARM_INS_VCMP - vcmp${p}.f16	$Sd, #0 */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { 0 }
}},
{{ /* ARM_VCMPZS - ARM_INS_VCMP - vcmp${p}.f32	$Sd, #0 */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { 0 }
}},
{{ /* ARM_VCNTd - ARM_INS_VCNT - vcnt${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCNTq - ARM_INS_VCNT - vcnt${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTANSDf - ARM_INS_VCVTA - vcvta.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTANSDh - ARM_INS_VCVTA - vcvta.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTANSQf - ARM_INS_VCVTA - vcvta.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTANSQh - ARM_INS_VCVTA - vcvta.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTANUDf - ARM_INS_VCVTA - vcvta.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTANUDh - ARM_INS_VCVTA - vcvta.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTANUQf - ARM_INS_VCVTA - vcvta.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTANUQh - ARM_INS_VCVTA - vcvta.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTASD - ARM_INS_VCVTA - vcvta.s32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTASH - ARM_INS_VCVTA - vcvta.s32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTASS - ARM_INS_VCVTA - vcvta.s32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTAUD - ARM_INS_VCVTA - vcvta.u32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTAUH - ARM_INS_VCVTA - vcvta.u32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTAUS - ARM_INS_VCVTA - vcvta.u32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTBDH - ARM_INS_VCVTB - vcvtb${p}.f16.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sda */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTBHD - ARM_INS_VCVTB - vcvtb${p}.f64.f16	$Dd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTBHS - ARM_INS_VCVTB - vcvtb${p}.f32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTBSH - ARM_INS_VCVTB - vcvtb${p}.f16.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sda */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTDS - ARM_INS_VCVT - vcvt${p}.f64.f32	$Dd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTMNSDf - ARM_INS_VCVTM - vcvtm.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTMNSDh - ARM_INS_VCVTM - vcvtm.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTMNSQf - ARM_INS_VCVTM - vcvtm.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTMNSQh - ARM_INS_VCVTM - vcvtm.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTMNUDf - ARM_INS_VCVTM - vcvtm.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTMNUDh - ARM_INS_VCVTM - vcvtm.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTMNUQf - ARM_INS_VCVTM - vcvtm.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTMNUQh - ARM_INS_VCVTM - vcvtm.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTMSD - ARM_INS_VCVTM - vcvtm.s32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTMSH - ARM_INS_VCVTM - vcvtm.s32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTMSS - ARM_INS_VCVTM - vcvtm.s32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTMUD - ARM_INS_VCVTM - vcvtm.u32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTMUH - ARM_INS_VCVTM - vcvtm.u32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTMUS - ARM_INS_VCVTM - vcvtm.u32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTNNSDf - ARM_INS_VCVTN - vcvtn.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTNNSDh - ARM_INS_VCVTN - vcvtn.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTNNSQf - ARM_INS_VCVTN - vcvtn.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTNNSQh - ARM_INS_VCVTN - vcvtn.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTNNUDf - ARM_INS_VCVTN - vcvtn.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTNNUDh - ARM_INS_VCVTN - vcvtn.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTNNUQf - ARM_INS_VCVTN - vcvtn.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTNNUQh - ARM_INS_VCVTN - vcvtn.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTNSD - ARM_INS_VCVTN - vcvtn.s32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTNSH - ARM_INS_VCVTN - vcvtn.s32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTNSS - ARM_INS_VCVTN - vcvtn.s32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTNUD - ARM_INS_VCVTN - vcvtn.u32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTNUH - ARM_INS_VCVTN - vcvtn.u32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTNUS - ARM_INS_VCVTN - vcvtn.u32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTPNSDf - ARM_INS_VCVTP - vcvtp.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTPNSDh - ARM_INS_VCVTP - vcvtp.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTPNSQf - ARM_INS_VCVTP - vcvtp.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTPNSQh - ARM_INS_VCVTP - vcvtp.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTPNUDf - ARM_INS_VCVTP - vcvtp.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTPNUDh - ARM_INS_VCVTP - vcvtp.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTPNUQf - ARM_INS_VCVTP - vcvtp.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTPNUQh - ARM_INS_VCVTP - vcvtp.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTPSD - ARM_INS_VCVTP - vcvtp.s32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTPSH - ARM_INS_VCVTP - vcvtp.s32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTPSS - ARM_INS_VCVTP - vcvtp.s32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTPUD - ARM_INS_VCVTP - vcvtp.u32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTPUH - ARM_INS_VCVTP - vcvtp.u32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTPUS - ARM_INS_VCVTP - vcvtp.u32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTSD - ARM_INS_VCVT - vcvt${p}.f32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTTDH - ARM_INS_VCVTT - vcvtt${p}.f16.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sda */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VCVTTHD - ARM_INS_VCVTT - vcvtt${p}.f64.f16	$Dd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTTHS - ARM_INS_VCVTT - vcvtt${p}.f32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTTSH - ARM_INS_VCVTT - vcvtt${p}.f16.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sda */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VCVTf2h - ARM_INS_VCVT - vcvt${p}.f16.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTf2sd - ARM_INS_VCVT - vcvt${p}.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTf2sq - ARM_INS_VCVT - vcvt${p}.s32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTf2ud - ARM_INS_VCVT - vcvt${p}.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTf2uq - ARM_INS_VCVT - vcvt${p}.u32.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTf2xsd - ARM_INS_VCVT - vcvt${p}.s32.f32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTf2xsq - ARM_INS_VCVT - vcvt${p}.s32.f32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTf2xud - ARM_INS_VCVT - vcvt${p}.u32.f32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTf2xuq - ARM_INS_VCVT - vcvt${p}.u32.f32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTh2f - ARM_INS_VCVT - vcvt${p}.f32.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTh2sd - ARM_INS_VCVT - vcvt${p}.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTh2sq - ARM_INS_VCVT - vcvt${p}.s16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTh2ud - ARM_INS_VCVT - vcvt${p}.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTh2uq - ARM_INS_VCVT - vcvt${p}.u16.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTh2xsd - ARM_INS_VCVT - vcvt${p}.s16.f16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTh2xsq - ARM_INS_VCVT - vcvt${p}.s16.f16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTh2xud - ARM_INS_VCVT - vcvt${p}.u16.f16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTh2xuq - ARM_INS_VCVT - vcvt${p}.u16.f16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTs2fd - ARM_INS_VCVT - vcvt${p}.f32.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTs2fq - ARM_INS_VCVT - vcvt${p}.f32.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTs2hd - ARM_INS_VCVT - vcvt${p}.f16.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTs2hq - ARM_INS_VCVT - vcvt${p}.f16.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTu2fd - ARM_INS_VCVT - vcvt${p}.f32.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTu2fq - ARM_INS_VCVT - vcvt${p}.f32.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTu2hd - ARM_INS_VCVT - vcvt${p}.f16.u16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTu2hq - ARM_INS_VCVT - vcvt${p}.f16.u16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VCVTxs2fd - ARM_INS_VCVT - vcvt${p}.f32.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTxs2fq - ARM_INS_VCVT - vcvt${p}.f32.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTxs2hd - ARM_INS_VCVT - vcvt${p}.f16.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTxs2hq - ARM_INS_VCVT - vcvt${p}.f16.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTxu2fd - ARM_INS_VCVT - vcvt${p}.f32.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTxu2fq - ARM_INS_VCVT - vcvt${p}.f32.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTxu2hd - ARM_INS_VCVT - vcvt${p}.f16.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VCVTxu2hq - ARM_INS_VCVT - vcvt${p}.f16.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VDIVD - ARM_INS_VDIV - vdiv${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VDIVH - ARM_INS_VDIV - vdiv${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VDIVS - ARM_INS_VDIV - vdiv${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VDUP16d - ARM_INS_VDUP - vdup${p}.16	$V, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { 0 }
}},
{{ /* ARM_VDUP16q - ARM_INS_VDUP - vdup${p}.16	$V, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { 0 }
}},
{{ /* ARM_VDUP32d - ARM_INS_VDUP - vdup${p}.32	$V, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { 0 }
}},
{{ /* ARM_VDUP32q - ARM_INS_VDUP - vdup${p}.32	$V, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { 0 }
}},
{{ /* ARM_VDUP8d - ARM_INS_VDUP - vdup${p}.8	$V, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { 0 }
}},
{{ /* ARM_VDUP8q - ARM_INS_VDUP - vdup${p}.8	$V, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { 0 }
}},
{{ /* ARM_VDUPLN16d - ARM_INS_VDUP - vdup${p}.16	$Vd, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VDUPLN16q - ARM_INS_VDUP - vdup${p}.16	$Vd, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VDUPLN32d - ARM_INS_VDUP - vdup${p}.32	$Vd, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VDUPLN32q - ARM_INS_VDUP - vdup${p}.32	$Vd, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VDUPLN8d - ARM_INS_VDUP - vdup${p}.8	$Vd, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VDUPLN8q - ARM_INS_VDUP - vdup${p}.8	$Vd, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VEORd - ARM_INS_VEOR - veor${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VEORq - ARM_INS_VEOR - veor${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VEXTd16 - ARM_INS_VEXT - vext${p}.16	$Vd, $Vn, $Vm, $index */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* index */
  { 0 }
}},
{{ /* ARM_VEXTd32 - ARM_INS_VEXT - vext${p}.32	$Vd, $Vn, $Vm, $index */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* index */
  { 0 }
}},
{{ /* ARM_VEXTd8 - ARM_INS_VEXT - vext${p}.8	$Vd, $Vn, $Vm, $index */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* index */
  { 0 }
}},
{{ /* ARM_VEXTq16 - ARM_INS_VEXT - vext${p}.16	$Vd, $Vn, $Vm, $index */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* index */
  { 0 }
}},
{{ /* ARM_VEXTq32 - ARM_INS_VEXT - vext${p}.32	$Vd, $Vn, $Vm, $index */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* index */
  { 0 }
}},
{{ /* ARM_VEXTq64 - ARM_INS_VEXT - vext${p}.64	$Vd, $Vn, $Vm, $index */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* index */
  { 0 }
}},
{{ /* ARM_VEXTq8 - ARM_INS_VEXT - vext${p}.8	$Vd, $Vn, $Vm, $index */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* index */
  { 0 }
}},
{{ /* ARM_VFMAD - ARM_INS_VFMA - vfma${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Ddin */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VFMAH - ARM_INS_VFMA - vfma${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFMALD - ARM_INS_VFMAL - vfmal.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMALDI - ARM_INS_VFMAL - vfmal.f16	$Vd, $Vn, $Vm$idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* idx */
  { 0 }
}},
{{ /* ARM_VFMALQ - ARM_INS_VFMAL - vfmal.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMALQI - ARM_INS_VFMAL - vfmal.f16	$Vd, $Vn, $Vm$idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* idx */
  { 0 }
}},
{{ /* ARM_VFMAS - ARM_INS_VFMA - vfma${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFMAfd - ARM_INS_VFMA - vfma${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMAfq - ARM_INS_VFMA - vfma${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMAhd - ARM_INS_VFMA - vfma${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMAhq - ARM_INS_VFMA - vfma${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMSD - ARM_INS_VFMS - vfms${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Ddin */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VFMSH - ARM_INS_VFMS - vfms${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFMSLD - ARM_INS_VFMSL - vfmsl.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMSLDI - ARM_INS_VFMSL - vfmsl.f16	$Vd, $Vn, $Vm$idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* idx */
  { 0 }
}},
{{ /* ARM_VFMSLQ - ARM_INS_VFMSL - vfmsl.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMSLQI - ARM_INS_VFMSL - vfmsl.f16	$Vd, $Vn, $Vm$idx */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* idx */
  { 0 }
}},
{{ /* ARM_VFMSS - ARM_INS_VFMS - vfms${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFMSfd - ARM_INS_VFMS - vfms${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMSfq - ARM_INS_VFMS - vfms${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMShd - ARM_INS_VFMS - vfms${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFMShq - ARM_INS_VFMS - vfms${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VFNMAD - ARM_INS_VFNMA - vfnma${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Ddin */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VFNMAH - ARM_INS_VFNMA - vfnma${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFNMAS - ARM_INS_VFNMA - vfnma${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFNMSD - ARM_INS_VFNMS - vfnms${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Ddin */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VFNMSH - ARM_INS_VFNMS - vfnms${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFNMSS - ARM_INS_VFNMS - vfnms${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFP_VMAXNMD - ARM_INS_VMAXNM - vmaxnm.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VFP_VMAXNMH - ARM_INS_VMAXNM - vmaxnm.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFP_VMAXNMS - ARM_INS_VMAXNM - vmaxnm.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFP_VMINNMD - ARM_INS_VMINNM - vminnm.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VFP_VMINNMH - ARM_INS_VMINNM - vminnm.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VFP_VMINNMS - ARM_INS_VMINNM - vminnm.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VGETLNi32 - ARM_INS_VMOV - vmov${p}.32	$R, $V$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* R */
  { CS_OP_REG, CS_AC_READ }, /* V */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VGETLNs16 - ARM_INS_VMOV - vmov${p}.s16	$R, $V$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* R */
  { CS_OP_REG, CS_AC_READ }, /* V */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VGETLNs8 - ARM_INS_VMOV - vmov${p}.s8	$R, $V$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* R */
  { CS_OP_REG, CS_AC_READ }, /* V */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VGETLNu16 - ARM_INS_VMOV - vmov${p}.u16	$R, $V$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* R */
  { CS_OP_REG, CS_AC_READ }, /* V */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VGETLNu8 - ARM_INS_VMOV - vmov${p}.u8	$R, $V$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* R */
  { CS_OP_REG, CS_AC_READ }, /* V */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VHADDsv16i8 - ARM_INS_VHADD - vhadd${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDsv2i32 - ARM_INS_VHADD - vhadd${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDsv4i16 - ARM_INS_VHADD - vhadd${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDsv4i32 - ARM_INS_VHADD - vhadd${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDsv8i16 - ARM_INS_VHADD - vhadd${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDsv8i8 - ARM_INS_VHADD - vhadd${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDuv16i8 - ARM_INS_VHADD - vhadd${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDuv2i32 - ARM_INS_VHADD - vhadd${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDuv4i16 - ARM_INS_VHADD - vhadd${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDuv4i32 - ARM_INS_VHADD - vhadd${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDuv8i16 - ARM_INS_VHADD - vhadd${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHADDuv8i8 - ARM_INS_VHADD - vhadd${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBsv16i8 - ARM_INS_VHSUB - vhsub${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBsv2i32 - ARM_INS_VHSUB - vhsub${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBsv4i16 - ARM_INS_VHSUB - vhsub${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBsv4i32 - ARM_INS_VHSUB - vhsub${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBsv8i16 - ARM_INS_VHSUB - vhsub${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBsv8i8 - ARM_INS_VHSUB - vhsub${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBuv16i8 - ARM_INS_VHSUB - vhsub${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBuv2i32 - ARM_INS_VHSUB - vhsub${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBuv4i16 - ARM_INS_VHSUB - vhsub${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBuv4i32 - ARM_INS_VHSUB - vhsub${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBuv8i16 - ARM_INS_VHSUB - vhsub${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VHSUBuv8i8 - ARM_INS_VHSUB - vhsub${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VINSH - ARM_INS_VINS - vins.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sda */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VJCVT - ARM_INS_VJCVT - vjcvt${p}.s32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VLD1DUPd16 - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPd16wb_fixed - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPd16wb_register - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1DUPd32 - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPd32wb_fixed - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPd32wb_register - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1DUPd8 - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPd8wb_fixed - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPd8wb_register - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1DUPq16 - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPq16wb_fixed - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPq16wb_register - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1DUPq32 - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPq32wb_fixed - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPq32wb_register - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1DUPq8 - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPq8wb_fixed - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1DUPq8wb_register - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1LNd16 - ARM_INS_VLD1 - vld1${p}.16	\{$Vd[$lane]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VLD1LNd16_UPD - ARM_INS_VLD1 - vld1${p}.16	\{$Vd[$lane]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VLD1LNd32 - ARM_INS_VLD1 - vld1${p}.32	\{$Vd[$lane]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VLD1LNd32_UPD - ARM_INS_VLD1 - vld1${p}.32	\{$Vd[$lane]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VLD1LNd8 - ARM_INS_VLD1 - vld1${p}.8	\{$Vd[$lane]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VLD1LNd8_UPD - ARM_INS_VLD1 - vld1${p}.8	\{$Vd[$lane]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VLD1d16 - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d16Q - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d16Qwb_fixed - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d16Qwb_register - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d16T - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d16Twb_fixed - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d16Twb_register - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d16wb_fixed - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d16wb_register - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d32 - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d32Q - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d32Qwb_fixed - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d32Qwb_register - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d32T - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d32Twb_fixed - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d32Twb_register - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d32wb_fixed - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d32wb_register - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d64 - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d64Q - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d64Qwb_fixed - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d64Qwb_register - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d64T - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d64Twb_fixed - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d64Twb_register - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d64wb_fixed - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d64wb_register - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d8 - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d8Q - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d8Qwb_fixed - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d8Qwb_register - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d8T - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d8Twb_fixed - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d8Twb_register - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1d8wb_fixed - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1d8wb_register - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1q16 - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1q16wb_fixed - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1q16wb_register - ARM_INS_VLD1 - vld1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1q32 - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1q32wb_fixed - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1q32wb_register - ARM_INS_VLD1 - vld1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1q64 - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1q64wb_fixed - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1q64wb_register - ARM_INS_VLD1 - vld1${p}.64	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD1q8 - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1q8wb_fixed - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD1q8wb_register - ARM_INS_VLD1 - vld1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2DUPd16 - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd16wb_fixed - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd16wb_register - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2DUPd16x2 - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd16x2wb_fixed - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd16x2wb_register - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2DUPd32 - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd32wb_fixed - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd32wb_register - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2DUPd32x2 - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd32x2wb_fixed - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd32x2wb_register - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2DUPd8 - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd8wb_fixed - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd8wb_register - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2DUPd8x2 - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd8x2wb_fixed - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2DUPd8x2wb_register - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2b16 - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2b16wb_fixed - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2b16wb_register - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2b32 - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2b32wb_fixed - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2b32wb_register - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2b8 - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2b8wb_fixed - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2b8wb_register - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2d16 - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2d16wb_fixed - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2d16wb_register - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2d32 - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2d32wb_fixed - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2d32wb_register - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2d8 - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2d8wb_fixed - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2d8wb_register - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2q16 - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2q16wb_fixed - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2q16wb_register - ARM_INS_VLD2 - vld2${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2q32 - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2q32wb_fixed - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2q32wb_register - ARM_INS_VLD2 - vld2${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD2q8 - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2q8wb_fixed - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD2q8wb_register - ARM_INS_VLD2 - vld2${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPd16 - ARM_INS_VLD3 - vld3${p}.16	\{$Vd[], $dst2[], $dst3[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3DUPd16_UPD - ARM_INS_VLD3 - vld3${p}.16	\{$Vd[], $dst2[], $dst3[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPd32 - ARM_INS_VLD3 - vld3${p}.32	\{$Vd[], $dst2[], $dst3[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3DUPd32_UPD - ARM_INS_VLD3 - vld3${p}.32	\{$Vd[], $dst2[], $dst3[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPd8 - ARM_INS_VLD3 - vld3${p}.8	\{$Vd[], $dst2[], $dst3[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3DUPd8_UPD - ARM_INS_VLD3 - vld3${p}.8	\{$Vd[], $dst2[], $dst3[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPq16 - ARM_INS_VLD3 - vld3${p}.16	\{$Vd[], $dst2[], $dst3[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3DUPq16_UPD - ARM_INS_VLD3 - vld3${p}.16	\{$Vd[], $dst2[], $dst3[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPq32 - ARM_INS_VLD3 - vld3${p}.32	\{$Vd[], $dst2[], $dst3[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3DUPq32_UPD - ARM_INS_VLD3 - vld3${p}.32	\{$Vd[], $dst2[], $dst3[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3DUPq8 - ARM_INS_VLD3 - vld3${p}.8	\{$Vd[], $dst2[], $dst3[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3DUPq8_UPD - ARM_INS_VLD3 - vld3${p}.8	\{$Vd[], $dst2[], $dst3[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3d16 - ARM_INS_VLD3 - vld3${p}.16	\{$Vd, $dst2, $dst3\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3d16_UPD - ARM_INS_VLD3 - vld3${p}.16	\{$Vd, $dst2, $dst3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3d32 - ARM_INS_VLD3 - vld3${p}.32	\{$Vd, $dst2, $dst3\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3d32_UPD - ARM_INS_VLD3 - vld3${p}.32	\{$Vd, $dst2, $dst3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3d8 - ARM_INS_VLD3 - vld3${p}.8	\{$Vd, $dst2, $dst3\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3d8_UPD - ARM_INS_VLD3 - vld3${p}.8	\{$Vd, $dst2, $dst3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3q16 - ARM_INS_VLD3 - vld3${p}.16	\{$Vd, $dst2, $dst3\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3q16_UPD - ARM_INS_VLD3 - vld3${p}.16	\{$Vd, $dst2, $dst3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3q32 - ARM_INS_VLD3 - vld3${p}.32	\{$Vd, $dst2, $dst3\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3q32_UPD - ARM_INS_VLD3 - vld3${p}.32	\{$Vd, $dst2, $dst3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD3q8 - ARM_INS_VLD3 - vld3${p}.8	\{$Vd, $dst2, $dst3\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD3q8_UPD - ARM_INS_VLD3 - vld3${p}.8	\{$Vd, $dst2, $dst3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPd16 - ARM_INS_VLD4 - vld4${p}.16	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4DUPd16_UPD - ARM_INS_VLD4 - vld4${p}.16	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPd32 - ARM_INS_VLD4 - vld4${p}.32	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4DUPd32_UPD - ARM_INS_VLD4 - vld4${p}.32	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPd8 - ARM_INS_VLD4 - vld4${p}.8	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4DUPd8_UPD - ARM_INS_VLD4 - vld4${p}.8	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPq16 - ARM_INS_VLD4 - vld4${p}.16	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4DUPq16_UPD - ARM_INS_VLD4 - vld4${p}.16	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPq32 - ARM_INS_VLD4 - vld4${p}.32	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4DUPq32_UPD - ARM_INS_VLD4 - vld4${p}.32	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4DUPq8 - ARM_INS_VLD4 - vld4${p}.8	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4DUPq8_UPD - ARM_INS_VLD4 - vld4${p}.8	\{$Vd[], $dst2[], $dst3[], $dst4[]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4d16 - ARM_INS_VLD4 - vld4${p}.16	\{$Vd, $dst2, $dst3, $dst4\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4d16_UPD - ARM_INS_VLD4 - vld4${p}.16	\{$Vd, $dst2, $dst3, $dst4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4d32 - ARM_INS_VLD4 - vld4${p}.32	\{$Vd, $dst2, $dst3, $dst4\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4d32_UPD - ARM_INS_VLD4 - vld4${p}.32	\{$Vd, $dst2, $dst3, $dst4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4d8 - ARM_INS_VLD4 - vld4${p}.8	\{$Vd, $dst2, $dst3, $dst4\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4d8_UPD - ARM_INS_VLD4 - vld4${p}.8	\{$Vd, $dst2, $dst3, $dst4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4q16 - ARM_INS_VLD4 - vld4${p}.16	\{$Vd, $dst2, $dst3, $dst4\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4q16_UPD - ARM_INS_VLD4 - vld4${p}.16	\{$Vd, $dst2, $dst3, $dst4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4q32 - ARM_INS_VLD4 - vld4${p}.32	\{$Vd, $dst2, $dst3, $dst4\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4q32_UPD - ARM_INS_VLD4 - vld4${p}.32	\{$Vd, $dst2, $dst3, $dst4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLD4q8 - ARM_INS_VLD4 - vld4${p}.8	\{$Vd, $dst2, $dst3, $dst4\}, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLD4q8_UPD - ARM_INS_VLD4 - vld4${p}.8	\{$Vd, $dst2, $dst3, $dst4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst3 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst4 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_VLDMDDB_UPD - ARM_INS_VLDMDB - vldmdb${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VLDMDIA - ARM_INS_VLDMIA - vldmia${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VLDMDIA_UPD - ARM_INS_VLDMIA - vldmia${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VLDMSDB_UPD - ARM_INS_VLDMDB - vldmdb${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VLDMSIA - ARM_INS_VLDMIA - vldmia${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VLDMSIA_UPD - ARM_INS_VLDMIA - vldmia${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VLDRD - ARM_INS_VLDR - vldr${p}	$Dd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDRH - ARM_INS_VLDR - vldr${p}.16	$Sd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDRS - ARM_INS_VLDR - vldr${p}	$Sd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPCXTNS_off - ARM_INS_VLDR - vldr${p}	fpcxtns, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPCXTNS_post - ARM_INS_VLDR - vldr${p}	fpcxtns, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPCXTNS_pre - ARM_INS_VLDR - vldr${p}	fpcxtns, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPCXTS_off - ARM_INS_VLDR - vldr${p}	fpcxts, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPCXTS_post - ARM_INS_VLDR - vldr${p}	fpcxts, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPCXTS_pre - ARM_INS_VLDR - vldr${p}	fpcxts, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPSCR_NZCVQC_off - ARM_INS_VLDR - vldr${p}	fpscr_nzcvqc, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPSCR_NZCVQC_post - ARM_INS_VLDR - vldr${p}	fpscr_nzcvqc, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPSCR_NZCVQC_pre - ARM_INS_VLDR - vldr${p}	fpscr_nzcvqc, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPSCR_off - ARM_INS_VLDR - vldr${p}	fpscr, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPSCR_post - ARM_INS_VLDR - vldr${p}	fpscr, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_FPSCR_pre - ARM_INS_VLDR - vldr${p}	fpscr, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_P0_off - ARM_INS_VLDR - vldr${p}	p0, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_P0_post - ARM_INS_VLDR - vldr${p}	p0, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_P0_pre - ARM_INS_VLDR - vldr${p}	p0, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* P0 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_VPR_off - ARM_INS_VLDR - vldr${p}	vpr, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_VPR_post - ARM_INS_VLDR - vldr${p}	vpr, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLDR_VPR_pre - ARM_INS_VLDR - vldr${p}	vpr, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VLLDM - ARM_INS_VLLDM - vlldm${p}	$Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VLSTM - ARM_INS_VLSTM - vlstm${p}	$Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_VMAXfd - ARM_INS_VMAX - vmax${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXfq - ARM_INS_VMAX - vmax${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXhd - ARM_INS_VMAX - vmax${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXhq - ARM_INS_VMAX - vmax${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXsv16i8 - ARM_INS_VMAX - vmax${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXsv2i32 - ARM_INS_VMAX - vmax${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXsv4i16 - ARM_INS_VMAX - vmax${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXsv4i32 - ARM_INS_VMAX - vmax${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXsv8i16 - ARM_INS_VMAX - vmax${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXsv8i8 - ARM_INS_VMAX - vmax${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXuv16i8 - ARM_INS_VMAX - vmax${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXuv2i32 - ARM_INS_VMAX - vmax${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXuv4i16 - ARM_INS_VMAX - vmax${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXuv4i32 - ARM_INS_VMAX - vmax${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXuv8i16 - ARM_INS_VMAX - vmax${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMAXuv8i8 - ARM_INS_VMAX - vmax${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINfd - ARM_INS_VMIN - vmin${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINfq - ARM_INS_VMIN - vmin${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINhd - ARM_INS_VMIN - vmin${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINhq - ARM_INS_VMIN - vmin${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINsv16i8 - ARM_INS_VMIN - vmin${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINsv2i32 - ARM_INS_VMIN - vmin${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINsv4i16 - ARM_INS_VMIN - vmin${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINsv4i32 - ARM_INS_VMIN - vmin${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINsv8i16 - ARM_INS_VMIN - vmin${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINsv8i8 - ARM_INS_VMIN - vmin${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINuv16i8 - ARM_INS_VMIN - vmin${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINuv2i32 - ARM_INS_VMIN - vmin${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINuv4i16 - ARM_INS_VMIN - vmin${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINuv4i32 - ARM_INS_VMIN - vmin${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINuv8i16 - ARM_INS_VMIN - vmin${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMINuv8i8 - ARM_INS_VMIN - vmin${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAD - ARM_INS_VMLA - vmla${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Ddin */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VMLAH - ARM_INS_VMLA - vmla${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VMLALslsv2i32 - ARM_INS_VMLAL - vmlal${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLALslsv4i16 - ARM_INS_VMLAL - vmlal${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLALsluv2i32 - ARM_INS_VMLAL - vmlal${p}.u32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLALsluv4i16 - ARM_INS_VMLAL - vmlal${p}.u16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLALsv2i64 - ARM_INS_VMLAL - vmlal${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLALsv4i32 - ARM_INS_VMLAL - vmlal${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLALsv8i16 - ARM_INS_VMLAL - vmlal${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLALuv2i64 - ARM_INS_VMLAL - vmlal${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLALuv4i32 - ARM_INS_VMLAL - vmlal${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLALuv8i16 - ARM_INS_VMLAL - vmlal${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAS - ARM_INS_VMLA - vmla${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VMLAfd - ARM_INS_VMLA - vmla${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAfq - ARM_INS_VMLA - vmla${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAhd - ARM_INS_VMLA - vmla${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAhq - ARM_INS_VMLA - vmla${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAslfd - ARM_INS_VMLA - vmla${p}.f32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLAslfq - ARM_INS_VMLA - vmla${p}.f32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLAslhd - ARM_INS_VMLA - vmla${p}.f16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLAslhq - ARM_INS_VMLA - vmla${p}.f16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLAslv2i32 - ARM_INS_VMLA - vmla${p}.i32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLAslv4i16 - ARM_INS_VMLA - vmla${p}.i16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLAslv4i32 - ARM_INS_VMLA - vmla${p}.i32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLAslv8i16 - ARM_INS_VMLA - vmla${p}.i16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLAv16i8 - ARM_INS_VMLA - vmla${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAv2i32 - ARM_INS_VMLA - vmla${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAv4i16 - ARM_INS_VMLA - vmla${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAv4i32 - ARM_INS_VMLA - vmla${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAv8i16 - ARM_INS_VMLA - vmla${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLAv8i8 - ARM_INS_VMLA - vmla${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSD - ARM_INS_VMLS - vmls${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Ddin */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VMLSH - ARM_INS_VMLS - vmls${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VMLSLslsv2i32 - ARM_INS_VMLSL - vmlsl${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSLslsv4i16 - ARM_INS_VMLSL - vmlsl${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSLsluv2i32 - ARM_INS_VMLSL - vmlsl${p}.u32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSLsluv4i16 - ARM_INS_VMLSL - vmlsl${p}.u16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSLsv2i64 - ARM_INS_VMLSL - vmlsl${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSLsv4i32 - ARM_INS_VMLSL - vmlsl${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSLsv8i16 - ARM_INS_VMLSL - vmlsl${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSLuv2i64 - ARM_INS_VMLSL - vmlsl${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSLuv4i32 - ARM_INS_VMLSL - vmlsl${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSLuv8i16 - ARM_INS_VMLSL - vmlsl${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSS - ARM_INS_VMLS - vmls${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VMLSfd - ARM_INS_VMLS - vmls${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSfq - ARM_INS_VMLS - vmls${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLShd - ARM_INS_VMLS - vmls${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLShq - ARM_INS_VMLS - vmls${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSslfd - ARM_INS_VMLS - vmls${p}.f32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSslfq - ARM_INS_VMLS - vmls${p}.f32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSslhd - ARM_INS_VMLS - vmls${p}.f16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSslhq - ARM_INS_VMLS - vmls${p}.f16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSslv2i32 - ARM_INS_VMLS - vmls${p}.i32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSslv4i16 - ARM_INS_VMLS - vmls${p}.i16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSslv4i32 - ARM_INS_VMLS - vmls${p}.i32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSslv8i16 - ARM_INS_VMLS - vmls${p}.i16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMLSv16i8 - ARM_INS_VMLS - vmls${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSv2i32 - ARM_INS_VMLS - vmls${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSv4i16 - ARM_INS_VMLS - vmls${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSv4i32 - ARM_INS_VMLS - vmls${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSv8i16 - ARM_INS_VMLS - vmls${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMLSv8i8 - ARM_INS_VMLS - vmls${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMMLA - ARM_INS_VMMLA - vmmla.bf16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVD - ARM_INS_VMOV - vmov${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VMOVDRR - ARM_INS_VMOV - vmov${p}	$Dm, $Rt, $Rt2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Dm */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { 0 }
}},
{{ /* ARM_VMOVH - ARM_INS_VMOVX - vmovx.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VMOVHR - ARM_INS_VMOV - vmov${p}.f16	$Sn, $Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMOVLsv2i64 - ARM_INS_VMOVL - vmovl${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVLsv4i32 - ARM_INS_VMOVL - vmovl${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVLsv8i16 - ARM_INS_VMOVL - vmovl${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVLuv2i64 - ARM_INS_VMOVL - vmovl${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVLuv4i32 - ARM_INS_VMOVL - vmovl${p}.u16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVLuv8i16 - ARM_INS_VMOVL - vmovl${p}.u8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVNv2i32 - ARM_INS_VMOVN - vmovn${p}.i64	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVNv4i16 - ARM_INS_VMOVN - vmovn${p}.i32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVNv8i8 - ARM_INS_VMOVN - vmovn${p}.i16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMOVRH - ARM_INS_VMOV - vmov${p}.f16	$Rt, $Sn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { 0 }
}},
{{ /* ARM_VMOVRRD - ARM_INS_VMOV - vmov${p}	$Rt, $Rt2, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VMOVRRS - ARM_INS_VMOV - vmov${p}	$Rt, $Rt2, $src1, $src2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VMOVRS - ARM_INS_VMOV - vmov${p}	$Rt, $Sn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { 0 }
}},
{{ /* ARM_VMOVS - ARM_INS_VMOV - vmov${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VMOVSR - ARM_INS_VMOV - vmov${p}	$Sn, $Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMOVSRR - ARM_INS_VMOV - vmov${p}	$dst1, $dst2, $src1, $src2 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst1 */
  { CS_OP_REG, CS_AC_WRITE }, /* dst2 */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VMOVv16i8 - ARM_INS_VMOV - vmov${p}.i8	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv1i64 - ARM_INS_VMOV - vmov${p}.i64	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv2f32 - ARM_INS_VMOV - vmov${p}.f32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv2i32 - ARM_INS_VMOV - vmov${p}.i32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv2i64 - ARM_INS_VMOV - vmov${p}.i64	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv4f32 - ARM_INS_VMOV - vmov${p}.f32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv4i16 - ARM_INS_VMOV - vmov${p}.i16	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv4i32 - ARM_INS_VMOV - vmov${p}.i32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv8i16 - ARM_INS_VMOV - vmov${p}.i16	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMOVv8i8 - ARM_INS_VMOV - vmov${p}.i8	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMRS - ARM_INS_VMRS - vmrs${p}	$Rt, fpscr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_FPCXTNS - ARM_INS_VMRS - vmrs${p}	$Rt, fpcxtns */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_FPCXTS - ARM_INS_VMRS - vmrs${p}	$Rt, fpcxts */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_FPEXC - ARM_INS_VMRS - vmrs${p}	$Rt, fpexc */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_FPINST - ARM_INS_VMRS - vmrs${p}	$Rt, fpinst */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_FPINST2 - ARM_INS_VMRS - vmrs${p}	$Rt, fpinst2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_FPSCR_NZCVQC - ARM_INS_VMRS - vmrs${p}	$Rt, fpscr_nzcvqc */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* fpscr_in */
  { 0 }
}},
{{ /* ARM_VMRS_FPSID - ARM_INS_VMRS - vmrs${p}	$Rt, fpsid */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_MVFR0 - ARM_INS_VMRS - vmrs${p}	$Rt, mvfr0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_MVFR1 - ARM_INS_VMRS - vmrs${p}	$Rt, mvfr1 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_MVFR2 - ARM_INS_VMRS - vmrs${p}	$Rt, mvfr2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMRS_P0 - ARM_INS_VMRS - vmrs${p}	$Rt, p0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* cond */
  { 0 }
}},
{{ /* ARM_VMRS_VPR - ARM_INS_VMRS - vmrs${p}	$Rt, vpr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR - ARM_INS_VMSR - vmsr${p}	fpscr, $Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_FPCXTNS - ARM_INS_VMSR - vmsr${p}	fpcxtns, $Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_FPCXTS - ARM_INS_VMSR - vmsr${p}	fpcxts, $Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_FPEXC - ARM_INS_VMSR - vmsr${p}	fpexc, $Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_FPINST - ARM_INS_VMSR - vmsr${p}	fpinst, $Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_FPINST2 - ARM_INS_VMSR - vmsr${p}	fpinst2, $Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_FPSCR_NZCVQC - ARM_INS_VMSR - vmsr${p}	fpscr_nzcvqc, $Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* fpscr_out */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_FPSID - ARM_INS_VMSR - vmsr${p}	fpsid, $Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_P0 - ARM_INS_VMSR - vmsr${p}	p0, $Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* cond */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMSR_VPR - ARM_INS_VMSR - vmsr${p}	vpr, $Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { 0 }
}},
{{ /* ARM_VMULD - ARM_INS_VMUL - vmul${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VMULH - ARM_INS_VMUL - vmul${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VMULLp64 - ARM_INS_VMULL - vmull.p64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULLp8 - ARM_INS_VMULL - vmull${p}.p8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULLslsv2i32 - ARM_INS_VMULL - vmull${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULLslsv4i16 - ARM_INS_VMULL - vmull${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULLsluv2i32 - ARM_INS_VMULL - vmull${p}.u32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULLsluv4i16 - ARM_INS_VMULL - vmull${p}.u16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULLsv2i64 - ARM_INS_VMULL - vmull${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULLsv4i32 - ARM_INS_VMULL - vmull${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULLsv8i16 - ARM_INS_VMULL - vmull${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULLuv2i64 - ARM_INS_VMULL - vmull${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULLuv4i32 - ARM_INS_VMULL - vmull${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULLuv8i16 - ARM_INS_VMULL - vmull${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULS - ARM_INS_VMUL - vmul${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VMULfd - ARM_INS_VMUL - vmul${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULfq - ARM_INS_VMUL - vmul${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULhd - ARM_INS_VMUL - vmul${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULhq - ARM_INS_VMUL - vmul${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULpd - ARM_INS_VMUL - vmul${p}.p8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULpq - ARM_INS_VMUL - vmul${p}.p8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULslfd - ARM_INS_VMUL - vmul${p}.f32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULslfq - ARM_INS_VMUL - vmul${p}.f32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULslhd - ARM_INS_VMUL - vmul${p}.f16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULslhq - ARM_INS_VMUL - vmul${p}.f16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULslv2i32 - ARM_INS_VMUL - vmul${p}.i32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULslv4i16 - ARM_INS_VMUL - vmul${p}.i16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULslv4i32 - ARM_INS_VMUL - vmul${p}.i32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULslv8i16 - ARM_INS_VMUL - vmul${p}.i16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VMULv16i8 - ARM_INS_VMUL - vmul${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULv2i32 - ARM_INS_VMUL - vmul${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULv4i16 - ARM_INS_VMUL - vmul${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULv4i32 - ARM_INS_VMUL - vmul${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULv8i16 - ARM_INS_VMUL - vmul${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMULv8i8 - ARM_INS_VMUL - vmul${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMVNd - ARM_INS_VMVN - vmvn${p}	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMVNq - ARM_INS_VMVN - vmvn${p}	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VMVNv2i32 - ARM_INS_VMVN - vmvn${p}.i32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMVNv4i16 - ARM_INS_VMVN - vmvn${p}.i16	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMVNv4i32 - ARM_INS_VMVN - vmvn${p}.i32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VMVNv8i16 - ARM_INS_VMVN - vmvn${p}.i16	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VNEGD - ARM_INS_VNEG - vneg${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VNEGH - ARM_INS_VNEG - vneg${p}.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VNEGS - ARM_INS_VNEG - vneg${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VNEGf32q - ARM_INS_VNEG - vneg${p}.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGfd - ARM_INS_VNEG - vneg${p}.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGhd - ARM_INS_VNEG - vneg${p}.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGhq - ARM_INS_VNEG - vneg${p}.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGs16d - ARM_INS_VNEG - vneg${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGs16q - ARM_INS_VNEG - vneg${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGs32d - ARM_INS_VNEG - vneg${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGs32q - ARM_INS_VNEG - vneg${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGs8d - ARM_INS_VNEG - vneg${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNEGs8q - ARM_INS_VNEG - vneg${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VNMLAD - ARM_INS_VNMLA - vnmla${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Ddin */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VNMLAH - ARM_INS_VNMLA - vnmla${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VNMLAS - ARM_INS_VNMLA - vnmla${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VNMLSD - ARM_INS_VNMLS - vnmls${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Ddin */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VNMLSH - ARM_INS_VNMLS - vnmls${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VNMLSS - ARM_INS_VNMLS - vnmls${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sdin */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VNMULD - ARM_INS_VNMUL - vnmul${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VNMULH - ARM_INS_VNMUL - vnmul${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VNMULS - ARM_INS_VNMUL - vnmul${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VORNd - ARM_INS_VORN - vorn${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VORNq - ARM_INS_VORN - vorn${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VORRd - ARM_INS_VORR - vorr${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VORRiv2i32 - ARM_INS_VORR - vorr${p}.i32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_VORRiv4i16 - ARM_INS_VORR - vorr${p}.i16	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_VORRiv4i32 - ARM_INS_VORR - vorr${p}.i32	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_VORRiv8i16 - ARM_INS_VORR - vorr${p}.i16	$Vd, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { 0 }
}},
{{ /* ARM_VORRq - ARM_INS_VORR - vorr${p}	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALsv16i8 - ARM_INS_VPADAL - vpadal${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALsv2i32 - ARM_INS_VPADAL - vpadal${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALsv4i16 - ARM_INS_VPADAL - vpadal${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALsv4i32 - ARM_INS_VPADAL - vpadal${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALsv8i16 - ARM_INS_VPADAL - vpadal${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALsv8i8 - ARM_INS_VPADAL - vpadal${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALuv16i8 - ARM_INS_VPADAL - vpadal${p}.u8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALuv2i32 - ARM_INS_VPADAL - vpadal${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALuv4i16 - ARM_INS_VPADAL - vpadal${p}.u16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALuv4i32 - ARM_INS_VPADAL - vpadal${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALuv8i16 - ARM_INS_VPADAL - vpadal${p}.u16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADALuv8i8 - ARM_INS_VPADAL - vpadal${p}.u8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLsv16i8 - ARM_INS_VPADDL - vpaddl${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLsv2i32 - ARM_INS_VPADDL - vpaddl${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLsv4i16 - ARM_INS_VPADDL - vpaddl${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLsv4i32 - ARM_INS_VPADDL - vpaddl${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLsv8i16 - ARM_INS_VPADDL - vpaddl${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLsv8i8 - ARM_INS_VPADDL - vpaddl${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLuv16i8 - ARM_INS_VPADDL - vpaddl${p}.u8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLuv2i32 - ARM_INS_VPADDL - vpaddl${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLuv4i16 - ARM_INS_VPADDL - vpaddl${p}.u16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLuv4i32 - ARM_INS_VPADDL - vpaddl${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLuv8i16 - ARM_INS_VPADDL - vpaddl${p}.u16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDLuv8i8 - ARM_INS_VPADDL - vpaddl${p}.u8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDf - ARM_INS_VPADD - vpadd${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDh - ARM_INS_VPADD - vpadd${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDi16 - ARM_INS_VPADD - vpadd${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDi32 - ARM_INS_VPADD - vpadd${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPADDi8 - ARM_INS_VPADD - vpadd${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMAXf - ARM_INS_VPMAX - vpmax${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMAXh - ARM_INS_VPMAX - vpmax${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMAXs16 - ARM_INS_VPMAX - vpmax${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMAXs32 - ARM_INS_VPMAX - vpmax${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMAXs8 - ARM_INS_VPMAX - vpmax${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMAXu16 - ARM_INS_VPMAX - vpmax${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMAXu32 - ARM_INS_VPMAX - vpmax${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMAXu8 - ARM_INS_VPMAX - vpmax${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMINf - ARM_INS_VPMIN - vpmin${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMINh - ARM_INS_VPMIN - vpmin${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMINs16 - ARM_INS_VPMIN - vpmin${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMINs32 - ARM_INS_VPMIN - vpmin${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMINs8 - ARM_INS_VPMIN - vpmin${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMINu16 - ARM_INS_VPMIN - vpmin${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMINu32 - ARM_INS_VPMIN - vpmin${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VPMINu8 - ARM_INS_VPMIN - vpmin${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQABSv16i8 - ARM_INS_VQABS - vqabs${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQABSv2i32 - ARM_INS_VQABS - vqabs${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQABSv4i16 - ARM_INS_VQABS - vqabs${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQABSv4i32 - ARM_INS_VQABS - vqabs${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQABSv8i16 - ARM_INS_VQABS - vqabs${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQABSv8i8 - ARM_INS_VQABS - vqabs${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDsv16i8 - ARM_INS_VQADD - vqadd${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDsv1i64 - ARM_INS_VQADD - vqadd${p}.s64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDsv2i32 - ARM_INS_VQADD - vqadd${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDsv2i64 - ARM_INS_VQADD - vqadd${p}.s64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDsv4i16 - ARM_INS_VQADD - vqadd${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDsv4i32 - ARM_INS_VQADD - vqadd${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDsv8i16 - ARM_INS_VQADD - vqadd${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDsv8i8 - ARM_INS_VQADD - vqadd${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDuv16i8 - ARM_INS_VQADD - vqadd${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDuv1i64 - ARM_INS_VQADD - vqadd${p}.u64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDuv2i32 - ARM_INS_VQADD - vqadd${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDuv2i64 - ARM_INS_VQADD - vqadd${p}.u64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDuv4i16 - ARM_INS_VQADD - vqadd${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDuv4i32 - ARM_INS_VQADD - vqadd${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDuv8i16 - ARM_INS_VQADD - vqadd${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQADDuv8i8 - ARM_INS_VQADD - vqadd${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMLALslv2i32 - ARM_INS_VQDMLAL - vqdmlal${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMLALslv4i16 - ARM_INS_VQDMLAL - vqdmlal${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMLALv2i64 - ARM_INS_VQDMLAL - vqdmlal${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMLALv4i32 - ARM_INS_VQDMLAL - vqdmlal${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMLSLslv2i32 - ARM_INS_VQDMLSL - vqdmlsl${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMLSLslv4i16 - ARM_INS_VQDMLSL - vqdmlsl${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMLSLv2i64 - ARM_INS_VQDMLSL - vqdmlsl${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMLSLv4i32 - ARM_INS_VQDMLSL - vqdmlsl${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMULHslv2i32 - ARM_INS_VQDMULH - vqdmulh${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMULHslv4i16 - ARM_INS_VQDMULH - vqdmulh${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMULHslv4i32 - ARM_INS_VQDMULH - vqdmulh${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMULHslv8i16 - ARM_INS_VQDMULH - vqdmulh${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMULHv2i32 - ARM_INS_VQDMULH - vqdmulh${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMULHv4i16 - ARM_INS_VQDMULH - vqdmulh${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMULHv4i32 - ARM_INS_VQDMULH - vqdmulh${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMULHv8i16 - ARM_INS_VQDMULH - vqdmulh${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMULLslv2i32 - ARM_INS_VQDMULL - vqdmull${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMULLslv4i16 - ARM_INS_VQDMULL - vqdmull${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQDMULLv2i64 - ARM_INS_VQDMULL - vqdmull${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQDMULLv4i32 - ARM_INS_VQDMULL - vqdmull${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNsuv2i32 - ARM_INS_VQMOVUN - vqmovun${p}.s64	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNsuv4i16 - ARM_INS_VQMOVUN - vqmovun${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNsuv8i8 - ARM_INS_VQMOVUN - vqmovun${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNsv2i32 - ARM_INS_VQMOVN - vqmovn${p}.s64	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNsv4i16 - ARM_INS_VQMOVN - vqmovn${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNsv8i8 - ARM_INS_VQMOVN - vqmovn${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNuv2i32 - ARM_INS_VQMOVN - vqmovn${p}.u64	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNuv4i16 - ARM_INS_VQMOVN - vqmovn${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQMOVNuv8i8 - ARM_INS_VQMOVN - vqmovn${p}.u16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQNEGv16i8 - ARM_INS_VQNEG - vqneg${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQNEGv2i32 - ARM_INS_VQNEG - vqneg${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQNEGv4i16 - ARM_INS_VQNEG - vqneg${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQNEGv4i32 - ARM_INS_VQNEG - vqneg${p}.s32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQNEGv8i16 - ARM_INS_VQNEG - vqneg${p}.s16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQNEGv8i8 - ARM_INS_VQNEG - vqneg${p}.s8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMLAHslv2i32 - ARM_INS_VQRDMLAH - vqrdmlah${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMLAHslv4i16 - ARM_INS_VQRDMLAH - vqrdmlah${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMLAHslv4i32 - ARM_INS_VQRDMLAH - vqrdmlah${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMLAHslv8i16 - ARM_INS_VQRDMLAH - vqrdmlah${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMLAHv2i32 - ARM_INS_VQRDMLAH - vqrdmlah${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMLAHv4i16 - ARM_INS_VQRDMLAH - vqrdmlah${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMLAHv4i32 - ARM_INS_VQRDMLAH - vqrdmlah${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMLAHv8i16 - ARM_INS_VQRDMLAH - vqrdmlah${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMLSHslv2i32 - ARM_INS_VQRDMLSH - vqrdmlsh${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMLSHslv4i16 - ARM_INS_VQRDMLSH - vqrdmlsh${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMLSHslv4i32 - ARM_INS_VQRDMLSH - vqrdmlsh${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMLSHslv8i16 - ARM_INS_VQRDMLSH - vqrdmlsh${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMLSHv2i32 - ARM_INS_VQRDMLSH - vqrdmlsh${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMLSHv4i16 - ARM_INS_VQRDMLSH - vqrdmlsh${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMLSHv4i32 - ARM_INS_VQRDMLSH - vqrdmlsh${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMLSHv8i16 - ARM_INS_VQRDMLSH - vqrdmlsh${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMULHslv2i32 - ARM_INS_VQRDMULH - vqrdmulh${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMULHslv4i16 - ARM_INS_VQRDMULH - vqrdmulh${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMULHslv4i32 - ARM_INS_VQRDMULH - vqrdmulh${p}.s32	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMULHslv8i16 - ARM_INS_VQRDMULH - vqrdmulh${p}.s16	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VQRDMULHv2i32 - ARM_INS_VQRDMULH - vqrdmulh${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMULHv4i16 - ARM_INS_VQRDMULH - vqrdmulh${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMULHv4i32 - ARM_INS_VQRDMULH - vqrdmulh${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRDMULHv8i16 - ARM_INS_VQRDMULH - vqrdmulh${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQRSHLsv16i8 - ARM_INS_VQRSHL - vqrshl${p}.s8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLsv1i64 - ARM_INS_VQRSHL - vqrshl${p}.s64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLsv2i32 - ARM_INS_VQRSHL - vqrshl${p}.s32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLsv2i64 - ARM_INS_VQRSHL - vqrshl${p}.s64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLsv4i16 - ARM_INS_VQRSHL - vqrshl${p}.s16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLsv4i32 - ARM_INS_VQRSHL - vqrshl${p}.s32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLsv8i16 - ARM_INS_VQRSHL - vqrshl${p}.s16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLsv8i8 - ARM_INS_VQRSHL - vqrshl${p}.s8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLuv16i8 - ARM_INS_VQRSHL - vqrshl${p}.u8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLuv1i64 - ARM_INS_VQRSHL - vqrshl${p}.u64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLuv2i32 - ARM_INS_VQRSHL - vqrshl${p}.u32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLuv2i64 - ARM_INS_VQRSHL - vqrshl${p}.u64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLuv4i16 - ARM_INS_VQRSHL - vqrshl${p}.u16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLuv4i32 - ARM_INS_VQRSHL - vqrshl${p}.u32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLuv8i16 - ARM_INS_VQRSHL - vqrshl${p}.u16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHLuv8i8 - ARM_INS_VQRSHL - vqrshl${p}.u8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQRSHRNsv2i32 - ARM_INS_VQRSHRN - vqrshrn${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQRSHRNsv4i16 - ARM_INS_VQRSHRN - vqrshrn${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQRSHRNsv8i8 - ARM_INS_VQRSHRN - vqrshrn${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQRSHRNuv2i32 - ARM_INS_VQRSHRN - vqrshrn${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQRSHRNuv4i16 - ARM_INS_VQRSHRN - vqrshrn${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQRSHRNuv8i8 - ARM_INS_VQRSHRN - vqrshrn${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQRSHRUNv2i32 - ARM_INS_VQRSHRUN - vqrshrun${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQRSHRUNv4i16 - ARM_INS_VQRSHRUN - vqrshrun${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQRSHRUNv8i8 - ARM_INS_VQRSHRUN - vqrshrun${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsiv16i8 - ARM_INS_VQSHL - vqshl${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsiv1i64 - ARM_INS_VQSHL - vqshl${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsiv2i32 - ARM_INS_VQSHL - vqshl${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsiv2i64 - ARM_INS_VQSHL - vqshl${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsiv4i16 - ARM_INS_VQSHL - vqshl${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsiv4i32 - ARM_INS_VQSHL - vqshl${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsiv8i16 - ARM_INS_VQSHL - vqshl${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsiv8i8 - ARM_INS_VQSHL - vqshl${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsuv16i8 - ARM_INS_VQSHLU - vqshlu${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsuv1i64 - ARM_INS_VQSHLU - vqshlu${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsuv2i32 - ARM_INS_VQSHLU - vqshlu${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsuv2i64 - ARM_INS_VQSHLU - vqshlu${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsuv4i16 - ARM_INS_VQSHLU - vqshlu${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsuv4i32 - ARM_INS_VQSHLU - vqshlu${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsuv8i16 - ARM_INS_VQSHLU - vqshlu${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsuv8i8 - ARM_INS_VQSHLU - vqshlu${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLsv16i8 - ARM_INS_VQSHL - vqshl${p}.s8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLsv1i64 - ARM_INS_VQSHL - vqshl${p}.s64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLsv2i32 - ARM_INS_VQSHL - vqshl${p}.s32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLsv2i64 - ARM_INS_VQSHL - vqshl${p}.s64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLsv4i16 - ARM_INS_VQSHL - vqshl${p}.s16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLsv4i32 - ARM_INS_VQSHL - vqshl${p}.s32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLsv8i16 - ARM_INS_VQSHL - vqshl${p}.s16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLsv8i8 - ARM_INS_VQSHL - vqshl${p}.s8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLuiv16i8 - ARM_INS_VQSHL - vqshl${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLuiv1i64 - ARM_INS_VQSHL - vqshl${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLuiv2i32 - ARM_INS_VQSHL - vqshl${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLuiv2i64 - ARM_INS_VQSHL - vqshl${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLuiv4i16 - ARM_INS_VQSHL - vqshl${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLuiv4i32 - ARM_INS_VQSHL - vqshl${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLuiv8i16 - ARM_INS_VQSHL - vqshl${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLuiv8i8 - ARM_INS_VQSHL - vqshl${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHLuv16i8 - ARM_INS_VQSHL - vqshl${p}.u8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLuv1i64 - ARM_INS_VQSHL - vqshl${p}.u64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLuv2i32 - ARM_INS_VQSHL - vqshl${p}.u32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLuv2i64 - ARM_INS_VQSHL - vqshl${p}.u64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLuv4i16 - ARM_INS_VQSHL - vqshl${p}.u16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLuv4i32 - ARM_INS_VQSHL - vqshl${p}.u32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLuv8i16 - ARM_INS_VQSHL - vqshl${p}.u16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHLuv8i8 - ARM_INS_VQSHL - vqshl${p}.u8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VQSHRNsv2i32 - ARM_INS_VQSHRN - vqshrn${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHRNsv4i16 - ARM_INS_VQSHRN - vqshrn${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHRNsv8i8 - ARM_INS_VQSHRN - vqshrn${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHRNuv2i32 - ARM_INS_VQSHRN - vqshrn${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHRNuv4i16 - ARM_INS_VQSHRN - vqshrn${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHRNuv8i8 - ARM_INS_VQSHRN - vqshrn${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHRUNv2i32 - ARM_INS_VQSHRUN - vqshrun${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHRUNv4i16 - ARM_INS_VQSHRUN - vqshrun${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSHRUNv8i8 - ARM_INS_VQSHRUN - vqshrun${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VQSUBsv16i8 - ARM_INS_VQSUB - vqsub${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBsv1i64 - ARM_INS_VQSUB - vqsub${p}.s64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBsv2i32 - ARM_INS_VQSUB - vqsub${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBsv2i64 - ARM_INS_VQSUB - vqsub${p}.s64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBsv4i16 - ARM_INS_VQSUB - vqsub${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBsv4i32 - ARM_INS_VQSUB - vqsub${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBsv8i16 - ARM_INS_VQSUB - vqsub${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBsv8i8 - ARM_INS_VQSUB - vqsub${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBuv16i8 - ARM_INS_VQSUB - vqsub${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBuv1i64 - ARM_INS_VQSUB - vqsub${p}.u64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBuv2i32 - ARM_INS_VQSUB - vqsub${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBuv2i64 - ARM_INS_VQSUB - vqsub${p}.u64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBuv4i16 - ARM_INS_VQSUB - vqsub${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBuv4i32 - ARM_INS_VQSUB - vqsub${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBuv8i16 - ARM_INS_VQSUB - vqsub${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VQSUBuv8i8 - ARM_INS_VQSUB - vqsub${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRADDHNv2i32 - ARM_INS_VRADDHN - vraddhn${p}.i64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRADDHNv4i16 - ARM_INS_VRADDHN - vraddhn${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRADDHNv8i8 - ARM_INS_VRADDHN - vraddhn${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPEd - ARM_INS_VRECPE - vrecpe${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPEfd - ARM_INS_VRECPE - vrecpe${p}.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPEfq - ARM_INS_VRECPE - vrecpe${p}.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPEhd - ARM_INS_VRECPE - vrecpe${p}.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPEhq - ARM_INS_VRECPE - vrecpe${p}.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPEq - ARM_INS_VRECPE - vrecpe${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPSfd - ARM_INS_VRECPS - vrecps${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPSfq - ARM_INS_VRECPS - vrecps${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPShd - ARM_INS_VRECPS - vrecps${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRECPShq - ARM_INS_VRECPS - vrecps${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV16d8 - ARM_INS_VREV16 - vrev16${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV16q8 - ARM_INS_VREV16 - vrev16${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV32d16 - ARM_INS_VREV32 - vrev32${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV32d8 - ARM_INS_VREV32 - vrev32${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV32q16 - ARM_INS_VREV32 - vrev32${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV32q8 - ARM_INS_VREV32 - vrev32${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV64d16 - ARM_INS_VREV64 - vrev64${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV64d32 - ARM_INS_VREV64 - vrev64${p}.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV64d8 - ARM_INS_VREV64 - vrev64${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV64q16 - ARM_INS_VREV64 - vrev64${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV64q32 - ARM_INS_VREV64 - vrev64${p}.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VREV64q8 - ARM_INS_VREV64 - vrev64${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDsv16i8 - ARM_INS_VRHADD - vrhadd${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDsv2i32 - ARM_INS_VRHADD - vrhadd${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDsv4i16 - ARM_INS_VRHADD - vrhadd${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDsv4i32 - ARM_INS_VRHADD - vrhadd${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDsv8i16 - ARM_INS_VRHADD - vrhadd${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDsv8i8 - ARM_INS_VRHADD - vrhadd${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDuv16i8 - ARM_INS_VRHADD - vrhadd${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDuv2i32 - ARM_INS_VRHADD - vrhadd${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDuv4i16 - ARM_INS_VRHADD - vrhadd${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDuv4i32 - ARM_INS_VRHADD - vrhadd${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDuv8i16 - ARM_INS_VRHADD - vrhadd${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRHADDuv8i8 - ARM_INS_VRHADD - vrhadd${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTAD - ARM_INS_VRINTA - vrinta.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VRINTAH - ARM_INS_VRINTA - vrinta.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTANDf - ARM_INS_VRINTA - vrinta.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTANDh - ARM_INS_VRINTA - vrinta.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTANQf - ARM_INS_VRINTA - vrinta.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTANQh - ARM_INS_VRINTA - vrinta.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTAS - ARM_INS_VRINTA - vrinta.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTMD - ARM_INS_VRINTM - vrintm.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VRINTMH - ARM_INS_VRINTM - vrintm.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTMNDf - ARM_INS_VRINTM - vrintm.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTMNDh - ARM_INS_VRINTM - vrintm.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTMNQf - ARM_INS_VRINTM - vrintm.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTMNQh - ARM_INS_VRINTM - vrintm.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTMS - ARM_INS_VRINTM - vrintm.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTND - ARM_INS_VRINTN - vrintn.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VRINTNH - ARM_INS_VRINTN - vrintn.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTNNDf - ARM_INS_VRINTN - vrintn.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTNNDh - ARM_INS_VRINTN - vrintn.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTNNQf - ARM_INS_VRINTN - vrintn.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTNNQh - ARM_INS_VRINTN - vrintn.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTNS - ARM_INS_VRINTN - vrintn.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTPD - ARM_INS_VRINTP - vrintp.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VRINTPH - ARM_INS_VRINTP - vrintp.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTPNDf - ARM_INS_VRINTP - vrintp.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTPNDh - ARM_INS_VRINTP - vrintp.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTPNQf - ARM_INS_VRINTP - vrintp.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTPNQh - ARM_INS_VRINTP - vrintp.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTPS - ARM_INS_VRINTP - vrintp.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTRD - ARM_INS_VRINTR - vrintr${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VRINTRH - ARM_INS_VRINTR - vrintr${p}.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTRS - ARM_INS_VRINTR - vrintr${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTXD - ARM_INS_VRINTX - vrintx${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VRINTXH - ARM_INS_VRINTX - vrintx${p}.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTXNDf - ARM_INS_VRINTX - vrintx.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTXNDh - ARM_INS_VRINTX - vrintx.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTXNQf - ARM_INS_VRINTX - vrintx.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTXNQh - ARM_INS_VRINTX - vrintx.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTXS - ARM_INS_VRINTX - vrintx${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTZD - ARM_INS_VRINTZ - vrintz${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VRINTZH - ARM_INS_VRINTZ - vrintz${p}.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRINTZNDf - ARM_INS_VRINTZ - vrintz.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTZNDh - ARM_INS_VRINTZ - vrintz.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTZNQf - ARM_INS_VRINTZ - vrintz.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTZNQh - ARM_INS_VRINTZ - vrintz.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRINTZS - ARM_INS_VRINTZ - vrintz${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VRSHLsv16i8 - ARM_INS_VRSHL - vrshl${p}.s8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLsv1i64 - ARM_INS_VRSHL - vrshl${p}.s64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLsv2i32 - ARM_INS_VRSHL - vrshl${p}.s32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLsv2i64 - ARM_INS_VRSHL - vrshl${p}.s64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLsv4i16 - ARM_INS_VRSHL - vrshl${p}.s16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLsv4i32 - ARM_INS_VRSHL - vrshl${p}.s32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLsv8i16 - ARM_INS_VRSHL - vrshl${p}.s16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLsv8i8 - ARM_INS_VRSHL - vrshl${p}.s8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLuv16i8 - ARM_INS_VRSHL - vrshl${p}.u8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLuv1i64 - ARM_INS_VRSHL - vrshl${p}.u64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLuv2i32 - ARM_INS_VRSHL - vrshl${p}.u32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLuv2i64 - ARM_INS_VRSHL - vrshl${p}.u64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLuv4i16 - ARM_INS_VRSHL - vrshl${p}.u16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLuv4i32 - ARM_INS_VRSHL - vrshl${p}.u32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLuv8i16 - ARM_INS_VRSHL - vrshl${p}.u16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHLuv8i8 - ARM_INS_VRSHL - vrshl${p}.u8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VRSHRNv2i32 - ARM_INS_VRSHRN - vrshrn${p}.i64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRNv4i16 - ARM_INS_VRSHRN - vrshrn${p}.i32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRNv8i8 - ARM_INS_VRSHRN - vrshrn${p}.i16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRsv16i8 - ARM_INS_VRSHR - vrshr${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRsv1i64 - ARM_INS_VRSHR - vrshr${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRsv2i32 - ARM_INS_VRSHR - vrshr${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRsv2i64 - ARM_INS_VRSHR - vrshr${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRsv4i16 - ARM_INS_VRSHR - vrshr${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRsv4i32 - ARM_INS_VRSHR - vrshr${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRsv8i16 - ARM_INS_VRSHR - vrshr${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRsv8i8 - ARM_INS_VRSHR - vrshr${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRuv16i8 - ARM_INS_VRSHR - vrshr${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRuv1i64 - ARM_INS_VRSHR - vrshr${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRuv2i32 - ARM_INS_VRSHR - vrshr${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRuv2i64 - ARM_INS_VRSHR - vrshr${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRuv4i16 - ARM_INS_VRSHR - vrshr${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRuv4i32 - ARM_INS_VRSHR - vrshr${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRuv8i16 - ARM_INS_VRSHR - vrshr${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSHRuv8i8 - ARM_INS_VRSHR - vrshr${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSQRTEd - ARM_INS_VRSQRTE - vrsqrte${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTEfd - ARM_INS_VRSQRTE - vrsqrte${p}.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTEfq - ARM_INS_VRSQRTE - vrsqrte${p}.f32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTEhd - ARM_INS_VRSQRTE - vrsqrte${p}.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTEhq - ARM_INS_VRSQRTE - vrsqrte${p}.f16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTEq - ARM_INS_VRSQRTE - vrsqrte${p}.u32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTSfd - ARM_INS_VRSQRTS - vrsqrts${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTSfq - ARM_INS_VRSQRTS - vrsqrts${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTShd - ARM_INS_VRSQRTS - vrsqrts${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSQRTShq - ARM_INS_VRSQRTS - vrsqrts${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSRAsv16i8 - ARM_INS_VRSRA - vrsra${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAsv1i64 - ARM_INS_VRSRA - vrsra${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAsv2i32 - ARM_INS_VRSRA - vrsra${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAsv2i64 - ARM_INS_VRSRA - vrsra${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAsv4i16 - ARM_INS_VRSRA - vrsra${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAsv4i32 - ARM_INS_VRSRA - vrsra${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAsv8i16 - ARM_INS_VRSRA - vrsra${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAsv8i8 - ARM_INS_VRSRA - vrsra${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAuv16i8 - ARM_INS_VRSRA - vrsra${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAuv1i64 - ARM_INS_VRSRA - vrsra${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAuv2i32 - ARM_INS_VRSRA - vrsra${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAuv2i64 - ARM_INS_VRSRA - vrsra${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAuv4i16 - ARM_INS_VRSRA - vrsra${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAuv4i32 - ARM_INS_VRSRA - vrsra${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAuv8i16 - ARM_INS_VRSRA - vrsra${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSRAuv8i8 - ARM_INS_VRSRA - vrsra${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VRSUBHNv2i32 - ARM_INS_VRSUBHN - vrsubhn${p}.i64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSUBHNv4i16 - ARM_INS_VRSUBHN - vrsubhn${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VRSUBHNv8i8 - ARM_INS_VRSUBHN - vrsubhn${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSCCLRMD - ARM_INS_VSCCLRM - vscclrm{$p}	$regs */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VSCCLRMS - ARM_INS_VSCCLRM - vscclrm{$p}	$regs */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VSDOTD - ARM_INS_VSDOT - vsdot.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSDOTDI - ARM_INS_VSDOT - vsdot.s8	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VSDOTQ - ARM_INS_VSDOT - vsdot.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSDOTQI - ARM_INS_VSDOT - vsdot.s8	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VSELEQD - ARM_INS_VSELEQ - vseleq.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VSELEQH - ARM_INS_VSELEQ - vseleq.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSELEQS - ARM_INS_VSELEQ - vseleq.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSELGED - ARM_INS_VSELGE - vselge.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VSELGEH - ARM_INS_VSELGE - vselge.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSELGES - ARM_INS_VSELGE - vselge.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSELGTD - ARM_INS_VSELGT - vselgt.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VSELGTH - ARM_INS_VSELGT - vselgt.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSELGTS - ARM_INS_VSELGT - vselgt.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSELVSD - ARM_INS_VSELVS - vselvs.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VSELVSH - ARM_INS_VSELVS - vselvs.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSELVSS - ARM_INS_VSELVS - vselvs.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSETLNi16 - ARM_INS_VMOV - vmov${p}.16	$V$lane, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VSETLNi32 - ARM_INS_VMOV - vmov${p}.32	$V$lane, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VSETLNi8 - ARM_INS_VMOV - vmov${p}.8	$V$lane, $R */
  { CS_OP_REG, CS_AC_WRITE }, /* V */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* R */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VSHLLi16 - ARM_INS_VSHLL - vshll${p}.i16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLLi32 - ARM_INS_VSHLL - vshll${p}.i32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLLi8 - ARM_INS_VSHLL - vshll${p}.i8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLLsv2i64 - ARM_INS_VSHLL - vshll${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLLsv4i32 - ARM_INS_VSHLL - vshll${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLLsv8i16 - ARM_INS_VSHLL - vshll${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLLuv2i64 - ARM_INS_VSHLL - vshll${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLLuv4i32 - ARM_INS_VSHLL - vshll${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLLuv8i16 - ARM_INS_VSHLL - vshll${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLiv16i8 - ARM_INS_VSHL - vshl${p}.i8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLiv1i64 - ARM_INS_VSHL - vshl${p}.i64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLiv2i32 - ARM_INS_VSHL - vshl${p}.i32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLiv2i64 - ARM_INS_VSHL - vshl${p}.i64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLiv4i16 - ARM_INS_VSHL - vshl${p}.i16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLiv4i32 - ARM_INS_VSHL - vshl${p}.i32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLiv8i16 - ARM_INS_VSHL - vshl${p}.i16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLiv8i8 - ARM_INS_VSHL - vshl${p}.i8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHLsv16i8 - ARM_INS_VSHL - vshl${p}.s8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLsv1i64 - ARM_INS_VSHL - vshl${p}.s64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLsv2i32 - ARM_INS_VSHL - vshl${p}.s32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLsv2i64 - ARM_INS_VSHL - vshl${p}.s64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLsv4i16 - ARM_INS_VSHL - vshl${p}.s16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLsv4i32 - ARM_INS_VSHL - vshl${p}.s32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLsv8i16 - ARM_INS_VSHL - vshl${p}.s16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLsv8i8 - ARM_INS_VSHL - vshl${p}.s8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLuv16i8 - ARM_INS_VSHL - vshl${p}.u8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLuv1i64 - ARM_INS_VSHL - vshl${p}.u64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLuv2i32 - ARM_INS_VSHL - vshl${p}.u32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLuv2i64 - ARM_INS_VSHL - vshl${p}.u64	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLuv4i16 - ARM_INS_VSHL - vshl${p}.u16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLuv4i32 - ARM_INS_VSHL - vshl${p}.u32	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLuv8i16 - ARM_INS_VSHL - vshl${p}.u16	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHLuv8i8 - ARM_INS_VSHL - vshl${p}.u8	$Vd, $Vm, $Vn */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { 0 }
}},
{{ /* ARM_VSHRNv2i32 - ARM_INS_VSHRN - vshrn${p}.i64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRNv4i16 - ARM_INS_VSHRN - vshrn${p}.i32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRNv8i8 - ARM_INS_VSHRN - vshrn${p}.i16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRsv16i8 - ARM_INS_VSHR - vshr${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRsv1i64 - ARM_INS_VSHR - vshr${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRsv2i32 - ARM_INS_VSHR - vshr${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRsv2i64 - ARM_INS_VSHR - vshr${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRsv4i16 - ARM_INS_VSHR - vshr${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRsv4i32 - ARM_INS_VSHR - vshr${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRsv8i16 - ARM_INS_VSHR - vshr${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRsv8i8 - ARM_INS_VSHR - vshr${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRuv16i8 - ARM_INS_VSHR - vshr${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRuv1i64 - ARM_INS_VSHR - vshr${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRuv2i32 - ARM_INS_VSHR - vshr${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRuv2i64 - ARM_INS_VSHR - vshr${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRuv4i16 - ARM_INS_VSHR - vshr${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRuv4i32 - ARM_INS_VSHR - vshr${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRuv8i16 - ARM_INS_VSHR - vshr${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHRuv8i8 - ARM_INS_VSHR - vshr${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSHTOD - ARM_INS_VCVT - vcvt${p}.f64.s16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VSHTOH - ARM_INS_VCVT - vcvt${p}.f16.s16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VSHTOS - ARM_INS_VCVT - vcvt${p}.f32.s16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VSITOD - ARM_INS_VCVT - vcvt${p}.f64.s32	$Dd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSITOH - ARM_INS_VCVT - vcvt${p}.f16.s32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSITOS - ARM_INS_VCVT - vcvt${p}.f32.s32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSLIv16i8 - ARM_INS_VSLI - vsli${p}.8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSLIv1i64 - ARM_INS_VSLI - vsli${p}.64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSLIv2i32 - ARM_INS_VSLI - vsli${p}.32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSLIv2i64 - ARM_INS_VSLI - vsli${p}.64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSLIv4i16 - ARM_INS_VSLI - vsli${p}.16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSLIv4i32 - ARM_INS_VSLI - vsli${p}.32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSLIv8i16 - ARM_INS_VSLI - vsli${p}.16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSLIv8i8 - ARM_INS_VSLI - vsli${p}.8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSLTOD - ARM_INS_VCVT - vcvt${p}.f64.s32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VSLTOH - ARM_INS_VCVT - vcvt${p}.f16.s32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VSLTOS - ARM_INS_VCVT - vcvt${p}.f32.s32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VSMMLA - ARM_INS_VSMMLA - vsmmla.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSQRTD - ARM_INS_VSQRT - vsqrt${p}.f64	$Dd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VSQRTH - ARM_INS_VSQRT - vsqrt${p}.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSQRTS - ARM_INS_VSQRT - vsqrt${p}.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSRAsv16i8 - ARM_INS_VSRA - vsra${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAsv1i64 - ARM_INS_VSRA - vsra${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAsv2i32 - ARM_INS_VSRA - vsra${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAsv2i64 - ARM_INS_VSRA - vsra${p}.s64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAsv4i16 - ARM_INS_VSRA - vsra${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAsv4i32 - ARM_INS_VSRA - vsra${p}.s32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAsv8i16 - ARM_INS_VSRA - vsra${p}.s16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAsv8i8 - ARM_INS_VSRA - vsra${p}.s8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAuv16i8 - ARM_INS_VSRA - vsra${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAuv1i64 - ARM_INS_VSRA - vsra${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAuv2i32 - ARM_INS_VSRA - vsra${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAuv2i64 - ARM_INS_VSRA - vsra${p}.u64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAuv4i16 - ARM_INS_VSRA - vsra${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAuv4i32 - ARM_INS_VSRA - vsra${p}.u32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAuv8i16 - ARM_INS_VSRA - vsra${p}.u16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRAuv8i8 - ARM_INS_VSRA - vsra${p}.u8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRIv16i8 - ARM_INS_VSRI - vsri${p}.8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRIv1i64 - ARM_INS_VSRI - vsri${p}.64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRIv2i32 - ARM_INS_VSRI - vsri${p}.32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRIv2i64 - ARM_INS_VSRI - vsri${p}.64	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRIv4i16 - ARM_INS_VSRI - vsri${p}.16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRIv4i32 - ARM_INS_VSRI - vsri${p}.32	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRIv8i16 - ARM_INS_VSRI - vsri${p}.16	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VSRIv8i8 - ARM_INS_VSRI - vsri${p}.8	$Vd, $Vm, $SIMM */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* SIMM */
  { 0 }
}},
{{ /* ARM_VST1LNd16 - ARM_INS_VST1 - vst1${p}.16	\{$Vd[$lane]\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VST1LNd16_UPD - ARM_INS_VST1 - vst1${p}.16	\{$Vd[$lane]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VST1LNd32 - ARM_INS_VST1 - vst1${p}.32	\{$Vd[$lane]\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VST1LNd32_UPD - ARM_INS_VST1 - vst1${p}.32	\{$Vd[$lane]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VST1LNd8 - ARM_INS_VST1 - vst1${p}.8	\{$Vd[$lane]\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VST1LNd8_UPD - ARM_INS_VST1 - vst1${p}.8	\{$Vd[$lane]\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VST1d16 - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d16Q - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d16Qwb_fixed - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d16Qwb_register - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d16T - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d16Twb_fixed - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d16Twb_register - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d16wb_fixed - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d16wb_register - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32 - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32Q - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32Qwb_fixed - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32Qwb_register - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32T - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32Twb_fixed - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32Twb_register - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32wb_fixed - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d32wb_register - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64 - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64Q - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64Qwb_fixed - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64Qwb_register - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64T - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64Twb_fixed - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64Twb_register - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64wb_fixed - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d64wb_register - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8 - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8Q - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8Qwb_fixed - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8Qwb_register - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8T - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8Twb_fixed - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8Twb_register - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8wb_fixed - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1d8wb_register - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q16 - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q16wb_fixed - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q16wb_register - ARM_INS_VST1 - vst1${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q32 - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q32wb_fixed - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q32wb_register - ARM_INS_VST1 - vst1${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q64 - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q64wb_fixed - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q64wb_register - ARM_INS_VST1 - vst1${p}.64	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q8 - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q8wb_fixed - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST1q8wb_register - ARM_INS_VST1 - vst1${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b16 - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b16wb_fixed - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b16wb_register - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b32 - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b32wb_fixed - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b32wb_register - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b8 - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b8wb_fixed - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2b8wb_register - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d16 - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d16wb_fixed - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d16wb_register - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d32 - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d32wb_fixed - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d32wb_register - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d8 - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d8wb_fixed - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2d8wb_register - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q16 - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q16wb_fixed - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q16wb_register - ARM_INS_VST2 - vst2${p}.16	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q32 - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q32wb_fixed - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q32wb_register - ARM_INS_VST2 - vst2${p}.32	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q8 - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q8wb_fixed - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST2q8wb_register - ARM_INS_VST2 - vst2${p}.8	$Vd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { 0 }
}},
{{ /* ARM_VST3d16 - ARM_INS_VST3 - vst3${p}.16	\{$Vd, $src2, $src3\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3d16_UPD - ARM_INS_VST3 - vst3${p}.16	\{$Vd, $src2, $src3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3d32 - ARM_INS_VST3 - vst3${p}.32	\{$Vd, $src2, $src3\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3d32_UPD - ARM_INS_VST3 - vst3${p}.32	\{$Vd, $src2, $src3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3d8 - ARM_INS_VST3 - vst3${p}.8	\{$Vd, $src2, $src3\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3d8_UPD - ARM_INS_VST3 - vst3${p}.8	\{$Vd, $src2, $src3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3q16 - ARM_INS_VST3 - vst3${p}.16	\{$Vd, $src2, $src3\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3q16_UPD - ARM_INS_VST3 - vst3${p}.16	\{$Vd, $src2, $src3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3q32 - ARM_INS_VST3 - vst3${p}.32	\{$Vd, $src2, $src3\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3q32_UPD - ARM_INS_VST3 - vst3${p}.32	\{$Vd, $src2, $src3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3q8 - ARM_INS_VST3 - vst3${p}.8	\{$Vd, $src2, $src3\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST3q8_UPD - ARM_INS_VST3 - vst3${p}.8	\{$Vd, $src2, $src3\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { 0 }
}},
{{ /* ARM_VST4d16 - ARM_INS_VST4 - vst4${p}.16	\{$Vd, $src2, $src3, $src4\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4d16_UPD - ARM_INS_VST4 - vst4${p}.16	\{$Vd, $src2, $src3, $src4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4d32 - ARM_INS_VST4 - vst4${p}.32	\{$Vd, $src2, $src3, $src4\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4d32_UPD - ARM_INS_VST4 - vst4${p}.32	\{$Vd, $src2, $src3, $src4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4d8 - ARM_INS_VST4 - vst4${p}.8	\{$Vd, $src2, $src3, $src4\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4d8_UPD - ARM_INS_VST4 - vst4${p}.8	\{$Vd, $src2, $src3, $src4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4q16 - ARM_INS_VST4 - vst4${p}.16	\{$Vd, $src2, $src3, $src4\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4q16_UPD - ARM_INS_VST4 - vst4${p}.16	\{$Vd, $src2, $src3, $src4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4q32 - ARM_INS_VST4 - vst4${p}.32	\{$Vd, $src2, $src3, $src4\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4q32_UPD - ARM_INS_VST4 - vst4${p}.32	\{$Vd, $src2, $src3, $src4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4q8 - ARM_INS_VST4 - vst4${p}.8	\{$Vd, $src2, $src3, $src4\}, $Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VST4q8_UPD - ARM_INS_VST4 - vst4${p}.8	\{$Vd, $src2, $src3, $src4\}, $Rn$Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { CS_OP_REG, CS_AC_READ }, /* src3 */
  { CS_OP_REG, CS_AC_READ }, /* src4 */
  { 0 }
}},
{{ /* ARM_VSTMDDB_UPD - ARM_INS_VSTMDB - vstmdb${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VSTMDIA - ARM_INS_VSTMIA - vstmia${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VSTMDIA_UPD - ARM_INS_VSTMIA - vstmia${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VSTMSDB_UPD - ARM_INS_VSTMDB - vstmdb${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VSTMSIA - ARM_INS_VSTMIA - vstmia${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VSTMSIA_UPD - ARM_INS_VSTMIA - vstmia${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_VSTRD - ARM_INS_VSTR - vstr${p}	$Dd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Dd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTRH - ARM_INS_VSTR - vstr${p}.16	$Sd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTRS - ARM_INS_VSTR - vstr${p}	$Sd, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Sd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPCXTNS_off - ARM_INS_VSTR - vstr${p}	fpcxtns, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPCXTNS_post - ARM_INS_VSTR - vstr${p}	fpcxtns, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPCXTNS_pre - ARM_INS_VSTR - vstr${p}	fpcxtns, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPCXTS_off - ARM_INS_VSTR - vstr${p}	fpcxts, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPCXTS_post - ARM_INS_VSTR - vstr${p}	fpcxts, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPCXTS_pre - ARM_INS_VSTR - vstr${p}	fpcxts, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPSCR_NZCVQC_off - ARM_INS_VSTR - vstr${p}	fpscr_nzcvqc, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPSCR_NZCVQC_post - ARM_INS_VSTR - vstr${p}	fpscr_nzcvqc, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPSCR_NZCVQC_pre - ARM_INS_VSTR - vstr${p}	fpscr_nzcvqc, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPSCR_off - ARM_INS_VSTR - vstr${p}	fpscr, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPSCR_post - ARM_INS_VSTR - vstr${p}	fpscr, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_FPSCR_pre - ARM_INS_VSTR - vstr${p}	fpscr, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_P0_off - ARM_INS_VSTR - vstr${p}	p0, $addr */
  { CS_OP_REG, CS_AC_READ }, /* P0 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_P0_post - ARM_INS_VSTR - vstr${p}	p0, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* P0 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_P0_pre - ARM_INS_VSTR - vstr${p}	p0, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* P0 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_VPR_off - ARM_INS_VSTR - vstr${p}	vpr, $addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_VPR_post - ARM_INS_VSTR - vstr${p}	vpr, $Rn$addr */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSTR_VPR_pre - ARM_INS_VSTR - vstr${p}	vpr, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_VSUBD - ARM_INS_VSUB - vsub${p}.f64	$Dd, $Dn, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Dn */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VSUBH - ARM_INS_VSUB - vsub${p}.f16	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSUBHNv2i32 - ARM_INS_VSUBHN - vsubhn${p}.i64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBHNv4i16 - ARM_INS_VSUBHN - vsubhn${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBHNv8i8 - ARM_INS_VSUBHN - vsubhn${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBLsv2i64 - ARM_INS_VSUBL - vsubl${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBLsv4i32 - ARM_INS_VSUBL - vsubl${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBLsv8i16 - ARM_INS_VSUBL - vsubl${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBLuv2i64 - ARM_INS_VSUBL - vsubl${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBLuv4i32 - ARM_INS_VSUBL - vsubl${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBLuv8i16 - ARM_INS_VSUBL - vsubl${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBS - ARM_INS_VSUB - vsub${p}.f32	$Sd, $Sn, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sn */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VSUBWsv2i64 - ARM_INS_VSUBW - vsubw${p}.s32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBWsv4i32 - ARM_INS_VSUBW - vsubw${p}.s16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBWsv8i16 - ARM_INS_VSUBW - vsubw${p}.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBWuv2i64 - ARM_INS_VSUBW - vsubw${p}.u32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBWuv4i32 - ARM_INS_VSUBW - vsubw${p}.u16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBWuv8i16 - ARM_INS_VSUBW - vsubw${p}.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBfd - ARM_INS_VSUB - vsub${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBfq - ARM_INS_VSUB - vsub${p}.f32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBhd - ARM_INS_VSUB - vsub${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBhq - ARM_INS_VSUB - vsub${p}.f16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBv16i8 - ARM_INS_VSUB - vsub${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBv1i64 - ARM_INS_VSUB - vsub${p}.i64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBv2i32 - ARM_INS_VSUB - vsub${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBv2i64 - ARM_INS_VSUB - vsub${p}.i64	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBv4i16 - ARM_INS_VSUB - vsub${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBv4i32 - ARM_INS_VSUB - vsub${p}.i32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBv8i16 - ARM_INS_VSUB - vsub${p}.i16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUBv8i8 - ARM_INS_VSUB - vsub${p}.i8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VSUDOTDI - ARM_INS_VSUDOT - vsudot.u8	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VSUDOTQI - ARM_INS_VSUDOT - vsudot.u8	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VSWPd - ARM_INS_VSWP - vswp${p}	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* in1 */
  { CS_OP_REG, CS_AC_READ }, /* in2 */
  { 0 }
}},
{{ /* ARM_VSWPq - ARM_INS_VSWP - vswp${p}	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* in1 */
  { CS_OP_REG, CS_AC_READ }, /* in2 */
  { 0 }
}},
{{ /* ARM_VTBL1 - ARM_INS_VTBL - vtbl${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTBL2 - ARM_INS_VTBL - vtbl${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTBL3 - ARM_INS_VTBL - vtbl${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTBL4 - ARM_INS_VTBL - vtbl${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTBX1 - ARM_INS_VTBX - vtbx${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* orig */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTBX2 - ARM_INS_VTBX - vtbx${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* orig */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTBX3 - ARM_INS_VTBX - vtbx${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* orig */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTBX4 - ARM_INS_VTBX - vtbx${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* orig */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTOSHD - ARM_INS_VCVT - vcvt${p}.s16.f64	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOSHH - ARM_INS_VCVT - vcvt${p}.s16.f16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOSHS - ARM_INS_VCVT - vcvt${p}.s16.f32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOSIRD - ARM_INS_VCVTR - vcvtr${p}.s32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VTOSIRH - ARM_INS_VCVTR - vcvtr${p}.s32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VTOSIRS - ARM_INS_VCVTR - vcvtr${p}.s32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VTOSIZD - ARM_INS_VCVT - vcvt${p}.s32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VTOSIZH - ARM_INS_VCVT - vcvt${p}.s32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VTOSIZS - ARM_INS_VCVT - vcvt${p}.s32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VTOSLD - ARM_INS_VCVT - vcvt${p}.s32.f64	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOSLH - ARM_INS_VCVT - vcvt${p}.s32.f16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOSLS - ARM_INS_VCVT - vcvt${p}.s32.f32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOUHD - ARM_INS_VCVT - vcvt${p}.u16.f64	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOUHH - ARM_INS_VCVT - vcvt${p}.u16.f16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOUHS - ARM_INS_VCVT - vcvt${p}.u16.f32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOUIRD - ARM_INS_VCVTR - vcvtr${p}.u32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VTOUIRH - ARM_INS_VCVTR - vcvtr${p}.u32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VTOUIRS - ARM_INS_VCVTR - vcvtr${p}.u32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VTOUIZD - ARM_INS_VCVT - vcvt${p}.u32.f64	$Sd, $Dm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Dm */
  { 0 }
}},
{{ /* ARM_VTOUIZH - ARM_INS_VCVT - vcvt${p}.u32.f16	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VTOUIZS - ARM_INS_VCVT - vcvt${p}.u32.f32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VTOULD - ARM_INS_VCVT - vcvt${p}.u32.f64	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOULH - ARM_INS_VCVT - vcvt${p}.u32.f16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTOULS - ARM_INS_VCVT - vcvt${p}.u32.f32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VTRNd16 - ARM_INS_VTRN - vtrn${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VTRNd32 - ARM_INS_VTRN - vtrn${p}.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VTRNd8 - ARM_INS_VTRN - vtrn${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VTRNq16 - ARM_INS_VTRN - vtrn${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VTRNq32 - ARM_INS_VTRN - vtrn${p}.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VTRNq8 - ARM_INS_VTRN - vtrn${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VTSTv16i8 - ARM_INS_VTST - vtst${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTSTv2i32 - ARM_INS_VTST - vtst${p}.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTSTv4i16 - ARM_INS_VTST - vtst${p}.16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTSTv4i32 - ARM_INS_VTST - vtst${p}.32	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTSTv8i16 - ARM_INS_VTST - vtst${p}.16	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VTSTv8i8 - ARM_INS_VTST - vtst${p}.8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VUDOTD - ARM_INS_VUDOT - vudot.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VUDOTDI - ARM_INS_VUDOT - vudot.u8	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VUDOTQ - ARM_INS_VUDOT - vudot.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VUDOTQI - ARM_INS_VUDOT - vudot.u8	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VUHTOD - ARM_INS_VCVT - vcvt${p}.f64.u16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VUHTOH - ARM_INS_VCVT - vcvt${p}.f16.u16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VUHTOS - ARM_INS_VCVT - vcvt${p}.f32.u16	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VUITOD - ARM_INS_VCVT - vcvt${p}.f64.u32	$Dd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Dd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VUITOH - ARM_INS_VCVT - vcvt${p}.f16.u32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VUITOS - ARM_INS_VCVT - vcvt${p}.f32.u32	$Sd, $Sm */
  { CS_OP_REG, CS_AC_WRITE }, /* Sd */
  { CS_OP_REG, CS_AC_READ }, /* Sm */
  { 0 }
}},
{{ /* ARM_VULTOD - ARM_INS_VCVT - vcvt${p}.f64.u32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VULTOH - ARM_INS_VCVT - vcvt${p}.f16.u32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VULTOS - ARM_INS_VCVT - vcvt${p}.f32.u32	$dst, $a, $fbits */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* a */
  { CS_OP_IMM, CS_AC_READ }, /* fbits */
  { 0 }
}},
{{ /* ARM_VUMMLA - ARM_INS_VUMMLA - vummla.u8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VUSDOTD - ARM_INS_VUSDOT - vusdot.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VUSDOTDI - ARM_INS_VUSDOT - vusdot.s8	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VUSDOTQ - ARM_INS_VUSDOT - vusdot.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VUSDOTQI - ARM_INS_VUSDOT - vusdot.s8	$Vd, $Vn, $Vm$lane */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { CS_OP_IMM, CS_AC_READ }, /* lane */
  { 0 }
}},
{{ /* ARM_VUSMMLA - ARM_INS_VUSMMLA - vusmmla.s8	$Vd, $Vn, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* Vd */
  { CS_OP_REG, CS_AC_READ }, /* Vn */
  { CS_OP_REG, CS_AC_READ }, /* Vm */
  { 0 }
}},
{{ /* ARM_VUZPd16 - ARM_INS_VUZP - vuzp${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VUZPd8 - ARM_INS_VUZP - vuzp${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VUZPq16 - ARM_INS_VUZP - vuzp${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VUZPq32 - ARM_INS_VUZP - vuzp${p}.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VUZPq8 - ARM_INS_VUZP - vuzp${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VZIPd16 - ARM_INS_VZIP - vzip${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VZIPd8 - ARM_INS_VZIP - vzip${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VZIPq16 - ARM_INS_VZIP - vzip${p}.16	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VZIPq32 - ARM_INS_VZIP - vzip${p}.32	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_VZIPq8 - ARM_INS_VZIP - vzip${p}.8	$Vd, $Vm */
  { CS_OP_REG, CS_AC_WRITE }, /* Vd */
  { CS_OP_REG, CS_AC_WRITE }, /* Vm */
  { CS_OP_REG, CS_AC_READ }, /* src1 */
  { CS_OP_REG, CS_AC_READ }, /* src2 */
  { 0 }
}},
{{ /* ARM_sysLDMDA - ARM_INS_LDMDA - ldmda${p}	$Rn, $regs ^ */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysLDMDA_UPD - ARM_INS_LDMDA - ldmda${p}	$Rn!, $regs ^ */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysLDMDB - ARM_INS_LDMDB - ldmdb${p}	$Rn, $regs ^ */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysLDMDB_UPD - ARM_INS_LDMDB - ldmdb${p}	$Rn!, $regs ^ */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysLDMIA - ARM_INS_LDM - ldm${p}	$Rn, $regs ^ */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysLDMIA_UPD - ARM_INS_LDM - ldm${p}	$Rn!, $regs ^ */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysLDMIB - ARM_INS_LDMIB - ldmib${p}	$Rn, $regs ^ */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysLDMIB_UPD - ARM_INS_LDMIB - ldmib${p}	$Rn!, $regs ^ */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysSTMDA - ARM_INS_STMDA - stmda${p}	$Rn, $regs ^ */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysSTMDA_UPD - ARM_INS_STMDA - stmda${p}	$Rn!, $regs ^ */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysSTMDB - ARM_INS_STMDB - stmdb${p}	$Rn, $regs ^ */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysSTMDB_UPD - ARM_INS_STMDB - stmdb${p}	$Rn!, $regs ^ */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysSTMIA - ARM_INS_STM - stm${p}	$Rn, $regs ^ */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysSTMIA_UPD - ARM_INS_STM - stm${p}	$Rn!, $regs ^ */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysSTMIB - ARM_INS_STMIB - stmib${p}	$Rn, $regs ^ */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_sysSTMIB_UPD - ARM_INS_STMIB - stmib${p}	$Rn!, $regs ^ */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2ADCri - ARM_INS_ADC - adc${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ADCrr - ARM_INS_ADC - adc${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2ADCrs - ARM_INS_ADC - adc${s}${p}.w	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2ADDri - ARM_INS_ADD - add${s}${p}.w	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ADDri12 - ARM_INS_ADDW - addw${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ADDrr - ARM_INS_ADD - add${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2ADDrs - ARM_INS_ADD - add${s}${p}.w	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2ADDspImm - ARM_INS_ADD - add${s}${p}.w	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ADDspImm12 - ARM_INS_ADDW - addw${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ADR - ARM_INS_ADR - adr{$p}.w	$Rd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2ANDri - ARM_INS_AND - and${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ANDrr - ARM_INS_AND - and${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2ANDrs - ARM_INS_AND - and${s}${p}.w	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2ASRri - ARM_INS_ASR - asr${s}${p}.w	$Rd, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ASRrr - ARM_INS_ASR - asr${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2AUT - ARM_INS_AUT - aut	r12, lr, sp */
  { 0 }
}},
{{ /* ARM_t2AUTG - ARM_INS_AUTG - autg${p}	$Ra, $Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2B - ARM_INS_B - b${p}.w	$target */
  { CS_OP_IMM, CS_AC_READ }, /* target */
  { 0 }
}},
{{ /* ARM_t2BFC - ARM_INS_BFC - bfc${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2BFI - ARM_INS_BFI - bfi${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2BFLi - ARM_INS_BFL - bfl${p}	$b_label, $label */
  { CS_OP_IMM, CS_AC_READ }, /* b_label */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_t2BFLr - ARM_INS_BFLX - bflx${p}	$b_label, $Rn */
  { CS_OP_IMM, CS_AC_READ }, /* b_label */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2BFi - ARM_INS_BF - bf${p}	$b_label, $label */
  { CS_OP_IMM, CS_AC_READ }, /* b_label */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_t2BFic - ARM_INS_BFCSEL - bfcsel	$b_label, $label, $ba_label, $bcond */
  { CS_OP_IMM, CS_AC_READ }, /* b_label */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { CS_OP_IMM, CS_AC_READ }, /* ba_label */
  { CS_OP_IMM, CS_AC_READ }, /* bcond */
  { 0 }
}},
{{ /* ARM_t2BFr - ARM_INS_BFX - bfx${p}	$b_label, $Rn */
  { CS_OP_IMM, CS_AC_READ }, /* b_label */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2BICri - ARM_INS_BIC - bic${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2BICrr - ARM_INS_BIC - bic${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2BICrs - ARM_INS_BIC - bic${s}${p}.w	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2BTI - ARM_INS_BTI - bti	 */
  { 0 }
}},
{{ /* ARM_t2BXAUT - ARM_INS_BXAUT - bxaut${p}	$Ra, $Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2BXJ - ARM_INS_BXJ - bxj${p}	$func */
  { CS_OP_REG, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_t2Bcc - ARM_INS_B - b${p}.w	$target */
  { CS_OP_IMM, CS_AC_READ }, /* target */
  { 0 }
}},
{{ /* ARM_t2CDP - ARM_INS_CDP - cdp${p}	$cop, $opc1, $CRd, $CRn, $CRm, $opc2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_t2CDP2 - ARM_INS_CDP2 - cdp2${p}	$cop, $opc1, $CRd, $CRn, $CRm, $opc2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_t2CLREX - ARM_INS_CLREX - clrex${p} */
  { 0 }
}},
{{ /* ARM_t2CLRM - ARM_INS_CLRM - clrm${p}	$regs */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2CLZ - ARM_INS_CLZ - clz${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CMNri - ARM_INS_CMN - cmn${p}.w	$Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2CMNzrr - ARM_INS_CMN - cmn${p}.w	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CMNzrs - ARM_INS_CMN - cmn${p}.w	$Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2CMPri - ARM_INS_CMP - cmp${p}.w	$Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2CMPrr - ARM_INS_CMP - cmp${p}.w	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CMPrs - ARM_INS_CMP - cmp${p}.w	$Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2CPS1p - ARM_INS_CPS - cps	$mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_t2CPS2p - ARM_INS_CPS - cps$imod.w	$iflags */
  { CS_OP_IMM, CS_AC_READ }, /* imod */
  { CS_OP_IMM, CS_AC_READ }, /* iflags */
  { 0 }
}},
{{ /* ARM_t2CPS3p - ARM_INS_CPS - cps$imod	$iflags, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* imod */
  { CS_OP_IMM, CS_AC_READ }, /* iflags */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_t2CRC32B - ARM_INS_CRC32B - crc32b	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CRC32CB - ARM_INS_CRC32CB - crc32cb	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CRC32CH - ARM_INS_CRC32CH - crc32ch	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CRC32CW - ARM_INS_CRC32CW - crc32cw	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CRC32H - ARM_INS_CRC32H - crc32h	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CRC32W - ARM_INS_CRC32W - crc32w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2CSEL - ARM_INS_CSEL - csel	$Rd, $Rn, $Rm, $fcond */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fcond */
  { 0 }
}},
{{ /* ARM_t2CSINC - ARM_INS_CSINC - csinc	$Rd, $Rn, $Rm, $fcond */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fcond */
  { 0 }
}},
{{ /* ARM_t2CSINV - ARM_INS_CSINV - csinv	$Rd, $Rn, $Rm, $fcond */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fcond */
  { 0 }
}},
{{ /* ARM_t2CSNEG - ARM_INS_CSNEG - csneg	$Rd, $Rn, $Rm, $fcond */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* fcond */
  { 0 }
}},
{{ /* ARM_t2DBG - ARM_INS_DBG - dbg${p}	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_t2DCPS1 - ARM_INS_DCPS1 - dcps1${p} */
  { 0 }
}},
{{ /* ARM_t2DCPS2 - ARM_INS_DCPS2 - dcps2${p} */
  { 0 }
}},
{{ /* ARM_t2DCPS3 - ARM_INS_DCPS3 - dcps3${p} */
  { 0 }
}},
{{ /* ARM_t2DLS - ARM_INS_DLS - dls	$LR, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2DMB - ARM_INS_DMB - dmb${p}	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_t2DSB - ARM_INS_DSB - dsb${p}	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_t2EORri - ARM_INS_EOR - eor${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2EORrr - ARM_INS_EOR - eor${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2EORrs - ARM_INS_EOR - eor${s}${p}.w	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2HINT - ARM_INS_YIELD - hint${p}.w	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2HINT - ARM_INS_HINT - hint${p}.w	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2HVC - ARM_INS_HVC - hvc.w	$imm16 */
  { CS_OP_IMM, CS_AC_READ }, /* imm16 */
  { 0 }
}},
{{ /* ARM_t2ISB - ARM_INS_ISB - isb${p}	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_t2IT - ARM_INS_IT - it$mask	$cc */
  { CS_OP_IMM, CS_AC_READ }, /* cc */
  { CS_OP_IMM, CS_AC_READ }, /* mask */
  { 0 }
}},
{{ /* ARM_t2LDA - ARM_INS_LDA - lda${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDAB - ARM_INS_LDAB - ldab${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDAEX - ARM_INS_LDAEX - ldaex${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDAEXB - ARM_INS_LDAEXB - ldaexb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDAEXD - ARM_INS_LDAEXD - ldaexd${p}	$Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDAEXH - ARM_INS_LDAEXH - ldaexh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDAH - ARM_INS_LDAH - ldah${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDC2L_OFFSET - ARM_INS_LDC2L - ldc2l${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDC2L_OPTION - ARM_INS_LDC2L - ldc2l${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_t2LDC2L_POST - ARM_INS_LDC2L - ldc2l${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDC2L_PRE - ARM_INS_LDC2L - ldc2l${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDC2_OFFSET - ARM_INS_LDC2 - ldc2${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDC2_OPTION - ARM_INS_LDC2 - ldc2${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_t2LDC2_POST - ARM_INS_LDC2 - ldc2${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDC2_PRE - ARM_INS_LDC2 - ldc2${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDCL_OFFSET - ARM_INS_LDCL - ldcl${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDCL_OPTION - ARM_INS_LDCL - ldcl${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_t2LDCL_POST - ARM_INS_LDCL - ldcl${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDCL_PRE - ARM_INS_LDCL - ldcl${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDC_OFFSET - ARM_INS_LDC - ldc${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDC_OPTION - ARM_INS_LDC - ldc${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_t2LDC_POST - ARM_INS_LDC - ldc${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDC_PRE - ARM_INS_LDC - ldc${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDMDB - ARM_INS_LDMDB - ldmdb${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2LDMDB_UPD - ARM_INS_LDMDB - ldmdb${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2LDMIA - ARM_INS_LDM - ldm${p}.w	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2LDMIA_UPD - ARM_INS_LDM - ldm${p}.w	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2LDRBT - ARM_INS_LDRBT - ldrbt${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRB_POST - ARM_INS_LDRB - ldrb${p}	$Rt, $Rn$offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDRB_PRE - ARM_INS_LDRB - ldrb${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRBi12 - ARM_INS_LDRB - ldrb${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRBi8 - ARM_INS_LDRB - ldrb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRBpci - ARM_INS_LDRB - ldrb${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRBs - ARM_INS_LDRB - ldrb${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRD_POST - ARM_INS_LDRD - ldrd${p}	$Rt, $Rt2, $addr$imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2LDRD_PRE - ARM_INS_LDRD - ldrd${p}	$Rt, $Rt2, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRDi8 - ARM_INS_LDRD - ldrd${p}	$Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDREX - ARM_INS_LDREX - ldrex${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDREXB - ARM_INS_LDREXB - ldrexb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDREXD - ARM_INS_LDREXD - ldrexd${p}	$Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDREXH - ARM_INS_LDREXH - ldrexh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRHT - ARM_INS_LDRHT - ldrht${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRH_POST - ARM_INS_LDRH - ldrh${p}	$Rt, $Rn$offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDRH_PRE - ARM_INS_LDRH - ldrh${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRHi12 - ARM_INS_LDRH - ldrh${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRHi8 - ARM_INS_LDRH - ldrh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRHpci - ARM_INS_LDRH - ldrh${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRHs - ARM_INS_LDRH - ldrh${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSBT - ARM_INS_LDRSBT - ldrsbt${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSB_POST - ARM_INS_LDRSB - ldrsb${p}	$Rt, $Rn$offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDRSB_PRE - ARM_INS_LDRSB - ldrsb${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSBi12 - ARM_INS_LDRSB - ldrsb${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSBi8 - ARM_INS_LDRSB - ldrsb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSBpci - ARM_INS_LDRSB - ldrsb${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSBs - ARM_INS_LDRSB - ldrsb${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSHT - ARM_INS_LDRSHT - ldrsht${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSH_POST - ARM_INS_LDRSH - ldrsh${p}	$Rt, $Rn$offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDRSH_PRE - ARM_INS_LDRSH - ldrsh${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSHi12 - ARM_INS_LDRSH - ldrsh${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSHi8 - ARM_INS_LDRSH - ldrsh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSHpci - ARM_INS_LDRSH - ldrsh${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRSHs - ARM_INS_LDRSH - ldrsh${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRT - ARM_INS_LDRT - ldrt${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDR_POST - ARM_INS_LDR - ldr${p}	$Rt, $Rn$offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2LDR_PRE - ARM_INS_LDR - ldr${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRi12 - ARM_INS_LDR - ldr${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRi8 - ARM_INS_LDR - ldr${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRpci - ARM_INS_LDR - ldr${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LDRs - ARM_INS_LDR - ldr${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2LE - ARM_INS_LE - le	$label */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_t2LEUpdate - ARM_INS_LE - le	$LRin, $label */
  { CS_OP_REG, CS_AC_WRITE }, /* LRout */
  { CS_OP_REG, CS_AC_READ }, /* LRin */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_t2LSLri - ARM_INS_LSL - lsl${s}${p}.w	$Rd, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2LSLrr - ARM_INS_LSL - lsl${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2LSRri - ARM_INS_LSR - lsr${s}${p}.w	$Rd, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2LSRrr - ARM_INS_LSR - lsr${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2MCR - ARM_INS_MCR - mcr${p}	$cop, $opc1, $Rt, $CRn, $CRm, $opc2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_t2MCR2 - ARM_INS_MCR2 - mcr2${p}	$cop, $opc1, $Rt, $CRn, $CRm, $opc2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_t2MCRR - ARM_INS_MCRR - mcrr${p}	$cop, $opc1, $Rt, $Rt2, $CRm */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { 0 }
}},
{{ /* ARM_t2MCRR2 - ARM_INS_MCRR2 - mcrr2${p}	$cop, $opc1, $Rt, $Rt2, $CRm */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { 0 }
}},
{{ /* ARM_t2MLA - ARM_INS_MLA - mla${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2MLS - ARM_INS_MLS - mls${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2MOVTi16 - ARM_INS_MOVT - movt${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* src */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2MOVi - ARM_INS_MOV - mov${s}${p}.w	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2MOVi16 - ARM_INS_MOVW - movw${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2MOVr - ARM_INS_MOV - mov${s}${p}.w	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2MRC - ARM_INS_MRC - mrc${p}	$cop, $opc1, $Rt, $CRn, $CRm, $opc2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_t2MRC2 - ARM_INS_MRC2 - mrc2${p}	$cop, $opc1, $Rt, $CRn, $CRm, $opc2 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRn */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { CS_OP_IMM, CS_AC_READ }, /* opc2 */
  { 0 }
}},
{{ /* ARM_t2MRRC - ARM_INS_MRRC - mrrc${p}	$cop, $opc1, $Rt, $Rt2, $CRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { 0 }
}},
{{ /* ARM_t2MRRC2 - ARM_INS_MRRC2 - mrrc2${p}	$cop, $opc1, $Rt, $Rt2, $CRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt2 */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* opc1 */
  { CS_OP_IMM, CS_AC_READ }, /* CRm */
  { 0 }
}},
{{ /* ARM_t2MRS_AR - ARM_INS_MRS - mrs${p}	$Rd, apsr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { 0 }
}},
{{ /* ARM_t2MRS_M - ARM_INS_MRS - mrs${p}	$Rd, $SYSm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* SYSm */
  { 0 }
}},
{{ /* ARM_t2MRSbanked - ARM_INS_MRS - mrs${p}	$Rd, $banked */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* banked */
  { 0 }
}},
{{ /* ARM_t2MRSsys_AR - ARM_INS_MRS - mrs${p}	$Rd, spsr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { 0 }
}},
{{ /* ARM_t2MSR_AR - ARM_INS_MSR - msr${p}	$mask, $Rn */
  { CS_OP_IMM, CS_AC_READ }, /* mask */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2MSR_M - ARM_INS_MSR - msr${p}	$SYSm, $Rn */
  { CS_OP_IMM, CS_AC_READ }, /* SYSm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2MSRbanked - ARM_INS_MSR - msr${p}	$banked, $Rn */
  { CS_OP_IMM, CS_AC_READ }, /* banked */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2MUL - ARM_INS_MUL - mul${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2MVNi - ARM_INS_MVN - mvn${s}${p}	$Rd, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2MVNr - ARM_INS_MVN - mvn${s}${p}.w	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2MVNs - ARM_INS_MVN - mvn${s}${p}.w	$Rd, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2ORNri - ARM_INS_ORN - orn${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ORNrr - ARM_INS_ORN - orn${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2ORNrs - ARM_INS_ORN - orn${s}${p}	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2ORRri - ARM_INS_ORR - orr${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2ORRrr - ARM_INS_ORR - orr${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2ORRrs - ARM_INS_ORR - orr${s}${p}.w	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2PAC - ARM_INS_PAC - pac	r12, lr, sp */
  { 0 }
}},
{{ /* ARM_t2PACBTI - ARM_INS_PACBTI - pacbti	r12, lr, sp */
  { 0 }
}},
{{ /* ARM_t2PACG - ARM_INS_PACG - pacg${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2PKHBT - ARM_INS_PKHBT - pkhbt${p}	$Rd, $Rn, $Rm$sh */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* sh */
  { 0 }
}},
{{ /* ARM_t2PKHTB - ARM_INS_PKHTB - pkhtb${p}	$Rd, $Rn, $Rm$sh */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* sh */
  { 0 }
}},
{{ /* ARM_t2PLDWi12 - ARM_INS_PLDW - pldw${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLDWi8 - ARM_INS_PLDW - pldw${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLDWs - ARM_INS_PLDW - pldw${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLDi12 - ARM_INS_PLD - pld${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLDi8 - ARM_INS_PLD - pld${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLDpci - ARM_INS_PLD - pld${p}	$addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLDs - ARM_INS_PLD - pld${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLIi12 - ARM_INS_PLI - pli${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLIi8 - ARM_INS_PLI - pli${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLIpci - ARM_INS_PLI - pli${p}	$addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2PLIs - ARM_INS_PLI - pli${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2QADD - ARM_INS_QADD - qadd${p}	$Rd, $Rm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2QADD16 - ARM_INS_QADD16 - qadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2QADD8 - ARM_INS_QADD8 - qadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2QASX - ARM_INS_QASX - qasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2QDADD - ARM_INS_QDADD - qdadd${p}	$Rd, $Rm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2QDSUB - ARM_INS_QDSUB - qdsub${p}	$Rd, $Rm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2QSAX - ARM_INS_QSAX - qsax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2QSUB - ARM_INS_QSUB - qsub${p}	$Rd, $Rm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2QSUB16 - ARM_INS_QSUB16 - qsub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2QSUB8 - ARM_INS_QSUB8 - qsub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2RBIT - ARM_INS_RBIT - rbit${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2REV - ARM_INS_REV - rev${p}.w	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2REV16 - ARM_INS_REV16 - rev16${p}.w	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2REVSH - ARM_INS_REVSH - revsh${p}.w	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2RFEDB - ARM_INS_RFEDB - rfedb${p}	$Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2RFEDBW - ARM_INS_RFEDB - rfedb${p}	$Rn! */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2RFEIA - ARM_INS_RFEIA - rfeia${p}	$Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2RFEIAW - ARM_INS_RFEIA - rfeia${p}	$Rn! */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2RORri - ARM_INS_ROR - ror${s}${p}.w	$Rd, $Rm, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2RORrr - ARM_INS_ROR - ror${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2RRX - ARM_INS_RRX - rrx${s}${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2RSBri - ARM_INS_RSB - rsb${s}${p}.w	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2RSBrr - ARM_INS_RSB - rsb${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2RSBrs - ARM_INS_RSB - rsb${s}${p}	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2SADD16 - ARM_INS_SADD16 - sadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SADD8 - ARM_INS_SADD8 - sadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SASX - ARM_INS_SASX - sasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SB - ARM_INS_SB - sb */
  { 0 }
}},
{{ /* ARM_t2SBCri - ARM_INS_SBC - sbc${s}${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2SBCrr - ARM_INS_SBC - sbc${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SBCrs - ARM_INS_SBC - sbc${s}${p}.w	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2SBFX - ARM_INS_SBFX - sbfx${p}	$Rd, $Rn, $lsb, $msb */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* lsb */
  { CS_OP_IMM, CS_AC_READ }, /* msb */
  { 0 }
}},
{{ /* ARM_t2SDIV - ARM_INS_SDIV - sdiv${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SEL - ARM_INS_SEL - sel${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SETPAN - ARM_INS_SETPAN - setpan	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2SG - ARM_INS_SG - sg${p} */
  { 0 }
}},
{{ /* ARM_t2SHADD16 - ARM_INS_SHADD16 - shadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SHADD8 - ARM_INS_SHADD8 - shadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SHASX - ARM_INS_SHASX - shasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SHSAX - ARM_INS_SHSAX - shsax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SHSUB16 - ARM_INS_SHSUB16 - shsub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SHSUB8 - ARM_INS_SHSUB8 - shsub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMC - ARM_INS_SMC - smc${p}	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_t2SMLABB - ARM_INS_SMLABB - smlabb${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLABT - ARM_INS_SMLABT - smlabt${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLAD - ARM_INS_SMLAD - smlad${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLADX - ARM_INS_SMLADX - smladx${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLAL - ARM_INS_SMLAL - smlal${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMLALBB - ARM_INS_SMLALBB - smlalbb${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMLALBT - ARM_INS_SMLALBT - smlalbt${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMLALD - ARM_INS_SMLALD - smlald${p}	$Ra, $Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMLALDX - ARM_INS_SMLALDX - smlaldx${p}	$Ra, $Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMLALTB - ARM_INS_SMLALTB - smlaltb${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMLALTT - ARM_INS_SMLALTT - smlaltt${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMLATB - ARM_INS_SMLATB - smlatb${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLATT - ARM_INS_SMLATT - smlatt${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLAWB - ARM_INS_SMLAWB - smlawb${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLAWT - ARM_INS_SMLAWT - smlawt${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLSD - ARM_INS_SMLSD - smlsd${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLSDX - ARM_INS_SMLSDX - smlsdx${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMLSLD - ARM_INS_SMLSLD - smlsld${p}	$Ra, $Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMLSLDX - ARM_INS_SMLSLDX - smlsldx${p}	$Ra, $Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2SMMLA - ARM_INS_SMMLA - smmla${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMMLAR - ARM_INS_SMMLAR - smmlar${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMMLS - ARM_INS_SMMLS - smmls${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMMLSR - ARM_INS_SMMLSR - smmlsr${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2SMMUL - ARM_INS_SMMUL - smmul${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMMULR - ARM_INS_SMMULR - smmulr${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMUAD - ARM_INS_SMUAD - smuad${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMUADX - ARM_INS_SMUADX - smuadx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMULBB - ARM_INS_SMULBB - smulbb${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMULBT - ARM_INS_SMULBT - smulbt${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMULL - ARM_INS_SMULL - smull${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMULTB - ARM_INS_SMULTB - smultb${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMULTT - ARM_INS_SMULTT - smultt${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMULWB - ARM_INS_SMULWB - smulwb${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMULWT - ARM_INS_SMULWT - smulwt${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMUSD - ARM_INS_SMUSD - smusd${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SMUSDX - ARM_INS_SMUSDX - smusdx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SRSDB - ARM_INS_SRSDB - srsdb${p}	sp, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_t2SRSDB_UPD - ARM_INS_SRSDB - srsdb${p}	sp!, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_t2SRSIA - ARM_INS_SRSIA - srsia${p}	sp, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_t2SRSIA_UPD - ARM_INS_SRSIA - srsia${p}	sp!, $mode */
  { CS_OP_IMM, CS_AC_READ }, /* mode */
  { 0 }
}},
{{ /* ARM_t2SSAT - ARM_INS_SSAT - ssat${p}	$Rd, $sat_imm, $Rn$sh */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* sat_imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* sh */
  { 0 }
}},
{{ /* ARM_t2SSAT16 - ARM_INS_SSAT16 - ssat16${p}	$Rd, $sat_imm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* sat_imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2SSAX - ARM_INS_SSAX - ssax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SSUB16 - ARM_INS_SSUB16 - ssub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SSUB8 - ARM_INS_SSUB8 - ssub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2STC2L_OFFSET - ARM_INS_STC2L - stc2l${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STC2L_OPTION - ARM_INS_STC2L - stc2l${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_t2STC2L_POST - ARM_INS_STC2L - stc2l${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2STC2L_PRE - ARM_INS_STC2L - stc2l${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STC2_OFFSET - ARM_INS_STC2 - stc2${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STC2_OPTION - ARM_INS_STC2 - stc2${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_t2STC2_POST - ARM_INS_STC2 - stc2${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2STC2_PRE - ARM_INS_STC2 - stc2${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STCL_OFFSET - ARM_INS_STCL - stcl${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STCL_OPTION - ARM_INS_STCL - stcl${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_t2STCL_POST - ARM_INS_STCL - stcl${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2STCL_PRE - ARM_INS_STCL - stcl${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STC_OFFSET - ARM_INS_STC - stc${p}	$cop, $CRd, $addr */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STC_OPTION - ARM_INS_STC - stc${p}	$cop, $CRd, $addr, $option */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_IMM, CS_AC_READ }, /* option */
  { 0 }
}},
{{ /* ARM_t2STC_POST - ARM_INS_STC - stc${p}	$cop, $CRd, $addr, $offset */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2STC_PRE - ARM_INS_STC - stc${p}	$cop, $CRd, $addr! */
  { CS_OP_IMM, CS_AC_READ }, /* cop */
  { CS_OP_IMM, CS_AC_READ }, /* CRd */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STL - ARM_INS_STL - stl${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STLB - ARM_INS_STLB - stlb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STLEX - ARM_INS_STLEX - stlex${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STLEXB - ARM_INS_STLEXB - stlexb${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STLEXD - ARM_INS_STLEXD - stlexd${p}	$Rd, $Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STLEXH - ARM_INS_STLEXH - stlexh${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STLH - ARM_INS_STLH - stlh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STMDB - ARM_INS_STMDB - stmdb${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2STMDB_UPD - ARM_INS_STMDB - stmdb${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2STMIA - ARM_INS_STM - stm${p}.w	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2STMIA_UPD - ARM_INS_STM - stm${p}.w	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_t2STRBT - ARM_INS_STRBT - strbt${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRB_POST - ARM_INS_STRB - strb${p}	$Rt, $Rn$offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2STRB_PRE - ARM_INS_STRB - strb${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRBi12 - ARM_INS_STRB - strb${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRBi8 - ARM_INS_STRB - strb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRBs - ARM_INS_STRB - strb${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRD_POST - ARM_INS_STRD - strd${p}	$Rt, $Rt2, $addr$imm */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2STRD_PRE - ARM_INS_STRD - strd${p}	$Rt, $Rt2, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRDi8 - ARM_INS_STRD - strd${p}	$Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STREX - ARM_INS_STREX - strex${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STREXB - ARM_INS_STREXB - strexb${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STREXD - ARM_INS_STREXD - strexd${p}	$Rd, $Rt, $Rt2, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rt2 */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STREXH - ARM_INS_STREXH - strexh${p}	$Rd, $Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRHT - ARM_INS_STRHT - strht${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRH_POST - ARM_INS_STRH - strh${p}	$Rt, $Rn$offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2STRH_PRE - ARM_INS_STRH - strh${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRHi12 - ARM_INS_STRH - strh${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRHi8 - ARM_INS_STRH - strh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRHs - ARM_INS_STRH - strh${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRT - ARM_INS_STRT - strt${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STR_POST - ARM_INS_STR - str${p}	$Rt, $Rn$offset */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* offset */
  { 0 }
}},
{{ /* ARM_t2STR_PRE - ARM_INS_STR - str${p}	$Rt, $addr! */
  { CS_OP_REG, CS_AC_WRITE }, /* Rn_wb */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRi12 - ARM_INS_STR - str${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRi8 - ARM_INS_STR - str${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2STRs - ARM_INS_STR - str${p}.w	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2SUBS_PC_LR - ARM_INS_SUBS - subs${p}	pc, lr, $imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2SUBS_PC_LR - ARM_INS_ERET - subs${p}	pc, lr, $imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2SUBri - ARM_INS_SUB - sub${s}${p}.w	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2SUBri12 - ARM_INS_SUBW - subw${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2SUBrr - ARM_INS_SUB - sub${s}${p}.w	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2SUBrs - ARM_INS_SUB - sub${s}${p}.w	$Rd, $Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2SUBspImm - ARM_INS_SUB - sub${s}${p}.w	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2SUBspImm12 - ARM_INS_SUBW - subw${p}	$Rd, $Rn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2SXTAB - ARM_INS_SXTAB - sxtab${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2SXTAB16 - ARM_INS_SXTAB16 - sxtab16${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2SXTAH - ARM_INS_SXTAH - sxtah${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2SXTB - ARM_INS_SXTB - sxtb${p}.w	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2SXTB16 - ARM_INS_SXTB16 - sxtb16${p}	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2SXTH - ARM_INS_SXTH - sxth${p}.w	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2TBB - ARM_INS_TBB - tbb${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2TBH - ARM_INS_TBH - tbh${p}	$addr */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_t2TEQri - ARM_INS_TEQ - teq${p}.w	$Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2TEQrr - ARM_INS_TEQ - teq${p}.w	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2TEQrs - ARM_INS_TEQ - teq${p}.w	$Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2TSB - ARM_INS_TSB - tsb${p}	$opt */
  { CS_OP_IMM, CS_AC_READ }, /* opt */
  { 0 }
}},
{{ /* ARM_t2TSTri - ARM_INS_TST - tst${p}.w	$Rn, $imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_t2TSTrr - ARM_INS_TST - tst${p}.w	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2TSTrs - ARM_INS_TST - tst${p}.w	$Rn, $ShiftedRm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* ShiftedRm */
  { 0 }
}},
{{ /* ARM_t2TT - ARM_INS_TT - tt${p}	$Rt, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2TTA - ARM_INS_TTA - tta${p}	$Rt, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2TTAT - ARM_INS_TTAT - ttat${p}	$Rt, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2TTT - ARM_INS_TTT - ttt${p}	$Rt, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2UADD16 - ARM_INS_UADD16 - uadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UADD8 - ARM_INS_UADD8 - uadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UASX - ARM_INS_UASX - uasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UBFX - ARM_INS_UBFX - ubfx${p}	$Rd, $Rn, $lsb, $msb */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* lsb */
  { CS_OP_IMM, CS_AC_READ }, /* msb */
  { 0 }
}},
{{ /* ARM_t2UDF - ARM_INS_UDF - udf.w	$imm16 */
  { CS_OP_IMM, CS_AC_READ }, /* imm16 */
  { 0 }
}},
{{ /* ARM_t2UDIV - ARM_INS_UDIV - udiv${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UHADD16 - ARM_INS_UHADD16 - uhadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UHADD8 - ARM_INS_UHADD8 - uhadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UHASX - ARM_INS_UHASX - uhasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UHSAX - ARM_INS_UHSAX - uhsax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UHSUB16 - ARM_INS_UHSUB16 - uhsub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UHSUB8 - ARM_INS_UHSUB8 - uhsub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UMAAL - ARM_INS_UMAAL - umaal${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2UMLAL - ARM_INS_UMLAL - umlal${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* RLo */
  { CS_OP_REG, CS_AC_READ }, /* RHi */
  { 0 }
}},
{{ /* ARM_t2UMULL - ARM_INS_UMULL - umull${p}	$RdLo, $RdHi, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* RdLo */
  { CS_OP_REG, CS_AC_WRITE }, /* RdHi */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UQADD16 - ARM_INS_UQADD16 - uqadd16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UQADD8 - ARM_INS_UQADD8 - uqadd8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UQASX - ARM_INS_UQASX - uqasx${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UQSAX - ARM_INS_UQSAX - uqsax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UQSUB16 - ARM_INS_UQSUB16 - uqsub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UQSUB8 - ARM_INS_UQSUB8 - uqsub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2USAD8 - ARM_INS_USAD8 - usad8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2USADA8 - ARM_INS_USADA8 - usada8${p}	$Rd, $Rn, $Rm, $Ra */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_REG, CS_AC_READ }, /* Ra */
  { 0 }
}},
{{ /* ARM_t2USAT - ARM_INS_USAT - usat${p}	$Rd, $sat_imm, $Rn$sh */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* sat_imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* sh */
  { 0 }
}},
{{ /* ARM_t2USAT16 - ARM_INS_USAT16 - usat16${p}	$Rd, $sat_imm, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* sat_imm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_t2USAX - ARM_INS_USAX - usax${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2USUB16 - ARM_INS_USUB16 - usub16${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2USUB8 - ARM_INS_USUB8 - usub8${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t2UXTAB - ARM_INS_UXTAB - uxtab${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2UXTAB16 - ARM_INS_UXTAB16 - uxtab16${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2UXTAH - ARM_INS_UXTAH - uxtah${p}	$Rd, $Rn, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2UXTB - ARM_INS_UXTB - uxtb${p}.w	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2UXTB16 - ARM_INS_UXTB16 - uxtb16${p}	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2UXTH - ARM_INS_UXTH - uxth${p}.w	$Rd, $Rm$rot */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* rot */
  { 0 }
}},
{{ /* ARM_t2WLS - ARM_INS_WLS - wls	$LR, $Rn, $label */
  { CS_OP_REG, CS_AC_WRITE }, /* LR */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* label */
  { 0 }
}},
{{ /* ARM_tADC - ARM_INS_ADC - adc${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tADDhirr - ARM_INS_ADD - add${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tADDi3 - ARM_INS_ADD - add${s}${p}	$Rd, $Rm, $imm3 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm3 */
  { 0 }
}},
{{ /* ARM_tADDi8 - ARM_INS_ADD - add${s}${p}	$Rdn, $imm8 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm8 */
  { 0 }
}},
{{ /* ARM_tADDrSP - ARM_INS_ADD - add${p}	$Rdn, $sp, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* sp */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_tADDrSPi - ARM_INS_ADD - add${p}	$dst, $sp, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* dst */
  { CS_OP_REG, CS_AC_READ }, /* sp */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_tADDrr - ARM_INS_ADD - add${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tADDspi - ARM_INS_ADD - add${p}	$Rdn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_tADDspr - ARM_INS_ADD - add${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tADR - ARM_INS_ADR - adr{$p}	$Rd, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tAND - ARM_INS_AND - and${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tASRri - ARM_INS_ASR - asr${s}${p}	$Rd, $Rm, $imm5 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm5 */
  { 0 }
}},
{{ /* ARM_tASRrr - ARM_INS_ASR - asr${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tB - ARM_INS_B - b${p}	$target */
  { CS_OP_IMM, CS_AC_READ }, /* target */
  { 0 }
}},
{{ /* ARM_tBIC - ARM_INS_BIC - bic${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tBKPT - ARM_INS_BKPT - bkpt	$val */
  { CS_OP_IMM, CS_AC_READ }, /* val */
  { 0 }
}},
{{ /* ARM_tBL - ARM_INS_BL - bl${p}	$func */
  { CS_OP_IMM, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_tBLXNSr - ARM_INS_BLXNS - blxns${p}	$func */
  { CS_OP_REG, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_tBLXi - ARM_INS_BLX - blx${p}	$func */
  { CS_OP_IMM, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_tBLXr - ARM_INS_BLX - blx${p}	$func */
  { CS_OP_REG, CS_AC_READ }, /* func */
  { 0 }
}},
{{ /* ARM_tBX - ARM_INS_BX - bx${p}	$Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tBXNS - ARM_INS_BXNS - bxns${p}	$Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tBcc - ARM_INS_B - b${p}	$target */
  { CS_OP_IMM, CS_AC_READ }, /* target */
  { 0 }
}},
{{ /* ARM_tCBNZ - ARM_INS_CBNZ - cbnz	$Rn, $target */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* target */
  { 0 }
}},
{{ /* ARM_tCBZ - ARM_INS_CBZ - cbz	$Rn, $target */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* target */
  { 0 }
}},
{{ /* ARM_tCMNz - ARM_INS_CMN - cmn${p}	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tCMPhir - ARM_INS_CMP - cmp${p}	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tCMPi8 - ARM_INS_CMP - cmp${p}	$Rn, $imm8 */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm8 */
  { 0 }
}},
{{ /* ARM_tCMPr - ARM_INS_CMP - cmp${p}	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tCPS - ARM_INS_CPS - cps$imod $iflags */
  { CS_OP_IMM, CS_AC_READ }, /* imod */
  { CS_OP_IMM, CS_AC_READ }, /* iflags */
  { 0 }
}},
{{ /* ARM_tEOR - ARM_INS_EOR - eor${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tHINT - ARM_INS_YIELD - hint${p}	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_tHINT - ARM_INS_HINT - hint${p}	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_tHLT - ARM_INS_HLT - hlt	$val */
  { CS_OP_IMM, CS_AC_READ }, /* val */
  { 0 }
}},
{{ /* ARM_tLDMIA - ARM_INS_LDM - ldm${p}	$Rn, $regs */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_tLDRBi - ARM_INS_LDRB - ldrb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRBr - ARM_INS_LDRB - ldrb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRHi - ARM_INS_LDRH - ldrh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRHr - ARM_INS_LDRH - ldrh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRSB - ARM_INS_LDRSB - ldrsb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRSH - ARM_INS_LDRSH - ldrsh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRi - ARM_INS_LDR - ldr${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRpci - ARM_INS_LDR - ldr${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_IMM, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRr - ARM_INS_LDR - ldr${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLDRspi - ARM_INS_LDR - ldr${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_WRITE }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tLSLri - ARM_INS_LSL - lsl${s}${p}	$Rd, $Rm, $imm5 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm5 */
  { 0 }
}},
{{ /* ARM_tLSLrr - ARM_INS_LSL - lsl${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tLSRri - ARM_INS_LSR - lsr${s}${p}	$Rd, $Rm, $imm5 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm5 */
  { 0 }
}},
{{ /* ARM_tLSRrr - ARM_INS_LSR - lsr${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tMOVSr - ARM_INS_MOVS - movs	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tMOVi8 - ARM_INS_MOV - mov${s}${p}	$Rd, $imm8 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_IMM, CS_AC_READ }, /* imm8 */
  { 0 }
}},
{{ /* ARM_tMOVr - ARM_INS_MOV - mov${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tMUL - ARM_INS_MUL - mul${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tMVN - ARM_INS_MVN - mvn${s}${p}	$Rd, $Rn */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_tORR - ARM_INS_ORR - orr${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tPOP - ARM_INS_POP - pop${p}	$regs */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_tPUSH - ARM_INS_PUSH - push${p}	$regs */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_tREV - ARM_INS_REV - rev${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tREV16 - ARM_INS_REV16 - rev16${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tREVSH - ARM_INS_REVSH - revsh${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tROR - ARM_INS_ROR - ror${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tRSB - ARM_INS_RSB - rsb${s}${p}	$Rd, $Rn, #0 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { 0 }
}},
{{ /* ARM_tSBC - ARM_INS_SBC - sbc${s}${p}	$Rdn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tSETEND - ARM_INS_SETEND - setend	$end */
  { CS_OP_IMM, CS_AC_READ }, /* end */
  { 0 }
}},
{{ /* ARM_tSTMIA_UPD - ARM_INS_STM - stm${p}	$Rn!, $regs */
  { CS_OP_REG, CS_AC_WRITE }, /* wb */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* regs */
  { 0 }
}},
{{ /* ARM_tSTRBi - ARM_INS_STRB - strb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tSTRBr - ARM_INS_STRB - strb${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tSTRHi - ARM_INS_STRH - strh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tSTRHr - ARM_INS_STRH - strh${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tSTRi - ARM_INS_STR - str${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tSTRr - ARM_INS_STR - str${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tSTRspi - ARM_INS_STR - str${p}	$Rt, $addr */
  { CS_OP_REG, CS_AC_READ }, /* Rt */
  { CS_OP_MEM | CS_OP_REG, CS_AC_READ }, /* addr */
  { 0 }
}},
{{ /* ARM_tSUBi3 - ARM_INS_SUB - sub${s}${p}	$Rd, $Rm, $imm3 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { CS_OP_IMM, CS_AC_READ }, /* imm3 */
  { 0 }
}},
{{ /* ARM_tSUBi8 - ARM_INS_SUB - sub${s}${p}	$Rdn, $imm8 */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm8 */
  { 0 }
}},
{{ /* ARM_tSUBrr - ARM_INS_SUB - sub${s}${p}	$Rd, $Rn, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tSUBspi - ARM_INS_SUB - sub${p}	$Rdn, $imm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rdn */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_tSVC - ARM_INS_SVC - svc${p}	$imm */
  { CS_OP_IMM, CS_AC_READ }, /* imm */
  { 0 }
}},
{{ /* ARM_tSXTB - ARM_INS_SXTB - sxtb${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tSXTH - ARM_INS_SXTH - sxth${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tTRAP - ARM_INS_TRAP - trap */
  { 0 }
}},
{{ /* ARM_tTST - ARM_INS_TST - tst${p}	$Rn, $Rm */
  { CS_OP_REG, CS_AC_READ }, /* Rn */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tUDF - ARM_INS_UDF - udf	$imm8 */
  { CS_OP_IMM, CS_AC_READ }, /* imm8 */
  { 0 }
}},
{{ /* ARM_tUXTB - ARM_INS_UXTB - uxtb${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_tUXTH - ARM_INS_UXTH - uxth${p}	$Rd, $Rm */
  { CS_OP_REG, CS_AC_WRITE }, /* Rd */
  { CS_OP_REG, CS_AC_READ }, /* Rm */
  { 0 }
}},
{{ /* ARM_t__brkdiv0 - ARM_INS___BRKDIV0 - __brkdiv0 */
  { 0 }
}},
