/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: 464bda7750a3ba9e23823fc707d7e7b6fc38438d */
/* LLVM-tag: llvmorg-16.0.2-5-g464bda7750a3 */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_BANKEDREG_DECL
#undef GET_BANKEDREG_DECL
#endif

#ifdef GET_MCLASSSYSREG_DECL
#undef GET_MCLASSSYSREG_DECL
#endif

#ifdef GET_BANKEDREG_DECL
#undef GET_BANKEDREG_DECL
const BankedReg *lookupBankedRegByEncoding(uint8_t Encoding);
#endif

#ifdef GET_MCLASSSYSREG_DECL
#undef GET_MCLASSSYSREG_DECL
const MClassSysReg *lookupMClassSysRegByM1Encoding12(uint16_t M1Encoding12);
const MClassSysReg *lookupMClassSysRegByM2M3Encoding8(uint16_t M2M3Encoding8);
const MClassSysReg *lookupMClassSysRegByEncoding(uint16_t Encoding);
#endif

#ifdef GET_BANKEDREG_IMPL
#undef GET_BANKEDREG_IMPL
static const BankedReg BankedRegsList[] = {
  { "elr_hyp", 0x1E }, // 0
  { "lr_abt", 0x14 }, // 1
  { "lr_fiq", 0xE }, // 2
  { "lr_irq", 0x10 }, // 3
  { "lr_mon", 0x1C }, // 4
  { "lr_svc", 0x12 }, // 5
  { "lr_und", 0x16 }, // 6
  { "lr_usr", 0x6 }, // 7
  { "r10_fiq", 0xA }, // 8
  { "r10_usr", 0x2 }, // 9
  { "r11_fiq", 0xB }, // 10
  { "r11_usr", 0x3 }, // 11
  { "r12_fiq", 0xC }, // 12
  { "r12_usr", 0x4 }, // 13
  { "r8_fiq", 0x8 }, // 14
  { "r8_usr", 0x0 }, // 15
  { "r9_fiq", 0x9 }, // 16
  { "r9_usr", 0x1 }, // 17
  { "spsr_abt", 0x34 }, // 18
  { "spsr_fiq", 0x2E }, // 19
  { "spsr_hyp", 0x3E }, // 20
  { "spsr_irq", 0x30 }, // 21
  { "spsr_mon", 0x3C }, // 22
  { "spsr_svc", 0x32 }, // 23
  { "spsr_und", 0x36 }, // 24
  { "sp_abt", 0x15 }, // 25
  { "sp_fiq", 0xD }, // 26
  { "sp_hyp", 0x1F }, // 27
  { "sp_irq", 0x11 }, // 28
  { "sp_mon", 0x1D }, // 29
  { "sp_svc", 0x13 }, // 30
  { "sp_und", 0x17 }, // 31
  { "sp_usr", 0x5 }, // 32
  };

const BankedReg *lookupBankedRegByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x0, 15 },
    { 0x1, 17 },
    { 0x2, 9 },
    { 0x3, 11 },
    { 0x4, 13 },
    { 0x5, 32 },
    { 0x6, 7 },
    { 0x8, 14 },
    { 0x9, 16 },
    { 0xA, 8 },
    { 0xB, 10 },
    { 0xC, 12 },
    { 0xD, 26 },
    { 0xE, 2 },
    { 0x10, 3 },
    { 0x11, 28 },
    { 0x12, 5 },
    { 0x13, 30 },
    { 0x14, 1 },
    { 0x15, 25 },
    { 0x16, 6 },
    { 0x17, 31 },
    { 0x1C, 4 },
    { 0x1D, 29 },
    { 0x1E, 0 },
    { 0x1F, 27 },
    { 0x2E, 19 },
    { 0x30, 21 },
    { 0x32, 23 },
    { 0x34, 18 },
    { 0x36, 24 },
    { 0x3C, 22 },
    { 0x3E, 20 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &BankedRegsList[Index[i].index];
}

#endif

#ifdef GET_MCLASSSYSREG_IMPL
#undef GET_MCLASSSYSREG_IMPL
static const MClassSysReg MClassSysRegsList[] = {
  { "apsr", 0x800, 0x100, 0x800,  {0}  }, // 0
  { "apsr_g", 0x400, 0x0, 0x400,  {ARM_FeatureDSP}  }, // 1
  { "apsr_nzcvq", 0x1800, 0x200, 0x800,  {0}  }, // 2
  { "apsr_nzcvqg", 0xC00, 0x300, 0xC00,  {ARM_FeatureDSP}  }, // 3
  { "basepri", 0x811, 0x111, 0x811,  {ARM_HasV7Ops}  }, // 4
  { "basepri_max", 0x812, 0x112, 0x812,  {ARM_HasV7Ops}  }, // 5
  { "basepri_ns", 0x891, 0x191, 0x891,  {ARM_Feature8MSecExt, ARM_HasV7Ops}  }, // 6
  { "control", 0x814, 0x114, 0x814,  {0}  }, // 7
  { "control_ns", 0x894, 0x194, 0x894,  {ARM_Feature8MSecExt}  }, // 8
  { "eapsr", 0x802, 0x102, 0x802,  {0}  }, // 9
  { "eapsr_g", 0x402, 0x2, 0x402,  {ARM_FeatureDSP}  }, // 10
  { "eapsr_nzcvq", 0x1802, 0x202, 0x802,  {0}  }, // 11
  { "eapsr_nzcvqg", 0xC02, 0x302, 0xC02,  {ARM_FeatureDSP}  }, // 12
  { "epsr", 0x806, 0x106, 0x806,  {0}  }, // 13
  { "faultmask", 0x813, 0x113, 0x813,  {ARM_HasV7Ops}  }, // 14
  { "faultmask_ns", 0x893, 0x193, 0x893,  {ARM_Feature8MSecExt, ARM_HasV7Ops}  }, // 15
  { "iapsr", 0x801, 0x101, 0x801,  {0}  }, // 16
  { "iapsr_g", 0x401, 0x1, 0x401,  {ARM_FeatureDSP}  }, // 17
  { "iapsr_nzcvq", 0x1801, 0x201, 0x801,  {0}  }, // 18
  { "iapsr_nzcvqg", 0xC01, 0x301, 0xC01,  {ARM_FeatureDSP}  }, // 19
  { "iepsr", 0x807, 0x107, 0x807,  {0}  }, // 20
  { "ipsr", 0x805, 0x105, 0x805,  {0}  }, // 21
  { "msp", 0x808, 0x108, 0x808,  {0}  }, // 22
  { "msplim", 0x80A, 0x10A, 0x80A,  {ARM_HasV8MBaselineOps}  }, // 23
  { "msplim_ns", 0x88A, 0x18A, 0x88A,  {ARM_Feature8MSecExt, ARM_HasV8MBaselineOps}  }, // 24
  { "msp_ns", 0x888, 0x188, 0x888,  {ARM_Feature8MSecExt}  }, // 25
  { "pac_key_p_0", 0x820, 0x120, 0x820,  {ARM_FeaturePACBTI}  }, // 26
  { "pac_key_p_0_ns", 0x8A0, 0x1A0, 0x8A0,  {ARM_FeaturePACBTI}  }, // 27
  { "pac_key_p_1", 0x821, 0x121, 0x821,  {ARM_FeaturePACBTI}  }, // 28
  { "pac_key_p_1_ns", 0x8A1, 0x1A1, 0x8A1,  {ARM_FeaturePACBTI}  }, // 29
  { "pac_key_p_2", 0x822, 0x122, 0x822,  {ARM_FeaturePACBTI}  }, // 30
  { "pac_key_p_2_ns", 0x8A2, 0x1A2, 0x8A2,  {ARM_FeaturePACBTI}  }, // 31
  { "pac_key_p_3", 0x823, 0x123, 0x823,  {ARM_FeaturePACBTI}  }, // 32
  { "pac_key_p_3_ns", 0x8A3, 0x1A3, 0x8A3,  {ARM_FeaturePACBTI}  }, // 33
  { "pac_key_u_0", 0x824, 0x124, 0x824,  {ARM_FeaturePACBTI}  }, // 34
  { "pac_key_u_0_ns", 0x8A4, 0x1A4, 0x8A4,  {ARM_FeaturePACBTI}  }, // 35
  { "pac_key_u_1", 0x825, 0x125, 0x825,  {ARM_FeaturePACBTI}  }, // 36
  { "pac_key_u_1_ns", 0x8A5, 0x1A5, 0x8A5,  {ARM_FeaturePACBTI}  }, // 37
  { "pac_key_u_2", 0x826, 0x126, 0x826,  {ARM_FeaturePACBTI}  }, // 38
  { "pac_key_u_2_ns", 0x8A6, 0x1A6, 0x8A6,  {ARM_FeaturePACBTI}  }, // 39
  { "pac_key_u_3", 0x827, 0x127, 0x827,  {ARM_FeaturePACBTI}  }, // 40
  { "pac_key_u_3_ns", 0x8A7, 0x1A7, 0x8A7,  {ARM_FeaturePACBTI}  }, // 41
  { "primask", 0x810, 0x110, 0x810,  {0}  }, // 42
  { "primask_ns", 0x890, 0x190, 0x890,  {0}  }, // 43
  { "psp", 0x809, 0x109, 0x809,  {0}  }, // 44
  { "psplim", 0x80B, 0x10B, 0x80B,  {ARM_HasV8MBaselineOps}  }, // 45
  { "psplim_ns", 0x88B, 0x18B, 0x88B,  {ARM_Feature8MSecExt, ARM_HasV8MBaselineOps}  }, // 46
  { "psp_ns", 0x889, 0x189, 0x889,  {ARM_Feature8MSecExt}  }, // 47
  { "sp_ns", 0x898, 0x198, 0x898,  {ARM_Feature8MSecExt}  }, // 48
  { "xpsr", 0x803, 0x103, 0x803,  {0}  }, // 49
  { "xpsr_g", 0x403, 0x3, 0x403,  {ARM_FeatureDSP}  }, // 50
  { "xpsr_nzcvq", 0x1803, 0x203, 0x803,  {0}  }, // 51
  { "xpsr_nzcvqg", 0xC03, 0x303, 0xC03,  {ARM_FeatureDSP}  }, // 52
  };

const MClassSysReg *lookupMClassSysRegByM1Encoding12(uint16_t M1Encoding12) {
  static const struct IndexType Index[] = {
    { 0x400, 1 },
    { 0x401, 17 },
    { 0x402, 10 },
    { 0x403, 50 },
    { 0x800, 0 },
    { 0x801, 16 },
    { 0x802, 9 },
    { 0x803, 49 },
    { 0x805, 21 },
    { 0x806, 13 },
    { 0x807, 20 },
    { 0x808, 22 },
    { 0x809, 44 },
    { 0x80A, 23 },
    { 0x80B, 45 },
    { 0x810, 42 },
    { 0x811, 4 },
    { 0x812, 5 },
    { 0x813, 14 },
    { 0x814, 7 },
    { 0x820, 26 },
    { 0x821, 28 },
    { 0x822, 30 },
    { 0x823, 32 },
    { 0x824, 34 },
    { 0x825, 36 },
    { 0x826, 38 },
    { 0x827, 40 },
    { 0x888, 25 },
    { 0x889, 47 },
    { 0x88A, 24 },
    { 0x88B, 46 },
    { 0x890, 43 },
    { 0x891, 6 },
    { 0x893, 15 },
    { 0x894, 8 },
    { 0x898, 48 },
    { 0x8A0, 27 },
    { 0x8A1, 29 },
    { 0x8A2, 31 },
    { 0x8A3, 33 },
    { 0x8A4, 35 },
    { 0x8A5, 37 },
    { 0x8A6, 39 },
    { 0x8A7, 41 },
    { 0xC00, 3 },
    { 0xC01, 19 },
    { 0xC02, 12 },
    { 0xC03, 52 },
    { 0x1800, 2 },
    { 0x1801, 18 },
    { 0x1802, 11 },
    { 0x1803, 51 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), M1Encoding12);
   if (i == -1)
      return NULL;
   else
      return &MClassSysRegsList[Index[i].index];
}

const MClassSysReg *lookupMClassSysRegByM2M3Encoding8(uint16_t M2M3Encoding8) {
  static const struct IndexType Index[] = {
    { 0x0, 1 },
    { 0x1, 17 },
    { 0x2, 10 },
    { 0x3, 50 },
    { 0x100, 0 },
    { 0x101, 16 },
    { 0x102, 9 },
    { 0x103, 49 },
    { 0x105, 21 },
    { 0x106, 13 },
    { 0x107, 20 },
    { 0x108, 22 },
    { 0x109, 44 },
    { 0x10A, 23 },
    { 0x10B, 45 },
    { 0x110, 42 },
    { 0x111, 4 },
    { 0x112, 5 },
    { 0x113, 14 },
    { 0x114, 7 },
    { 0x120, 26 },
    { 0x121, 28 },
    { 0x122, 30 },
    { 0x123, 32 },
    { 0x124, 34 },
    { 0x125, 36 },
    { 0x126, 38 },
    { 0x127, 40 },
    { 0x188, 25 },
    { 0x189, 47 },
    { 0x18A, 24 },
    { 0x18B, 46 },
    { 0x190, 43 },
    { 0x191, 6 },
    { 0x193, 15 },
    { 0x194, 8 },
    { 0x198, 48 },
    { 0x1A0, 27 },
    { 0x1A1, 29 },
    { 0x1A2, 31 },
    { 0x1A3, 33 },
    { 0x1A4, 35 },
    { 0x1A5, 37 },
    { 0x1A6, 39 },
    { 0x1A7, 41 },
    { 0x200, 2 },
    { 0x201, 18 },
    { 0x202, 11 },
    { 0x203, 51 },
    { 0x300, 3 },
    { 0x301, 19 },
    { 0x302, 12 },
    { 0x303, 52 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), M2M3Encoding8);
   if (i == -1)
      return NULL;
   else
      return &MClassSysRegsList[Index[i].index];
}

const MClassSysReg *lookupMClassSysRegByEncoding(uint16_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x400, 1 },
    { 0x401, 17 },
    { 0x402, 10 },
    { 0x403, 50 },
    { 0x800, 0 },
    { 0x800, 2 },
    { 0x801, 16 },
    { 0x801, 18 },
    { 0x802, 9 },
    { 0x802, 11 },
    { 0x803, 49 },
    { 0x803, 51 },
    { 0x805, 21 },
    { 0x806, 13 },
    { 0x807, 20 },
    { 0x808, 22 },
    { 0x809, 44 },
    { 0x80A, 23 },
    { 0x80B, 45 },
    { 0x810, 42 },
    { 0x811, 4 },
    { 0x812, 5 },
    { 0x813, 14 },
    { 0x814, 7 },
    { 0x820, 26 },
    { 0x821, 28 },
    { 0x822, 30 },
    { 0x823, 32 },
    { 0x824, 34 },
    { 0x825, 36 },
    { 0x826, 38 },
    { 0x827, 40 },
    { 0x888, 25 },
    { 0x889, 47 },
    { 0x88A, 24 },
    { 0x88B, 46 },
    { 0x890, 43 },
    { 0x891, 6 },
    { 0x893, 15 },
    { 0x894, 8 },
    { 0x898, 48 },
    { 0x8A0, 27 },
    { 0x8A1, 29 },
    { 0x8A2, 31 },
    { 0x8A3, 33 },
    { 0x8A4, 35 },
    { 0x8A5, 37 },
    { 0x8A6, 39 },
    { 0x8A7, 41 },
    { 0xC00, 3 },
    { 0xC01, 19 },
    { 0xC02, 12 },
    { 0xC03, 52 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &MClassSysRegsList[Index[i].index];
}

#endif

