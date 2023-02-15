//===-- ARMBaseInfo.cpp - ARM Base encoding information------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides basic encoding and assembly information for ARM.
//
//===----------------------------------------------------------------------===//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "ARMBaseInfo.h"

#define CONCAT(a, b)	CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

// lookup system register using 12-bit SYSm value.
// Note: the search is uniqued using M1 mask
const MClassSysReg *lookupMClassSysRegBy12bitSYSmValue(unsigned SYSm)
{
	return lookupMClassSysRegByM1Encoding12(SYSm);
}

// returns APSR with _<bits> qualifier.
// Note: ARMv7-M deprecates using MSR APSR without a _<bits> qualifier
const MClassSysReg *lookupMClassSysRegAPSRNonDeprecated(unsigned SYSm)
{
	return lookupMClassSysRegByM2M3Encoding8((1 << 9) | (SYSm & 0xFF));
}

// lookup system registers using 8-bit SYSm value
const MClassSysReg *lookupMClassSysRegBy8bitSYSmValue(unsigned SYSm)
{
	return lookupMClassSysRegByM2M3Encoding8((1 << 8) | (SYSm & 0xFF));
}
