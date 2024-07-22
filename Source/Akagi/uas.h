/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021 - 2024
*
*  TITLE:       UAS.H
*
*  VERSION:     3.66
*
*  DATE:        22 Jul 2024
*
*  UserAssocSet signature file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// UserAssocSet patterns.
//

// mov r8, [rbx + 40h]
// mov rdx, [rbx + 38h]
// mov ecx, 1
// call UserAssocSet
static BYTE UserAssocSet_7601[] = {
    0x4C, 0x8B, 0x43, 0x40, 0x48, 0x8B, 0x53, 0x38, 0xB9, 0x01, 0x00, 0x00, 0x00
};

// mov r8, rsi
// mov rdx, rbx
// mov ecx, 2
// call UserAssocSet
static BYTE UserAssocSet_9600[] = {
    0x4C, 0x8B, 0xC6, 0x48, 0x8B, 0xD3, 0xB9, 0x02, 0x00, 0x00, 0x00
};

// imul rax, 4Eh
// mov ecx, 2
// add r8, rax
// call UserAssocSet
static BYTE UserAssocSet_14393[] = {
    0x48, 0x6B, 0xC0, 0x4E, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x4C, 0x03, 0xC0
};

// mov r8, rsi
// mov r9d, ecx
// mov rdx, r15
// call UserAssocSet
static BYTE UserAssocSet_17763_v1554[] = {
    0x4C, 0x8B, 0xC6, 0x44, 0x8B, 0xC9, 0x49, 0x8B, 0xD7
};

// mov ecx, r9d
// mov r8, rdi
// mov rdx, rsi
// call UserAssocSet
static BYTE UserAssocSet_17763_v1728[] = {
    0x41, 0x8B, 0xC9, 0x4C, 0x8B, 0xC7, 0x48, 0x8B, 0xD6
};

// mov ecx, eax
// mov r8, rdi
// mov rdx, rbp
// call UserAssocSet
static BYTE UserAssocSet_17763_v1971[] = {
    0x44, 0x8B, 0xC8, 0x8B, 0xC8, 0x4C, 0x8B, 0xC7, 0x48, 0x8B, 0xD5
};

// mov r9d, ecx
// mov r8, rsi
// mov rdx, r15
// call UserAssocSet
static BYTE UserAssocSet_18362[] = {
    0x44, 0x8B, 0xC9, 0x4C, 0x8B, 0xC6, 0x49, 0x8B, 0xD7
};

static BYTE UserAssocSet_18362_v2[] = {
    0x4C, 0x8B, 0xC7, 0x41, 0x8B, 0xC9, 0x48, 0x8B, 0xD6
};

// mov r8, rsi
// mov r9d, ecx
// mov rdx, r15
// call UserAssocSet
static BYTE UserAssocSet_18363[] = {
    0x4C, 0x8B, 0xC6, 0x44, 0x8B, 0xC9, 0x49, 0x8B, 0xD7
};

// mov r9d, ecx
// mov r8, rsi
// mov rdx, r15
// call UserAssocSet
static BYTE UserAssocSet_19041[] = {
    0x44, 0x8B, 0xC9, 0x4C, 0x8B, 0xC6, 0x49, 0x8B, 0xD7
};

// mov r8, rdi
// mov rdx, rsi
// mov ecx, r9d
// call UserAssocSet
static BYTE UserAssocSet_19042[] = {
    0x4C, 0x8B, 0xC7, 0x48, 0x8B, 0xD6, 0x41, 0x8B, 0xC9
};

// mov r8, rdi
// mov rdx, rbp
// mov ecx, eax
// call UserAssocSet
static BYTE UserAssocSet_19043_v1023[] = {
    0x4C, 0x8B, 0xC7, 0x48, 0x8B, 0xD5, 0x8B, 0xC8
};

// mov r8, rsi
// mov rdx, r14
// mov eax, ecx
// call UserAssocSet
static BYTE UserAssocSet_22000[] = {
    0x4C, 0x8B, 0xC6, 0x49, 0x8B, 0xD6, 0x8B, 0xC8
};

// mov r9d, ecx
// mov r8, rdi
// mov rdx, r14
// call UserAssocSet
static BYTE UserAssocSet_22621[] = {
    0x44, 0x8B, 0xC9, 0x4C, 0x8B, 0xC7, 0x49, 0x8B, 0xD6
};

// mov r8, rsi
// mov rdx, r15
// lea ecx, [r9 + 2]
// call UserAssocSet
static BYTE UserAssocSet_26100[] = {
    0x4C, 0x8B, 0xC6, 0x49, 0x8B, 0xD7, 0x41, 0x8D, 0x49, 0x02
};

//
// End of UserAssocSet patterns.
//

//
// Windows 7 SP1 7601
//
USER_ASSOC_PATTERN UAS_7601 = { UserAssocSet_7601, sizeof(UserAssocSet_7601) };
PVOID UAS_PATTERN_TABLE_7601[] = { &UAS_7601 };
USER_ASSOC_SIGNATURE UAS_SIG_7601 = { NT_WIN7_SP1, NT_WIN7_SP1, RTL_NUMBER_OF(UAS_PATTERN_TABLE_7601), &UAS_PATTERN_TABLE_7601 };

//
// Windows 8 (9600)
//
USER_ASSOC_PATTERN UAS_9600 = { UserAssocSet_9600, sizeof(UserAssocSet_9600) };
PVOID UAS_PATTERN_TABLE_9600[] = { &UAS_9600 };
USER_ASSOC_SIGNATURE UAS_SIG_9600 = { NT_WIN8_BLUE, NT_WIN8_BLUE, RTL_NUMBER_OF(UAS_PATTERN_TABLE_9600), &UAS_PATTERN_TABLE_9600 };

//
// Windows 10 1607 (14393)
//
USER_ASSOC_PATTERN UAS_14393 = { UserAssocSet_14393, sizeof(UserAssocSet_14393) };
PVOID UAS_PATTERN_TABLE_14393[] = { &UAS_14393 };
USER_ASSOC_SIGNATURE UAS_SIG_14393 = { NT_WIN10_REDSTONE1, NT_WIN10_REDSTONE1, RTL_NUMBER_OF(UAS_PATTERN_TABLE_14393), &UAS_PATTERN_TABLE_14393 };

//
// Windows 10 1809 (17763)
//
USER_ASSOC_PATTERN UAS_17763_1554 = { UserAssocSet_17763_v1554, sizeof(UserAssocSet_17763_v1554) };
USER_ASSOC_PATTERN UAS_17763_1728 = { UserAssocSet_17763_v1728, sizeof(UserAssocSet_17763_v1728) };
USER_ASSOC_PATTERN UAS_17763_1971 = { UserAssocSet_17763_v1971, sizeof(UserAssocSet_17763_v1971) };
PVOID UAS_PATTERN_TABLE_17763[] = { &UAS_17763_1554, &UAS_17763_1728, &UAS_17763_1971 };
USER_ASSOC_SIGNATURE UAS_SIG_17763 = { NT_WIN10_REDSTONE5, NT_WIN10_REDSTONE5, RTL_NUMBER_OF(UAS_PATTERN_TABLE_17763), &UAS_PATTERN_TABLE_17763 };

//
// Windows 10 1903 (18362)
//
USER_ASSOC_PATTERN UAS_18362 = { UserAssocSet_18362, sizeof(UserAssocSet_18362) };
USER_ASSOC_PATTERN UAS_18362_1350 = { UserAssocSet_18362_v2, sizeof(UserAssocSet_18362_v2) };
PVOID UAS_PATTERN_TABLE_18362[] = { &UAS_18362, &UAS_18362_1350 };
USER_ASSOC_SIGNATURE UAS_SIG_18362 = { NT_WIN10_19H1, NT_WIN10_19H1, RTL_NUMBER_OF(UAS_PATTERN_TABLE_18362), &UAS_PATTERN_TABLE_18362 };

//
// Windows 10 1909 (18363)
//
USER_ASSOC_PATTERN UAS_18363 = { UserAssocSet_18363, sizeof(UserAssocSet_18363) };
PVOID UAS_PATTERN_TABLE_18363[] = { &UAS_18363, &UAS_18362_1350 };
USER_ASSOC_SIGNATURE UAS_SIG_18363 = { NT_WIN10_19H2, NT_WIN10_19H2, RTL_NUMBER_OF(UAS_PATTERN_TABLE_18363), &UAS_PATTERN_TABLE_18363 };

//
// Windows 10 2004 (19041)
//
USER_ASSOC_PATTERN UAS_19041 = { UserAssocSet_19041, sizeof(UserAssocSet_19041) };
USER_ASSOC_PATTERN UAS_19042_789 = { UserAssocSet_19042, sizeof(UserAssocSet_19042) }; //same as for 19042
PVOID UAS_PATTERN_TABLE_19041[] = { &UAS_19041, &UAS_19042_789 };
USER_ASSOC_SIGNATURE UAS_SIG_19041 = { NT_WIN10_20H1, NT_WIN10_20H1, RTL_NUMBER_OF(UAS_PATTERN_TABLE_19041), &UAS_PATTERN_TABLE_19041 };

//
// Windows 10 2009 (19042/19043/19044)
//
USER_ASSOC_PATTERN UAS_19043 = { UserAssocSet_19043_v1023, sizeof(UserAssocSet_19043_v1023) };
PVOID UAS_PATTERN_TABLE_19042_19043[] = { &UAS_19042_789, &UAS_19043 };
USER_ASSOC_SIGNATURE UAS_SIG_19042_19043 = { NT_WIN10_20H2, NT_WIN10_21H2, RTL_NUMBER_OF(UAS_PATTERN_TABLE_19042_19043), &UAS_PATTERN_TABLE_19042_19043 };

// Windows 11 21H2 (22000)
USER_ASSOC_PATTERN UAS_22000 = { UserAssocSet_22000, sizeof(UserAssocSet_22000) };
PVOID UAS_PATTERN_TABLE_22000[] = { &UAS_22000 };
USER_ASSOC_SIGNATURE UAS_SIG_22000 = { NT_WIN11_21H2 , NT_WIN11_21H2, RTL_NUMBER_OF(UAS_PATTERN_TABLE_22000), &UAS_PATTERN_TABLE_22000 };

//
// Windows 11 22H2-23H2 (22621/22631)
//
USER_ASSOC_PATTERN UAS_22621 = { UserAssocSet_22621, sizeof(UserAssocSet_22621) };
PVOID UAS_PATTERN_TABLE_22621[] = { &UAS_22621 };
USER_ASSOC_SIGNATURE UAS_SIG_22621 = { NT_WIN11_22H2, NT_WIN11_23H2, RTL_NUMBER_OF(UAS_PATTERN_TABLE_22621), &UAS_PATTERN_TABLE_22621 };

//
// Windows 11 24H2 (26100+)
//
USER_ASSOC_PATTERN UAS_26100 = { UserAssocSet_26100, sizeof(UserAssocSet_26100) };
PVOID UAS_PATTERN_TABLE_26100[] = { &UAS_26100 };
USER_ASSOC_SIGNATURE UAS_SIG_26100 = { NT_WIN11_24H2, NT_WIN11_24H2, RTL_NUMBER_OF(UAS_PATTERN_TABLE_26100), &UAS_PATTERN_TABLE_26100 };
