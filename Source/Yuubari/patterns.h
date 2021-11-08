/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       PATTERNS.H
*
*  VERSION:     1.51
*
*  DATE:        31 Oct 2021
*
*  Patterns for supported AppInfo versions.
*
*  Minimum client: 7600
*
*  Maximum client: 22000
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// g_MmcBlock
//
const unsigned char ptMmcBlock_7600[] = {
    0x48, 0x8D, 0x3C, 0x40, 0x4C, 0x39, 0x6C, 0xFB
};
const unsigned char ptMmcBlock_7601[] = {
    0x48, 0x8B, 0x55, 0x00, 0x48, 0x8B, 0xCF, 0xFF, 0x15
};
const unsigned char ptMmcBlock_9200[] = {
    0x49, 0x8B, 0x16, 0x48, 0x8B, 0xCE, 0xFF, 0x15
};
const unsigned char ptMmcBlock_9600[] = {
    0x48, 0x8b, 0x17, 0x49, 0x8b, 0xce, 0xff, 0x15
};
const unsigned char ptMmcBlock_10240[] = {
    0x49, 0x8B, 0x14, 0x24, 0x49, 0x8B, 0xCE, 0xFF, 0x15
};
const unsigned char ptMmcBlock_10586_16299[] = {
    0x49, 0x8B, 0x16, 0x49, 0x8B, 0xCD, 0xFF, 0x15
};
const unsigned char ptMmcBlock_16300_17134[] = {
    0x41, 0x8B, 0xF7, 0x49, 0x8B, 0x16, 0x48, 0x8B
};

//
// xor     r15d, r15d
//
const unsigned char ptMmcBlock_Start[] = {
    0x45, 0x33, 0xFF
};

//
// xor     r13d, r13d
// mov     rcx
//
const unsigned char ptMmcBlock_StartW11[] = {
    0xBA, 0x0D, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xCF
};
