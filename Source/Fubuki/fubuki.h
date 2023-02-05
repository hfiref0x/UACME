/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2023
*
*  TITLE:       FUBUKI.H
*
*  VERSION:     3.64
*
*  DATE:        04 Feb 2023
*
*  Fubuki global include header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#include "shared\shared.h"
#include "shared\libinc.h"
#include "shared\cmdline.h"

#include "uihacks.h"
#include "pca.h"

//
// Forwards
//
#include "winmm.h"
#include "atldll.h"

#define LoadedMsg      TEXT("Fubuki lock and loaded")

//default execution flow
#define AKAGI_FLAG_KILO  1

//suppress all additional output
#define AKAGI_FLAG_TANGO 2

extern UACME_PARAM_BLOCK g_SharedParams;
