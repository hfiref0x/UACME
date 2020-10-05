/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2020
*
*  TITLE:       FUBUKI.H
*
*  VERSION:     3.50
*
*  DATE:        14 Sep 2020
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

//
// Forwards
//
#include "winmm.h"

#define LoadedMsg      TEXT("Fubuki lock and loaded")

//default execution flow
#define AKAGI_FLAG_KILO  1

//suppress all additional output
#define AKAGI_FLAG_TANGO 2
