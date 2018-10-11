/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2018
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.33
*
*  DATE:        11 Oct 2018
*
*  Common header file for the program support routines.
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

#include "shared\libinc.h"

//disable nonmeaningful warnings.
#pragma warning(disable: 28278) // Function name appears with no prototype in scope
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4091)  // 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#include <Windows.h>
#include <ntstatus.h>
#include <CommCtrl.h>
#include "shared\ntos.h"
#include "shared\ntsxs.h"
#include "shared\minirtl.h"
#include "shared\_filename.h"
#include "shared\cmdline.h"
#include "consts.h"
#include "logger.h"
#include "wintrustex.h"
#include "sup.h"
#include "cui.h"
#include "appinfo.h"
#include "basic.h"
#include "comobj.h"
#include "fusion.h"
#ifdef _DEBUG
#include "tests\test_fusion.h"
#endif

extern ULONG g_NtBuildNumber;
extern BOOL g_VerboseOutput;
