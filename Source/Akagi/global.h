/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
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

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) //exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#define GENERATE_COMPRESSED_PAYLOAD
#ifndef _DEBUG
#undef GENERATE_COMPRESSED_PAYLOAD
#endif

#ifdef _WIN64
#include "fubuki64comp.h"
#include "hibiki64comp.h"
#include "kongou64comp.h"
#define FUBUKIDLL Fubuki64Comp
#define HIBIKIDLL Hibiki64Comp
#define KONGOUDLL Kongou64Comp
#else
#include "fubuki32comp.h"
#include "hibiki32comp.h"
#include "kongou32comp.h"
#define FUBUKIDLL Fubuki32Comp
#define HIBIKIDLL Hibiki32Comp
#define KONGOUDLL Kongou32Comp
#endif

typedef enum _UACBYPASSMETHOD {
	UacMethodSysprep1 = 1,
	UacMethodSysprep2,
	UacMethodOobe,
	UacMethodRedirectExe,
	UacMethodSimda,
	UacMethodCarberp1,
	UacMethodCarberp2,
	UacMethodTilon,
	UacMethodAVrf,
	UacMethodWinsat,
	UacMethodShimPatch,
	UacMethodSysprep3,
	UacMethodMMC,
	UacMethodH1N1,
	UacMethodGeneric,
	UacMethodGWX,
	UacMethodMax
} UACBYPASSMETHOD;

#include <Windows.h>
#include <ntstatus.h>
#include "..\shared\ntos.h"
#include "..\shared\minirtl.h"
#include "consts.h"
#include "compress.h"
#include "sup.h"
#include "inject.h"
#include "cmdline.h"
#include "pitou.h"
#include "gootkit.h"
#include "simda.h"
#include "carberp.h"
#include "hybrids.h"



typedef struct _UACME_CONTEXT {
	BOOL                IsWow64;
	UACBYPASSMETHOD     Method;
	HINSTANCE           hKernel32;
	HINSTANCE           hOle32;
	HINSTANCE           hShell32;
	PVOID               PayloadDll;
	ULONG               PayloadDllSize;
	RTL_OSVERSIONINFOW  osver;
	WCHAR               szSystemDirectory[MAX_PATH + 1];
} UACMECONTEXT, *PUACMECONTEXT;

extern UACMECONTEXT g_ctx;
