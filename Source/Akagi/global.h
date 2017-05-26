/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     2.72
*
*  DATE:        24 May 2017
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

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#define PAYLOAD_ID_NONE MAXDWORD

#ifdef _WIN64
#include "bin64res.h"
#define FUBUKI_ID IDR_FUBUKI64
#define HIBIKI_ID IDR_HIBIKI64
#define IKAZUCHI_ID IDR_IKAZUCHI64
#define AKATSUKI_ID IDR_AKATSUKI64
#else
#include "bin32res.h"
#define FUBUKI_ID IDR_FUBUKI32
#define HIBIKI_ID IDR_HIBIKI32
#define IKAZUCHI_ID IDR_IKAZUCHI32
#define AKATSUKI_ID PAYLOAD_ID_NONE //this module unavailable for 32 bit
#endif

#include <Windows.h>
#include <ntstatus.h>
#include <CommCtrl.h>
#include <shlobj.h>
#include "shared\ntos.h"
#include "shared\minirtl.h"
#include "shared\cmdline.h"
#include "shared\_filename.h"
#include "Shared\ldr.h"
#include "consts.h"
#include "compress.h"
#include "sup.h"
#include "methods\methods.h"
#include "windefend.h"

//default execution flow
#define AKAGI_FLAG_KILO  0

//suppress all additional output
#define AKAGI_FLAG_TANGO 1

typedef struct _UACME_CONTEXT {
    BOOL                    IsWow64;
    PVOID                   ucmHeap;
    pfnDecompressPayload    DecryptRoutine;
    HINSTANCE               hKernel32;
    HINSTANCE               hOle32;
    HINSTANCE               hShell32;
    ULONG                   dwBuildNumber;
    ULONG                   AkagiFlag;
    ULONG                   IFileOperationFlags;
    ULONG                   OptionalParameterLength;
    WCHAR                   szSystemDirectory[MAX_PATH + 1];//with end slash
    WCHAR                   szTempDirectory[MAX_PATH + 1]; //with end slash
    WCHAR                   szOptionalParameter[MAX_PATH + 1]; //limited to MAX_PATH
} UACMECONTEXT, *PUACMECONTEXT;

typedef UINT(WINAPI *pfnEntryPoint)();

typedef struct _UACME_THREAD_CONTEXT {
    TEB_ACTIVE_FRAME Frame;
    pfnEntryPoint ucmMain;
    DWORD ReturnedResult;
} UACME_THREAD_CONTEXT, *PUACME_THREAD_CONTEXT;

extern UACMECONTEXT g_ctx;
