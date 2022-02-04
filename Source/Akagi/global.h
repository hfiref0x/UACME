/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2022
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     3.59
*
*  DATE:        04 Feb 2022
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
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER
#pragma warning(disable: 6255 6263)  // alloca
#pragma warning(disable: 28159)

#define PAYLOAD_ID_NONE MAXDWORD

#define USER_REQUESTS_AUTOAPPROVED FALSE //auto approve any asking dialogs

#define SECRETS_ID IDR_SECRETS

#ifdef _WIN64
#include "bin64res.h"
#define FUBUKI_ID IDR_FUBUKI64
#define AKATSUKI_ID IDR_AKATSUKI64
#define FUBUKI32_ID IDR_FUBUKI32
#define KAMIKAZE_ID IDR_KAMIKAZE
#else
#include "bin32res.h"
#define FUBUKI_ID IDR_FUBUKI32
#define AKATSUKI_ID PAYLOAD_ID_NONE //this module unavailable for 32 bit
#define FUBUKI32_ID IDR_FUBUKI32
#define KAMIKAZE_ID IDR_KAMIKAZE
#endif

#include <Windows.h>
#include <ntstatus.h>
#include <CommCtrl.h>
#include <shlobj.h>
#include <AccCtrl.h>
#include <wintrust.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "rpcrt4.lib")

#pragma warning(push)
#pragma warning(disable: 4115) //named type definition in parentheses
#include <fusion.h>
#pragma warning(pop)

#include "shared\hde\hde64.h"
#include "shared\ntos\ntos.h"
#include "shared\ntos\ntbuilds.h"
#include "shared\minirtl.h"
#include "shared\cmdline.h"
#include "shared\_filename.h"
#include "shared\ldr.h"
#include "shared\windefend.h"
#include "shared\consts.h"
#include "sup.h"
#include "fusutil.h"
#include "compress.h"
#include "aic.h"
#include "stub.h"
#include "methods\methods.h"

//default execution flow
#define AKAGI_FLAG_KILO  1

//suppress all additional output
#define AKAGI_FLAG_TANGO 2

typedef struct _UACME_SHARED_CONTEXT {
    HANDLE hIsolatedNamespace;
    HANDLE hSharedSection;
    HANDLE hCompletionEvent;
} UACME_SHARED_CONTEXT, *PUACME_SHARED_CONTEXT;

typedef struct _UACME_CONTEXT {
    BOOLEAN                 IsWow64;
    BOOLEAN                 UserRequestsAutoApprove;
    BOOL                    OutputToDebugger;
    ULONG                   Cookie;
    ULONG                   dwBuildNumber;
    ULONG                   AkagiFlag;
    ULONG                   IFileOperationFlags;

    // Count of characters
    ULONG                   OptionalParameterLength; 

    PVOID                   ucmHeap;
    pfnDecompressPayload    DecompressRoutine;
    UACME_FUSION_CONTEXT    FusionContext;
    UACME_SHARED_CONTEXT    SharedContext;

    // Windows directory with end slash
    WCHAR                   szSystemRoot[MAX_PATH + 1];

    // Windows\System32 directory with end slash
    WCHAR                   szSystemDirectory[MAX_PATH + 1];

    // Current user temp directory with end slash
    WCHAR                   szTempDirectory[MAX_PATH + 1];

    // Current program directory with end slash
    WCHAR                   szCurrentDirectory[MAX_PATH + 1];

    // Optional parameter, limited to MAX_PATH
    WCHAR                   szOptionalParameter[MAX_PATH + 1]; 

    // Default payload (system32\cmd.exe), limited to MAX_PATH
    WCHAR                   szDefaultPayload[MAX_PATH + 1]; 
} UACMECONTEXT, *PUACMECONTEXT;

typedef struct _UACME_PARAM_BLOCK {
    ULONG Crc32;
    ULONG SessionId;
    ULONG AkagiFlag;
    WCHAR szParameter[MAX_PATH + 1];
    WCHAR szDesktop[MAX_PATH + 1];
    WCHAR szWinstation[MAX_PATH + 1];
    WCHAR szSignalObject[MAX_PATH + 1];
} UACME_PARAM_BLOCK, *PUACME_PARAM_BLOCK;

typedef UINT(WINAPI *pfnEntryPoint)(
    _In_opt_ UCM_METHOD Method,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_opt_ ULONG OptionalParameterLength,
    _In_ BOOL OutputToDebugger
    );

typedef struct _UACME_THREAD_CONTEXT {
    TEB_ACTIVE_FRAME Frame;
    pfnEntryPoint ucmMain;
    DWORD ReturnedResult;
    ULONG OptionalParameterLength;
    LPWSTR OptionalParameter;
} UACME_THREAD_CONTEXT, * PUACME_THREAD_CONTEXT;

extern PUACMECONTEXT g_ctx;
extern HINSTANCE g_hInstance;
