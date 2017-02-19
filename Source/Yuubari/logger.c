/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       LOGGER.C
*
*  VERSION:     1.0F
*
*  DATE:        14 Feb 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* LoggerCreate
*
* Purpose:
*
* Create log file.
*
*/
HANDLE LoggerCreate(
    _In_opt_ LPWSTR lpLogFileName
    )
{
    WCHAR ch;
    LPWSTR fname = lpLogFileName;
    HANDLE hFile;
    DWORD bytesIO;

    if (lpLogFileName == NULL) {
        fname = TEXT("log.log");
    }
    hFile = CreateFile(fname, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        ch = (WCHAR)0xFEFF;
        WriteFile(hFile, &ch, sizeof(WCHAR), &bytesIO, NULL);
    }
    return hFile;
}

/*
* LoggerWrite
*
* Purpose:
*
* Output text to file.
*
*/
VOID LoggerWrite(
    _In_ HANDLE hLogFile,
    _In_ LPWSTR lpText,
    _In_ BOOL UseReturn
    )
{
    SIZE_T sz = 0;
    DWORD bytesIO = 0;
    LPWSTR Buffer = NULL;

    if (hLogFile != INVALID_HANDLE_VALUE) {
        if (lpText == NULL)
            return;

        sz = _strlen(lpText);
        if (sz == 0)
            return;

        sz = sz * sizeof(WCHAR) + 4 + sizeof(UNICODE_NULL);
        Buffer = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (Buffer) {
            _strcpy(Buffer, lpText);
            if (UseReturn) _strcat(Buffer, TEXT("\r\n"));
            sz = _strlen(Buffer);
            WriteFile(hLogFile, Buffer, (DWORD)(sz * sizeof(WCHAR)), &bytesIO, NULL);
            HeapFree(GetProcessHeap(), 0, Buffer);
        }
    }
}
