/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2025
*
*  TITLE:       LOGGER.C
*
*  VERSION:     1.60
*
*  DATE:        17 Jun 2025
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
    DWORD bytesIO, lastError;

    if (lpLogFileName == NULL) {
        fname = TEXT("log.log");
    }

    hFile = CreateFile(fname, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        ch = (WCHAR)0xFEFF;

        if (!WriteFile(hFile, &ch, sizeof(WCHAR), &bytesIO, NULL)) {
            lastError = GetLastError();
            CloseHandle(hFile);
            SetLastError(lastError);
            return INVALID_HANDLE_VALUE;
        }
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
    SIZE_T textLength = 0, bufferSize = 0;
    DWORD bytesIO = 0;
    LPWSTR Buffer = NULL;

    if (lpText == NULL)
        return;

    textLength = _strlen(lpText);
    if (textLength == 0)
        return;

    if (hLogFile != INVALID_HANDLE_VALUE) {

        if (UseReturn) {
            if (textLength > (SIZE_MAX / sizeof(WCHAR)) - 3)
                return;
            bufferSize = (textLength + 3) * sizeof(WCHAR);
        }
        else {
            if (textLength > (SIZE_MAX / sizeof(WCHAR)) - 1)
                return;
            bufferSize = (textLength + 1) * sizeof(WCHAR);
        }

        Buffer = (LPWSTR)supHeapAlloc(bufferSize);
        if (Buffer) {
            _strcpy(Buffer, lpText);
            if (UseReturn) _strcat(Buffer, TEXT("\r\n"));
            textLength = _strlen(Buffer);
            WriteFile(hLogFile, Buffer, (DWORD)(textLength * sizeof(WCHAR)), &bytesIO, NULL);
            supHeapFree(Buffer);
        }
    }
}
