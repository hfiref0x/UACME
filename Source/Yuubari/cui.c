/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       CUI.C
*
*  VERSION:     1.60
*
*  DATE:        17 Jun 2025
*
*  Console output.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

HANDLE g_ConOut = NULL, g_ConIn = NULL;
BOOL   g_ConsoleOutput = FALSE;
WCHAR  g_BE = 0xFEFF;
const SIZE_T MAX_CONSOLE_OUTPUT = 4096;


/*
* cuiInitialize
*
* Purpose:
*
* Initialize console input/output.
*
*/
VOID cuiInitialize(
    _In_ BOOL InitInput,
    _Out_opt_ PBOOL IsConsoleOutput
)
{
    ULONG dummy;

    g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_ConOut == INVALID_HANDLE_VALUE || g_ConOut == NULL) {
        g_ConOut = GetStdHandle(STD_ERROR_HANDLE);
    }

    if (InitInput) {
        g_ConIn = GetStdHandle(STD_INPUT_HANDLE);
        if (g_ConIn == INVALID_HANDLE_VALUE) {
            g_ConIn = NULL;
        }
    }

    g_ConsoleOutput = TRUE;

    if (g_ConOut != INVALID_HANDLE_VALUE && g_ConOut != NULL) {
        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);

        if (!GetConsoleMode(g_ConOut, &dummy)) {
            g_ConsoleOutput = FALSE;
            WriteFile(g_ConOut, &g_BE, sizeof(WCHAR), &dummy, NULL);
        }
    }
    else {
        g_ConsoleOutput = FALSE;
    }

    if (IsConsoleOutput)
        *IsConsoleOutput = g_ConsoleOutput;

    return;
}

/*
* cuiClrScr
*
* Purpose:
*
* Clear screen.
*
*/
VOID cuiClrScr(
    VOID
)
{
    COORD coordScreen;
    DWORD cCharsWritten;
    DWORD dwConSize;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    coordScreen.X = 0;
    coordScreen.Y = 0;

    if (!GetConsoleScreenBufferInfo(g_ConOut, &csbi))
        return;

    dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

    if (!FillConsoleOutputCharacter(g_ConOut, TEXT(' '),
        dwConSize, coordScreen, &cCharsWritten))
        return;

    if (!GetConsoleScreenBufferInfo(g_ConOut, &csbi))
        return;

    if (!FillConsoleOutputAttribute(g_ConOut, csbi.wAttributes,
        dwConSize, coordScreen, &cCharsWritten))
        return;

    SetConsoleCursorPosition(g_ConOut, coordScreen);
}

/*
* cuiPrintTextA
*
* Purpose:
*
* Output text to the console or file.
* ANSI version.
*
*/
VOID cuiPrintTextA(
    _In_ LPSTR lpText,
    _In_ BOOL UseReturn
)
{
    BOOL writeSuccess;
    DWORD bytesIO;
    SIZE_T consoleIO, bufferSize, copySize;
    LPSTR Buffer;

    if (lpText == NULL)
        return;

    consoleIO = _strlen_a(lpText);
    if (consoleIO == 0 || consoleIO > MAX_CONSOLE_OUTPUT)
        return;

    if (UseReturn) {
        bufferSize = consoleIO + 3;
    }
    else {
        bufferSize = consoleIO + 1;
    }

    if (bufferSize > MAX_CONSOLE_OUTPUT)
        return;

    Buffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
    if (Buffer) {
        copySize = min(bufferSize - 1, consoleIO);
        memcpy(Buffer, lpText, copySize);
        Buffer[copySize] = '\0';

        if (UseReturn) _strcat_a(Buffer, "\r\n");

        consoleIO = _strlen_a(Buffer);

        if (g_ConsoleOutput != FALSE) {
            writeSuccess = WriteConsoleA(g_ConOut, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
        }
        else {
            writeSuccess = WriteFile(g_ConOut, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
        }

        HeapFree(GetProcessHeap(), 0, Buffer);
    }
}

/*
* cuiPrintTextW
*
* Purpose:
*
* Output text to the console or file.
* UNICODE version.
*
*/
VOID cuiPrintTextW(
    _In_ LPWSTR lpText,
    _In_ BOOL UseReturn
)
{
    BOOL writeSuccess;
    DWORD bytesIO;
    SIZE_T consoleIO, bufferSize, copySize;
    LPWSTR Buffer;

    if (lpText == NULL)
        return;

    consoleIO = _strlen_w(lpText);
    if (consoleIO == 0 || consoleIO > MAX_CONSOLE_OUTPUT)
        return;

    if (UseReturn) {
        bufferSize = (consoleIO + 3) * sizeof(WCHAR);
    }
    else {
        bufferSize = (consoleIO + 1) * sizeof(WCHAR);
    }

    if (bufferSize > MAX_CONSOLE_OUTPUT * sizeof(WCHAR))
        return;

    Buffer = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
    if (Buffer) {
        copySize = min(bufferSize / sizeof(WCHAR) - 1, consoleIO);
        memcpy(Buffer, lpText, copySize * sizeof(WCHAR));
        Buffer[copySize] = L'\0';

        if (UseReturn) _strcat_w(Buffer, TEXT("\r\n"));

        consoleIO = _strlen_w(Buffer);

        if (g_ConsoleOutput != FALSE) {
            writeSuccess = WriteConsoleW(g_ConOut, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
        }
        else {
            writeSuccess = WriteFile(g_ConOut, Buffer, (DWORD)(consoleIO * sizeof(WCHAR)), &bytesIO, NULL);
        }

        HeapFree(GetProcessHeap(), 0, Buffer);
    }
}

/*
* cuiPrintTextLastErrorA
*
* Purpose:
*
* Output LastError translated code to the console or file.
* ANSI version.
*
*/
VOID cuiPrintTextLastErrorA(
    _In_ BOOL UseReturn
)
{
    CHAR szTextBuffer[1024];
    DWORD dwLastError = GetLastError();

    RtlSecureZeroMemory(szTextBuffer, sizeof(szTextBuffer));
    if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwLastError, LANG_USER_DEFAULT,
        (LPSTR)&szTextBuffer, sizeof(szTextBuffer) - 64, NULL) == 0)
    {
        _strcpy_a(szTextBuffer, "Error code: ");
        itostr_a(dwLastError, _strend_a(szTextBuffer));
    }
    cuiPrintTextA(szTextBuffer, UseReturn);
}

/*
* cuiPrintTextLastErrorW
*
* Purpose:
*
* Output LastError translated code to the console or file.
* UNICODE version.
*
*/
VOID cuiPrintTextLastErrorW(
    _In_ BOOL UseReturn
)
{
    WCHAR szTextBuffer[1024];
    DWORD dwLastError = GetLastError();

    RtlSecureZeroMemory(szTextBuffer, sizeof(szTextBuffer));
    if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwLastError, LANG_USER_DEFAULT,
        (LPWSTR)&szTextBuffer, (sizeof(szTextBuffer) / sizeof(WCHAR)) - 64, NULL) == 0)
    {
        _strcpy_w(szTextBuffer, TEXT("Error code: "));
        itostr_w(dwLastError, _strend_w(szTextBuffer));
    }

    cuiPrintTextW(szTextBuffer, UseReturn);
}
