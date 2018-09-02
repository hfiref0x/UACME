/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       CUI.C
*
*  VERSION:     1.30
*
*  DATE:        01 Aug 2018
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

    if (InitInput) g_ConIn = GetStdHandle(STD_INPUT_HANDLE);

    SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);

    g_ConsoleOutput = TRUE;
    if (!GetConsoleMode(g_ConOut, &dummy)) {
        g_ConsoleOutput = FALSE;
        WriteFile(g_ConOut, &g_BE, sizeof(WCHAR), &dummy, NULL);
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
    SIZE_T consoleIO;
    DWORD bytesIO;
    LPSTR Buffer;

    if (lpText == NULL)
        return;

    consoleIO = _strlen_a(lpText);
    if ((consoleIO == 0) || (consoleIO > MAX_PATH * 4))
        return;

    consoleIO = 5 + consoleIO;
    Buffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, consoleIO);
    if (Buffer) {

        _strcpy_a(Buffer, lpText);
        if (UseReturn) _strcat_a(Buffer, "\r\n");

        consoleIO = _strlen_a(Buffer);

        if (g_ConsoleOutput != FALSE) {
            WriteConsoleA(g_ConOut, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
        }
        else {
            WriteFile(g_ConOut, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
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
	SIZE_T consoleIO;
	DWORD bytesIO;
	LPWSTR Buffer;

	if (lpText == NULL)
		return;

	consoleIO = _strlen_w(lpText);
	if ((consoleIO == 0) || (consoleIO > MAX_PATH * 4))
		return;

	consoleIO = consoleIO * sizeof(WCHAR) + 4 + sizeof(UNICODE_NULL);
	Buffer = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, consoleIO);
	if (Buffer) {

		_strcpy(Buffer, lpText);
		if (UseReturn) _strcat_w(Buffer, TEXT("\r\n"));

		consoleIO = _strlen_w(Buffer);

		if (g_ConsoleOutput != FALSE) {
			WriteConsoleW(g_ConOut, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
		}
		else {
			WriteFile(g_ConOut, Buffer, (DWORD)(consoleIO * sizeof(WCHAR)), &bytesIO, NULL);
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
    CHAR szTextBuffer[512];
    DWORD dwLastError = GetLastError();
    
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwLastError, LANG_USER_DEFAULT, (LPSTR)&szTextBuffer, 512, NULL);
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
    WCHAR szTextBuffer[512];
    DWORD dwLastError = GetLastError();

    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwLastError, LANG_USER_DEFAULT, (LPWSTR)&szTextBuffer, 512, NULL);
    cuiPrintTextW(szTextBuffer, UseReturn);
}
