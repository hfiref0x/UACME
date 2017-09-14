/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       CUI.C
*
*  VERSION:     1.11
*
*  DATE:        20 Mar 2017
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

/*
* cuiPrintTextA
*
* Purpose:
*
* Output text to the console or file.
*
* ANSI variant
*
*/
VOID cuiPrintTextA(
	_In_ HANDLE hOutConsole,
	_In_ LPSTR lpText,
	_In_ BOOL ConsoleOutputEnabled,
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

	consoleIO = consoleIO * sizeof(CHAR) + 4 + sizeof(UNICODE_NULL);
	Buffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, consoleIO);
	if (Buffer) {

		_strcpy_a(Buffer, lpText);
		if (UseReturn) _strcat_a(Buffer, "\r\n");

		consoleIO = _strlen_a(Buffer);

		if (ConsoleOutputEnabled != FALSE) {
			WriteConsoleA(hOutConsole, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
		}
		else {
			WriteFile(hOutConsole, Buffer, (DWORD)(consoleIO * sizeof(CHAR)), &bytesIO, NULL);
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
*
* UNICODE variant
*
*/
VOID cuiPrintTextW(
    _In_ HANDLE hOutConsole,
    _In_ LPWSTR lpText,
    _In_ BOOL ConsoleOutputEnabled,
    _In_ BOOL UseReturn
)
{
    SIZE_T consoleIO;
    DWORD bytesIO;
    LPWSTR Buffer;

    if (lpText == NULL)
        return;

    consoleIO = _strlen(lpText);
    if ((consoleIO == 0) || (consoleIO > MAX_PATH * 4))
        return;

    consoleIO = (4 + sizeof(UNICODE_NULL) + consoleIO) * sizeof(WCHAR);
    Buffer = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, consoleIO);
    if (Buffer) {

        _strcpy(Buffer, lpText);
        if (UseReturn) _strcat(Buffer, TEXT("\r\n"));

        consoleIO = _strlen(Buffer);

        if (ConsoleOutputEnabled != FALSE) {
            WriteConsole(hOutConsole, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
        }
        else {
            WriteFile(hOutConsole, Buffer, (DWORD)(consoleIO * sizeof(WCHAR)), &bytesIO, NULL);
        }
        HeapFree(GetProcessHeap(), 0, Buffer);
    }
}
