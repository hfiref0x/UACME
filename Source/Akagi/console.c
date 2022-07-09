/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       CONSOLE.C
*
*  VERSION:     3.62
*
*  DATE:        08 Jul 2022
*
*  Debug console.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

HANDLE StdOutputHandle = NULL;

pswprintf_s _swprintf_s = NULL;

VOID ConsolePrint(
    _In_ LPCWSTR Message
)
{
    WriteConsole(StdOutputHandle, Message, (ULONG)_strlen(Message), NULL, NULL);
}

VOID ConsolePrintValueUlong(
    _In_ LPCWSTR Message,
    _In_ ULONG Value,
    _In_ BOOL Hexademical
)
{
    WCHAR szText[200];

    if (_swprintf_s) {

        _swprintf_s(szText, RTL_NUMBER_OF(szText),
            Hexademical ? TEXT("%ws 0x%lX\r\n") : TEXT("%ws %lu\r\n"),
            Message,
            Value);

        ConsolePrint(szText);
    }
}

VOID ConsolePrintStatus(
    _In_ LPCWSTR Message,
    _In_ NTSTATUS Status
)
{
    ConsolePrintValueUlong(Message, Status, TRUE);
}

VOID ConsoleInit(
    VOID
)
{
    WCHAR szBuffer[100];
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    if (hNtdll == NULL || !AllocConsole())
        return;

    _swprintf_s = (pswprintf_s)GetProcAddress(hNtdll, "swprintf_s");
    if (_swprintf_s == NULL)
        return;

    StdOutputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleMode(StdOutputHandle, ENABLE_PROCESSED_OUTPUT |
        ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    _swprintf_s(szBuffer, RTL_NUMBER_OF(szBuffer), TEXT("[*] UACMe v%lu.%lu.%lu.%lu\r\n"),
        UCM_VERSION_MAJOR,
        UCM_VERSION_MINOR,
        UCM_VERSION_REVISION,
        UCM_VERSION_BUILD);

    SetConsoleTitle(szBuffer);
}

BOOL ConsoleIsKeyPressed(
    _In_ WORD VirtualKeyCode
)
{
    BOOL bResult = FALSE;
    DWORD numberOfEvents = 0;
    INPUT_RECORD inp1;
    HANDLE nStdHandle = GetStdHandle(STD_INPUT_HANDLE);

    GetNumberOfConsoleInputEvents(nStdHandle, &numberOfEvents);

    if (numberOfEvents) {

        PeekConsoleInput(nStdHandle, &inp1, 1, &numberOfEvents);

        bResult = (numberOfEvents != 0 &&
            inp1.EventType == KEY_EVENT &&
            inp1.Event.KeyEvent.bKeyDown &&
            inp1.Event.KeyEvent.wVirtualKeyCode == VirtualKeyCode);

        FlushConsoleInputBuffer(nStdHandle);
    }

    return bResult;
}

VOID ConsoleRelease(
    VOID
)
{
    DWORD dwStop = GetTickCount() + (10 * 1000);

    ConsolePrint(TEXT("[+] Press Enter to exit or wait few seconds and it will close automatically\r\n"));

    while (!ConsoleIsKeyPressed(VK_RETURN) && GetTickCount() < dwStop)
        Sleep(50);

    FreeConsole();
}
