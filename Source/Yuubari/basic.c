/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2025
*
*  TITLE:       BASIC.C
*
*  VERSION:     1.60
*
*  DATE:        17 Jun 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

VOID QueryAndOutputRegValue(
    _In_ OUTPUTCALLBACK OutputCallback,
    _In_ HKEY hKey,
    _In_ LPWSTR ValueName,
    _In_ LPWSTR DisplayName,
    _In_ BOOL IsBool
)
{
    UAC_BASIC_DATA TempData;
    ULONG Value = 0;
    LRESULT Result = supRegReadDword(hKey, ValueName, &Value);
    if (Result == ERROR_SUCCESS) {
        RtlSecureZeroMemory(&TempData, sizeof(TempData));
        TempData.Name = DisplayName;
        TempData.IsValueBool = IsBool;
        TempData.Value = Value;
        OutputCallback((PVOID)&TempData);
    }
}

/*
* ScanBasicUacData
*
* Purpose:
*
* Query UserSharedData flags, UAC registry values.
*
*/
VOID ScanBasicUacData(
    _In_ OUTPUTCALLBACK OutputCallback
)
{
    ULONG Flags = 0;
    LRESULT lRet;
    HKEY hKey = NULL;

    UAC_BASIC_DATA Data;

    if (OutputCallback == NULL)
        return;

    if (!NT_SUCCESS(RtlQueryElevationFlags(&Flags)))
        return;

    RtlSecureZeroMemory(&Data, sizeof(Data));

    Data.Name = T_FLAG_ELEVATION_ENABLED;
    Data.IsValueBool = TRUE;
    Data.Value = ((Flags & DBG_FLAG_ELEVATION_ENABLED) > 0);
    OutputCallback((PVOID)&Data);

    Data.Name = T_FLAG_VIRTUALIZATION_ENABLED;
    Data.IsValueBool = TRUE;
    Data.Value = ((Flags & DBG_FLAG_VIRTUALIZATION_ENABLED) > 0);
    OutputCallback((PVOID)&Data);

    Data.Name = T_FLAG_INSTALLERDETECT_ENABLED;
    Data.IsValueBool = TRUE;
    Data.Value = ((Flags & DBG_FLAG_INSTALLER_DETECT_ENABLED) > 0);
    OutputCallback((PVOID)&Data);

    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_UAC_SETTINGS_KEY, 0, KEY_READ, &hKey);
    if (lRet == ERROR_SUCCESS && hKey != NULL) {
        QueryAndOutputRegValue(OutputCallback, hKey, T_UAC_PROMPT_BEHAVIOR, T_UAC_PROMPT_BEHAVIOR, FALSE);
        QueryAndOutputRegValue(OutputCallback, hKey, T_UAC_RESTRICTED_AUTOAPPROVE, T_UAC_RESTRICTED_AUTOAPPROVE, FALSE);
        QueryAndOutputRegValue(OutputCallback, hKey, T_UAC_AUTOAPPROVEIC, T_UAC_AUTOAPPROVEIC, FALSE);
        QueryAndOutputRegValue(OutputCallback, hKey, T_UAC_AUTOAPPROVEMP, T_UAC_AUTOAPPROVEMP, FALSE);
        QueryAndOutputRegValue(OutputCallback, hKey, T_UAC_AUTOAPPROVEHARDCLAIMS, T_UAC_AUTOAPPROVEHARDCLAIMS, FALSE);
        QueryAndOutputRegValue(OutputCallback, hKey, T_UAC_ENABLESECUREUIPATHS, T_UAC_ENABLESECUREUIPATHS, FALSE);
        QueryAndOutputRegValue(OutputCallback, hKey, T_UAC_SECURE_DESKTOP, T_UAC_SECURE_DESKTOP, TRUE);
        RegCloseKey(hKey);
    }
}
