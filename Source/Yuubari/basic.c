/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       BASIC.C
*
*  VERSION:     1.0F
*
*  DATE:        18 Feb 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ScanBasicUacData
*
* Purpose:
*
* Query UserSharedData flags, UAC registry values.
*
*/
VOID ScanBasicUacData(
    BASICDATACALLBACK OutputCallback
)
{
    ULONG       Flags = 0, bytesIO;
    LRESULT     lRet;
    HKEY        hKey = NULL;

    UAC_BASIC_DATA Data;

    if (OutputCallback == NULL)
        return;

    RtlQueryElevationFlags(&Flags);

    RtlSecureZeroMemory(&Data, sizeof(Data));

    Data.Name = TEXT("ElevationEnabled");
    Data.IsValueBool = TRUE;
    Data.Value = ((Flags & DBG_FLAG_ELEVATION_ENABLED) > 0);
    OutputCallback(&Data);

    Data.Name = TEXT("VirtualizationEnabled");
    Data.IsValueBool = TRUE;
    Data.Value = ((Flags & DBG_FLAG_VIRTUALIZATION_ENABLED) > 0);
    OutputCallback(&Data);

    Data.Name = TEXT("InstallerDetectEnabled");
    Data.IsValueBool = TRUE;
    Data.Value = ((Flags & DBG_FLAG_INSTALLER_DETECT_ENABLED) > 0);
    OutputCallback(&Data);

    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system"), 0, KEY_READ, &hKey);
    if (lRet == ERROR_SUCCESS) {

        Flags = 0;
        bytesIO = sizeof(Flags);
        lRet = RegQueryValueEx(hKey, TEXT("ConsentPromptBehaviorAdmin"), NULL, NULL, (LPBYTE)&Flags, &bytesIO);
        if (lRet == ERROR_SUCCESS) {

            Data.Name = TEXT("ConsentPromptBehaviorAdmin");
            Data.IsDescUsed = TRUE;
            Data.IsValueBool = FALSE;
      
            switch (Flags) {
            case 0:
                Data.Desc = TEXT("Never notify");
                break;
            case 1:
                Data.Desc = TEXT("Admin pwd and login required, secured desktop used");
                break;
            case 2:
                Data.Desc = TEXT("Always notify, secure desktop used, MS autoelevation disabled");
                break;
            case 3:
                Data.Desc = TEXT("Admin pwd and login required");
                break;
            case 4:
                Data.Desc = TEXT("Admin approval mode, secure desktop used, MS autoelevation disabled");
                break;
            case 5:
                Data.Desc = TEXT("Admin approval mode (Default), secure desktop used, MS autoelevation enabled");
                break;
            default:
                Data.IsDescUsed = FALSE;
                Data.Value = Flags;
                break;
            }
        }

        OutputCallback(&Data);

        Flags = 0;
        bytesIO = sizeof(Flags);
        lRet = RegQueryValueEx(hKey, TEXT("PromptOnSecureDesktop"), NULL, NULL, (LPBYTE)&Flags, &bytesIO);
        if (lRet == ERROR_SUCCESS) {
            Data.Name = TEXT("PromptOnSecureDesktop");
            Data.IsDescUsed = FALSE;
            Data.Desc = NULL;
            Data.IsValueBool = TRUE;
            Data.Value = Flags;
            OutputCallback(&Data);
        }

        Flags = 0;
        bytesIO = sizeof(Flags);
        lRet = RegQueryValueEx(hKey, TEXT("EnableRestrictedAutoApprove"), NULL, NULL, (LPBYTE)&Flags, &bytesIO);
        if (lRet == ERROR_SUCCESS) {
            Data.Name = TEXT("EnableRestrictedAutoApprove");
            Data.IsDescUsed = FALSE;
            Data.Desc = NULL;
            Data.IsValueBool = TRUE;
            Data.Value = Flags;
            OutputCallback(&Data);
        }
        RegCloseKey(hKey);
    }
}
