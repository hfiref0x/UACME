#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       COMOBJ.H
*
*  VERSION:     1.11
*
*  DATE:        28 Feb 2017
*
*  Header file for the COM registry objects scan.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define UacCOMDataCommonType         0
#define UacCOMDataInterfaceType      1

typedef struct _INTERFACE_INFO {
    IID iid;
    WCHAR szInterfaceName[MAX_PATH];
} INTERFACE_INFO, *PINTERFACE_INFO;

typedef struct _INTERFACE_INFO_LIST {
    ULONG cEntries;
    INTERFACE_INFO *List;
} INTERFACE_INFO_LIST, *PINTERFACE_INFO_LIST;

typedef struct _UAC_INTERFACE_DATA {
    DWORD DataType;
    LPWSTR Name;
    CLSID Clsid;
    IID IID;
} UAC_INTERFACE_DATA, *PUAC_INTERFACE_DATA;

typedef struct _UAC_REGISTRY_DATA {
    DWORD DataType;
    LPWSTR Name;
    LPWSTR Key;
    LPWSTR AppId;
    LPWSTR LocalizedString;
} UAC_REGISTRY_DATA, *PUAC_REGISTRY_DATA;

typedef VOID(WINAPI *REGCALLBACK)(
    _In_ UAC_REGISTRY_DATA *Data
    );

VOID CoListInformation(
    _In_ REGCALLBACK OutputCallback
    );

