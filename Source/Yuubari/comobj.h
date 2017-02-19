#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       COMOBJ.H
*
*  VERSION:     1.0F
*
*  DATE:        14 Feb 2017
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

typedef struct _UAC_REGISTRY_DATA {
    LPWSTR Name;
    LPWSTR AppId;
    LPWSTR LocalizedString;
    LPWSTR Key;
} UAC_REGISTRY_DATA, *PUAC_REGISTRY_DATA;

typedef VOID(WINAPI *REGCALLBACK)(UAC_REGISTRY_DATA *Data);

VOID ScanRegistry(
    HKEY RootKey,
    REGCALLBACK OutputCallback
    );
