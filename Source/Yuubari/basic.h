#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       BASIC.H
*
*  VERSION:     1.11
*
*  DATE:        27 Feb 2017
*
*  Header file for the basic UAC info scan.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _UAC_BASIC_DATA {
    LPWSTR Name;
    DWORD Value;
    BOOL IsValueBool;
} UAC_BASIC_DATA, *PUAC_BASIC_DATA;

typedef VOID(WINAPI *BASICDATACALLBACK)(UAC_BASIC_DATA *Data);

VOID ScanBasicUacData(
    BASICDATACALLBACK OutputCallback
    );