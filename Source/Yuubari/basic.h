#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       BASIC.H
*
*  VERSION:     1.49
*
*  DATE:        11 Nov 2019
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

VOID ScanBasicUacData(
    _In_ OUTPUTCALLBACK OutputCallback);
