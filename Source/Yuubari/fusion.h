#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       FUSION.H
*
*  VERSION:     1.0F
*
*  DATE:        13 Feb 2017
*
*  Header file for the autoelevated applications scan.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _UAC_FUSION_DATA {
    LPWSTR Name;
    LPWSTR RequestedExecutionLevel;
    BOOL IsFusion;
    BOOL AutoElevate;
    BOOL IsDotNet;
    BOOL IsOSBinary;
    BOOL IsSignatureValidOrTrusted;
} UAC_FUSION_DATA, *PUAC_FUSION_DATA;

typedef VOID(WINAPI *FUSIONCALLBACK)(UAC_FUSION_DATA *Data);

VOID ScanDirectory(
    LPWSTR lpDirectory,
    FUSIONCALLBACK OutputCallback
    );

extern ptrWTGetSignatureInfo WTGetSignatureInfo;
