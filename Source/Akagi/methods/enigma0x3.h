/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       ENIGMA0X3.H
*
*  VERSION:     2.72
*
*  DATE:        26 May 2017
*
*  Prototypes and definitions for Enigma0x3 autoelevation method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _UCM_ENIGMA0x3_CTX {
    PVOID PayloadDll;
    DWORD PayloadDllSize;
    WCHAR szTempDirectory[MAX_PATH + 1];
} UCM_ENIGMA0x3_CTX, *PUCM_ENIGMA0x3_CTX;

BOOL ucmHijackShellCommandMethod(
    _In_opt_ LPWSTR lpszPayload,
    _In_ LPWSTR lpszTargetApp,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

BOOL ucmDiskCleanupRaceCondition(
    _In_ PVOID PayloadDll,
    _In_ DWORD PayloadDllSize);

BOOL ucmAppPathMethod(
    _In_opt_ LPWSTR lpszPayload,
    _In_ LPWSTR lpszAppPathTarget,
    _In_ LPWSTR lpszTargetApp);

BOOL ucmSdcltIsolatedCommandMethod(
    _In_opt_ LPWSTR lpszPayload);

BOOL ucmMsSettingsDelegateExecuteMethod(
    _In_opt_ LPWSTR lpszPayload);
