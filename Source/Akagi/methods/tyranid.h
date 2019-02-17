/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       TYRANID.H
*
*  VERSION:     3.15
*
*  DATE:        15 Feb 2019
*
*  Prototypes and definitions for James Forshaw method(s).
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmDiskCleanupEnvironmentVariable(
    _In_ LPWSTR lpszPayload);

BOOL ucmTokenModification(
    _In_ LPWSTR lpszPayload,
    _In_ BOOL fUseCommandLine);

BOOL ucmTokenModUIAccessMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);
