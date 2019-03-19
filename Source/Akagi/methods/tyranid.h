/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       TYRANID.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
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

NTSTATUS ucmDiskCleanupEnvironmentVariable(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmTokenModification(
    _In_ LPWSTR lpszPayload,
    _In_ BOOL fUseCommandLine);

NTSTATUS ucmTokenModUIAccessMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);
