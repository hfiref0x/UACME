/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       HAKRIL.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  Prototypes and definitions for hakril method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef ULONG_PTR (WINAPI *pfnAipFindLaunchAdminProcess)(
    LPWSTR lpApplicationName,
    LPWSTR lpParameters,
    DWORD UacRequestFlag,
    DWORD dwCreationFlags,
    LPWSTR lpCurrentDirectory,
    HWND hWnd,
    PVOID StartupInfo,
    PVOID ProcessInfo,
    ELEVATION_REASON *ElevationReason);

NTSTATUS ucmHakrilMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

BOOL ucmHakrilMethodCleanup(
    VOID);
