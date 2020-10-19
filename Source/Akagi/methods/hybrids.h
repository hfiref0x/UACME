/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       HYBRIDS.H
*
*  VERSION:     3.51
*
*  DATE:        16 Oct 2020
*
*  Prototypes and definitions for hybrid methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

NTSTATUS ucmSXSMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize,
    _In_opt_ LPWSTR lpTargetDirectory,
    _In_ LPWSTR lpTargetApplication,
    _In_opt_ LPWSTR lpLaunchApplication,
    _In_ BOOL bConsentItself);

NTSTATUS ucmDismMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmWow64LoggerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmUiAccessMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmJunctionMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmSXSDccwMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmCorProfilerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmDccwCOMMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmNICPoisonMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmIeAddOnInstallMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

//
// Post execution cleanup routines.
//
BOOL ucmMethodCleanupSingleItemSystem32(
    LPWSTR lpItemName);

BOOL ucmJunctionMethodCleanup(
    VOID);

BOOL ucmSXSDccwMethodCleanup(
    VOID);

BOOL ucmSXSMethodCleanup(
    VOID);

