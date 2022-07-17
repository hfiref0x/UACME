/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2022
*
*  TITLE:       ROUTINES.H
*
*  VERSION:     3.63
*
*  DATE:        16 Jul 2022
*
*  Prototypes of methods for UAC bypass methods table.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

NTSTATUS ucmShellRegModMethod(
    _In_ UCM_METHOD Method,
    LPCWSTR lpTargetKey,
    LPCWSTR lpszTargetApp,
    LPCWSTR lpszPayload);

NTSTATUS ucmShellRegModMethod2(
    _In_ UCM_METHOD Method,
    LPCWSTR lpTargetKey,
    LPCWSTR lpszTargetApp,
    LPCWSTR lpszPayload);

NTSTATUS ucmShellRegModMethod3(
    LPCWSTR lpTargetKey,
    LPCWSTR lpszTargetApp,
    LPCWSTR lpszPayload);

NTSTATUS ucmCMLuaUtilShellExecMethod(
    _In_ LPWSTR lpszExecutable);

NTSTATUS ucmNICPoisonMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmNICPoisonMethod2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmIeAddOnInstallMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmWscActionProtocolMethod(
    _In_ LPCWSTR lpszPayload);

NTSTATUS ucmFwCplLuaMethod2(
    _In_ LPCWSTR lpszPayload);

NTSTATUS ucmMsSettingsProtocolMethod(
    _In_ LPCWSTR lpszPayload);

NTSTATUS ucmMsStoreProtocolMethod(
    _In_ LPCWSTR lpszPayload);

NTSTATUS ucmPcaMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmDirectoryMockMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmHakrilMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

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

NTSTATUS ucmSXSDccwMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmCorProfilerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmDccwCOMMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmJunctionMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmMsdtMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmIscsiCplMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmDotNetSerialMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmEditionUpgradeManagerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmDiskCleanupEnvironmentVariable(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmTokenModUIAccessMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmDebugObjectMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmVFServerTaskSchedMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmVFServerDiagProfileMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

BOOL ucmCreateCabinetForSingleFile(
    _In_ LPWSTR lpSourceDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize,
    _In_opt_ LPWSTR lpInternalName);

BOOL ucmWusaExtractViaJunction(
    _In_ LPWSTR lpTargetDirectory);


//
// Post execution cleanup routines.
//
BOOL ucmMethodCleanupSingleItemSystem32(
    LPCWSTR lpItemName);

BOOL ucmJunctionMethodCleanup(
    VOID);

BOOL ucmSXSDccwMethodCleanup(
    VOID);

BOOL ucmSXSMethodCleanup(
    VOID);

VOID ucmDismMethodCleanup(
    VOID);

BOOL ucmHakrilMethodCleanup(
    VOID);

VOID ucmWusaCabinetCleanup(
    VOID);

VOID ucmIscsiCplMethodCleanup(
    VOID);
