/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       HYBRIDS.H
*
*  VERSION:     2.71
*
*  DATE:        06 May 2017
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

typedef BOOL(WINAPI *pfnShellExecuteExW)(
    SHELLEXECUTEINFOW *pExecInfo);

typedef DWORD(WINAPI *pfnWaitForSingleObject)(
    HANDLE hHandle,
    DWORD dwMilliseconds);

typedef BOOL(WINAPI *pfnCloseHandle)(
    HANDLE hObject);

typedef struct _ELOAD_PARAMETERS_SIREFEF {
    WCHAR                   szVerb[MAX_PATH];
    WCHAR                   szTargetApp[MAX_PATH * 2];
    pfnShellExecuteExW      xShellExecuteExW;
    pfnWaitForSingleObject  xWaitForSingleObject;
    pfnCloseHandle          xCloseHandle;
} ELOAD_PARAMETERS_SIREFEF, *PELOAD_PARAMETERS_SIREFEF;

BOOL ucmAvrfMethod(
    CONST PVOID AvrfDll,
    DWORD AvrfDllSize);

BOOL ucmWinSATMethod(
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize,
    BOOL UseWusa);

BOOL ucmMMCMethod(
    UCM_METHOD Method,
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmSirefefMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmGenericAutoelevation(
    LPWSTR lpTargetApp,
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmGWX(
    PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmAutoElevateManifest(
    PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmInetMgrMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

BOOL ucmSXSMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize,
    LPWSTR lpTargetDirectory,
    LPWSTR lpTargetApplication,
    LPWSTR lpLaunchApplication,
    BOOL bConsentItself);

BOOL ucmSetupAkagiLink(
    VOID);

BOOL ucmDismMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmWow64LoggerMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmUiAccessMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize);
