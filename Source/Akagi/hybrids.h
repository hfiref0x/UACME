/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       HYBRIDS.H
*
*  VERSION:     2.30
*
*  DATE:        12 June 2016
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

typedef BOOL(WINAPI *pfnShellExecuteExW)(SHELLEXECUTEINFOW *pExecInfo);
typedef DWORD(WINAPI *pfnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef BOOL(WINAPI *pfnCloseHandle)(HANDLE hObject);

typedef struct _ELOAD_PARAMETERS_SIREFEF {
    WCHAR                   szVerb[MAX_PATH];
    WCHAR                   szTargetApp[MAX_PATH * 2];
    pfnShellExecuteExW      xShellExecuteExW;
    pfnWaitForSingleObject  xWaitForSingleObject;
    pfnCloseHandle          xCloseHandle;
} ELOAD_PARAMETERS_SIREFEF, *PELOAD_PARAMETERS_SIREFEF;

BOOL ucmAvrfMethod(
    CONST PVOID AvrfDll,
    DWORD AvrfDllSize
    );

BOOL ucmWinSATMethod(
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize,
    BOOL UseWusa
    );

BOOL ucmMMCMethod(
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize
    );

BOOL ucmSirefefMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize
    );

BOOL ucmGenericAutoelevation(
    LPWSTR lpTargetApp,
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize
    );

BOOL ucmGWX(
    VOID
    );

BOOL ucmAutoElevateManifest(
    PVOID ProxyDll,
    DWORD ProxyDllSize
    );

BOOL ucmInetMgrMethod(
    VOID
    );
