/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       HYBRIDS.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
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

typedef HRESULT(WINAPI *pfnCoInitialize)(
    LPVOID pvReserved);

typedef HRESULT(WINAPI *pfnCoGetObject)(
    LPCWSTR pszName,
    BIND_OPTS *pBindOptions,
    REFIID riid,
    void **ppv);

typedef HRESULT(WINAPI *pfnSHCreateItemFromParsingName)(
    PCWSTR pszPath, 
    IBindCtx *pbc, 
    REFIID riid, 
    void **ppv);

typedef void(WINAPI *pfnCoUninitialize)(
    VOID);

typedef NTSTATUS (NTAPI *pfnRtlExitUserThread)(
    _In_ NTSTATUS ExitStatus);

typedef struct tagLOAD_PARAMETERS_SIREFEF {
    WCHAR                   szVerb[10];
    WCHAR                   szTargetApp[MAX_PATH + 1];
    pfnShellExecuteExW      ShellExecuteExW;
    pfnWaitForSingleObject  WaitForSingleObject;
    pfnCloseHandle          CloseHandle;
    pfnRtlExitUserThread    RtlExitUserThread;
} LOAD_PARAMETERS_SIREFEF, *PLOAD_PARAMETERS_SIREFEF;

NTSTATUS ucmAvrfMethod(
    _In_ PVOID AvrfDll,
    _In_ DWORD AvrfDllSize);

NTSTATUS ucmWinSATMethod(
    _In_ LPWSTR lpTargetDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize,
    _In_ BOOL UseWusa);

NTSTATUS ucmMMCMethod(
    _In_ UCM_METHOD Method,
    _In_ LPWSTR lpTargetDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmSirefefMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmGenericAutoelevation(
    _In_ LPWSTR lpTargetApp,
    _In_ LPWSTR lpTargetDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmGWX(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmAutoElevateManifest(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmInetMgrMethod(
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

NTSTATUS ucmJunctionMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmSXSDccwMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmCorProfilerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmFwCplLuaMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmDccwCOMMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmBitlockerRCMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmCOMHandlersMethod2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmDateTimeStateWriterMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmAcCplAdminMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmEgre55Method(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

//
// Post execution cleanup routines.
//
BOOL ucmMMCMethodCleanup(
    _In_ UCM_METHOD Method);

BOOL ucmMethodCleanupSingleItemSystem32(
    LPWSTR lpItemName);

BOOL ucmJunctionMethodCleanup(
    VOID);

BOOL ucmSXSDccwMethodCleanup(
    VOID);

BOOL ucmSXSMethodCleanup(
    _In_ BOOL bConsentItself);

BOOL ucmSirefefMethodCleanup(
    VOID);
