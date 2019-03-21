/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       UTIL.H
*
*  VERSION:     3.17
*
*  DATE:        19 Mar 2019
*
*  Global support routines header file shared between payload dlls.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _UACME_PARAM_BLOCK {
    ULONG Crc32;
    ULONG SessionId;
    ULONG AkagiFlag;
    WCHAR szParameter[MAX_PATH + 1];
    WCHAR szDesktop[MAX_PATH + 1];
    WCHAR szWinstation[MAX_PATH + 1];
    WCHAR szSignalObject[MAX_PATH + 1];
} UACME_PARAM_BLOCK, *PUACME_PARAM_BLOCK;

typedef BOOL(WINAPI* PFNCREATEPROCESSW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

typedef struct _OBJSCANPARAM {
    PWSTR Buffer;
    SIZE_T BufferSize;
} OBJSCANPARAM, *POBJSCANPARAM;

typedef struct _SXS_SEARCH_CONTEXT {
    LPWSTR DllName;
    LPWSTR SxsKey;
    LPWSTR FullDllPath;
} SXS_SEARCH_CONTEXT, *PSXS_SEARCH_CONTEXT;

VOID ucmPingBack(
    VOID);

BOOLEAN ucmPrivilegeEnabled(
    _In_ HANDLE hToken,
    _In_ ULONG Privilege);

NTSTATUS ucmCreateSyncMutant(
    _Out_ PHANDLE phMutant);

LPVOID ucmLdrGetProcAddress(
    _In_ PCHAR ImageBase,
    _In_ PCHAR RoutineName);

VOID ucmGetStartupInfo(
    _In_ LPSTARTUPINFOW lpStartupInfo);

DWORD ucmExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize);

PVOID ucmGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass);

BOOL ucmLaunchPayload(
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload);

BOOL ucmLaunchPayloadEx(
    _In_ PFNCREATEPROCESSW pCreateProcess,
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload);

BOOL ucmLaunchPayload2(
    _In_ BOOL bIsLocalSystem,
    _In_ ULONG SessionId,
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload);

LPWSTR ucmQueryRuntimeInfo(
    _In_ BOOL ReturnData);

BOOLEAN ucmDestroyRuntimeInfo(
    _In_ LPWSTR RuntimeInfo);

BOOL ucmIsUserWinstaInteractive(
    VOID);

NTSTATUS ucmIsUserHasInteractiveSid(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbInteractiveSid);

NTSTATUS ucmIsLocalSystem(
    _Out_ PBOOL pbResult);

wchar_t *sxsFilePathNoSlash(
    _In_ const wchar_t *fname,
    _In_ wchar_t *fpath);

BOOL sxsFindLoaderEntry(
    _In_ PSXS_SEARCH_CONTEXT Context);

HANDLE ucmOpenAkagiNamespace(
    VOID);

_Success_(return == TRUE)
BOOL ucmReadSharedParameters(
    _Out_ UACME_PARAM_BLOCK *SharedParameters);

VOID ucmSetCompletion(
    _In_ LPWSTR lpEvent);

BOOL ucmGetProcessElevationType(
    _In_opt_ HANDLE ProcessHandle,
    _Out_ TOKEN_ELEVATION_TYPE *lpType);

NTSTATUS ucmIsProcessElevated(
    _In_ ULONG ProcessId,
    _Out_ PBOOL Elevated);

#ifdef _DEBUG
#define ucmDbgMsg(Message)  OutputDebugString(Message)
#else
#define ucmDbgMsg(Message)  
#endif
