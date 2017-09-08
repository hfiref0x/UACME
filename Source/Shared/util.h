/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       UTIL.H
*
*  VERSION:     2.80
*
*  DATE:        07 Sept 2017
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

typedef NTSTATUS(NTAPI *PENUMOBJECTSCALLBACK)(
    POBJECT_DIRECTORY_INFORMATION Entry,
    PVOID CallbackParam);

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
    LPWSTR PartialPath;
    LPWSTR FullDllPath;
} SXS_SEARCH_CONTEXT, *PSXS_SEARCH_CONTEXT;

BOOLEAN ucmPrivilegeEnabled(
    _In_ HANDLE hToken,
    _In_ ULONG Privilege);

NTSTATUS ucmReadValue(
    _In_ HANDLE hKey,
    _In_ LPWSTR ValueName,
    _In_ DWORD ValueType,
    _Out_ PVOID *Buffer,
    _Out_ ULONG *BufferSize);

NTSTATUS ucmCreateSyncMutant(
    _Out_ PHANDLE phMutant);

NTSTATUS NTAPI ucmEnumSystemObjects(
    _In_opt_ LPWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam);

NTSTATUS NTAPI ucmDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam);

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

BOOL ucmReadParameters(
    _Inout_ PWSTR *pszParamBuffer,
    _Inout_ ULONG *cbParamBuffer,
    _Inout_opt_ PDWORD pdwGlobalFlag,
    _Inout_opt_ PDWORD pdwSessionId,
    _In_ BOOL IsSystem);

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

VOID NTAPI sxsFindDllCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _In_ OUT BOOLEAN *StopEnumeration);
