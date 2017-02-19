/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       SUP.H
*
*  VERSION:     2.56
*
*  DATE:        10 Feb 2017
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef BOOL(CALLBACK *UCM_FIND_FILE_CALLBACK)(WIN32_FIND_DATA *fdata, LPWSTR lpDirectory);

typedef struct _SXS_SEARCH_CONTEXT {
    LPWSTR DllName;
    LPWSTR PartialPath;
    LPWSTR FullDllPath;
} SXS_SEARCH_CONTEXT, *PSXS_SEARCH_CONTEXT;

BOOLEAN supIsProcess32bit(
    _In_ HANDLE hProcess
    );

BOOL supGetElevationType(
    TOKEN_ELEVATION_TYPE *lpType
    );

BOOL supWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize
    );

PBYTE supReadFileToBuffer(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize
    );

BOOL supRunProcess(
    _In_ LPWSTR lpszProcessName,
    _In_opt_ LPWSTR lpszParameters
    );

HANDLE NTAPI supRunProcessEx(
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _Out_opt_ HANDLE *PrimaryThread,
    _Inout_opt_ LPWSTR lpApplicationName
    );

void supCopyMemory(
    _Inout_ void *dest,
    _In_ size_t cbdest,
    _In_ const void *src,
    _In_ size_t cbsrc
    );

DWORD supQueryEntryPointRVA(
    _In_ LPWSTR lpImageFile
    );

BOOL supSetParameter(
    LPWSTR lpParameter,
    DWORD cbParameter
    );

BOOLEAN supVerifyMappedImageMatchesChecksum(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength
    );

VOID ucmShowMessage(
    LPWSTR lpszMsg
    );

INT ucmShowQuestion(
    LPWSTR lpszMsg
    );

PBYTE supLdrQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize
    );

VOID supMasqueradeProcess(
    VOID
    );

DWORD supExpandEnvironmentStrings(
    LPCWSTR lpSrc,
    LPWSTR lpDst,
    DWORD nSize
    );

BOOL supScanFiles(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpFileType,
    _In_ UCM_FIND_FILE_CALLBACK Callback
    );

VOID supCheckMSEngineVFS(
    VOID
    );

VOID NTAPI sxsFindDllCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _In_ OUT BOOLEAN *StopEnumeration
    );

PVOID supNativeGetProcAddress(
    WCHAR *Module,
    CHAR *Routine
    );

VOID supDebugPrint(
    LPWSTR ApiName,
    DWORD status
    );

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
