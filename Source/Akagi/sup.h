/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       SUP.H
*
*  VERSION:     2.10
*
*  DATE:        16 Apr 2016
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

BOOL supRunProcess(
    _In_ LPWSTR lpszProcessName,
    _In_opt_ LPWSTR lpszParameters
    );

HANDLE supRunProcessEx(
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _Out_opt_ HANDLE *PrimaryThread
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

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
