#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       SUP.H
*
*  VERSION:     1.40
*
*  DATE:        19 Mar 2019
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

BOOL supIsCorImageFile(
    PVOID ImageBase
    );

LPWSTR supReadKeyString(
    HKEY hKey,
    LPWSTR KeyValue,
    PDWORD pdwDataSize
    );

PVOID supQueryKeyName(
    _In_ HKEY hKey,
    _Out_opt_ PSIZE_T ReturnedLength
    );

BOOLEAN supIsProcess32bit(
    _In_ HANDLE hProcess
    );

PVOID supFindPattern(
    CONST PBYTE Buffer,
    SIZE_T BufferSize,
    CONST PBYTE Pattern,
    SIZE_T PatternSize
    );

LRESULT supRegReadDword(
    _In_ HKEY hKey,
    _In_ LPWSTR lpValueName,
    _In_ LPDWORD Value
    );

BOOL supQueryNtBuildNumber(
    _Inout_ PULONG BuildNumber
    );
