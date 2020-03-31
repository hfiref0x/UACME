#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       SUP.H
*
*  VERSION:     1.47
*
*  DATE:        22 Mar 2020
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
    PVOID ImageBase);

LPWSTR supReadKeyString(
    HKEY hKey,
    LPWSTR KeyValue,
    PDWORD pdwDataSize);

PVOID supQueryKeyName(
    _In_ HKEY hKey,
    _Out_opt_ PSIZE_T ReturnedLength);

BOOLEAN supIsProcess32bit(
    _In_ HANDLE hProcess);

PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize);

LRESULT supRegReadDword(
    _In_ HKEY hKey,
    _In_ LPWSTR lpValueName,
    _In_ LPDWORD Value);

PVOID supLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize);
