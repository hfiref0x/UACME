#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2022
*
*  TITLE:       APPINFO.H
*
*  VERSION:     1.54
*
*  DATE:        01 Dec 2022
*
*  Header file for the AppInfo scan.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once
#include <DbgHelp.h>

typedef enum _AI_DATA_TYPE {
    AiSnapinFile = 1,
    AiManagementConsole,
    AiAutoApproveEXE,
    AiIncludedPFDirs,
    AiIncludedSystemDirs,
    AilpIncludedWindowsDirs,
    AiExemptedAutoApproveExes,
    AiExcludedWindowsDirs,
    AiMax
} AI_DATA_TYPE;

typedef struct _UAC_AI_DATA {
    LPWSTR Name;
    SIZE_T Length;
    AI_DATA_TYPE Type;
} UAC_AI_DATA, *PUAC_AI_DATA;

typedef struct _UAC_MMC_BLOCK {
    LPWSTR lpManagementApplication;
    PVOID Base;
    ULONG NumOfElements;
    ULONG Reserved;
} UAC_MMC_BLOCK, *PUAC_MMC_BLOCK;

typedef struct _UAC_AI_GLOBALS {
    ULONG AppInfoBuildNumber;
    PVOID DllBase;
    SIZE_T DllVirtualSize;
    UAC_MMC_BLOCK *MmcBlock;
    PVOID *lpIncludedWindowsDirs;
    PVOID *lpIncludedPFDirs;
    PVOID *lpAutoApproveEXEList;
    PVOID *lpIncludedSystemDirs;
    PVOID *lpExemptedAutoApproveExes;
    PVOID *lpExcludedWindowsDirs;
} UAC_AI_GLOBALS, *PUAC_AI_GLOBALS;

typedef  DWORD(WINAPI *pfnSymSetOptions)(
    _In_ DWORD   SymOptions);

typedef BOOL(WINAPI *pfnSymInitializeW)(
    _In_ HANDLE hProcess,
    _In_opt_ PCWSTR UserSearchPath,
    _In_ BOOL fInvadeProcess);

typedef BOOL(WINAPI* pfnSymFromNameW)(
    _In_ HANDLE hProcess,
    _In_ PCWSTR Name,
    _Inout_ PSYMBOL_INFOW Symbol);

typedef DWORD64(WINAPI *pfnSymLoadModuleExW)(
    _In_ HANDLE hProcess,
    _In_opt_ HANDLE hFile,
    _In_opt_ PCWSTR ImageName,
    _In_opt_ PCWSTR ModuleName,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD DllSize,
    _In_opt_ PMODLOAD_DATA Data,
    _In_ DWORD Flags);

typedef BOOL(WINAPI *pfnSymUnloadModule64)(
    _In_ HANDLE hProcess,
    _In_ DWORD64 BaseOfDll);

typedef BOOL(WINAPI *pfnSymCleanup)(
    _In_ HANDLE hProcess);

VOID ScanAppInfo(
    LPWSTR lpFileName,
    OUTPUTCALLBACK OutputCallback);
