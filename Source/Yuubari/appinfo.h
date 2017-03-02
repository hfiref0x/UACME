#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       APPINFO.H
*
*  VERSION:     1.20
*
*  DATE:        01 Mar 2017
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

typedef struct _SYMBOL_ENTRY {
    struct _SYMBOL_ENTRY *Next;
    LPWSTR   Name;
    DWORD64  Address;
} SYMBOL_ENTRY, *PSYMBOL_ENTRY;

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
    PVOID ControlFiles;
    ULONG ControlFilesCount;
    ULONG Reserved;
} UAC_MMC_BLOCK, *PUAC_MMC_BLOCK;

typedef struct _UAC_PATTERN {
    PVOID PatternData;
    ULONG PatternSize;
    ULONG AppInfoBuildMin;
    ULONG AppInfoBuildMax;
} UAC_PATTERN, *PUAC_PATTERN;

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

typedef VOID(WINAPI *APPINFODATACALLBACK)(UAC_AI_DATA *Data);

typedef  DWORD(WINAPI *pfnSymSetOptions)(
    _In_ DWORD   SymOptions
    );

typedef BOOL(WINAPI *pfnSymInitializeW)(
    _In_ HANDLE hProcess,
    _In_opt_ PCWSTR UserSearchPath,
    _In_ BOOL fInvadeProcess
    );

typedef DWORD64(WINAPI *pfnSymLoadModuleExW)(
    _In_ HANDLE hProcess,
    _In_opt_ HANDLE hFile,
    _In_opt_ PCWSTR ImageName,
    _In_opt_ PCWSTR ModuleName,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD DllSize,
    _In_opt_ PMODLOAD_DATA Data,
    _In_opt_ DWORD Flags
    );

typedef BOOL(WINAPI *pfnSymEnumSymbolsW)(
    _In_ HANDLE hProcess,
    _In_ ULONG64 BaseOfDll,
    _In_opt_ PCWSTR Mask,
    _In_ PSYM_ENUMERATESYMBOLS_CALLBACKW EnumSymbolsCallback,
    _In_opt_ PVOID UserContext
    );

typedef BOOL(WINAPI *pfnSymUnloadModule64)(
    _In_ HANDLE hProcess,
    _In_ DWORD64 BaseOfDll
    );

typedef BOOL(WINAPI *pfnSymCleanup)(
    _In_ HANDLE hProcess
    );

typedef BOOL(WINAPI *pfnSymFromAddrW)(
    _In_ HANDLE hProcess,
    _In_ DWORD64 Address,
    _Out_opt_ PDWORD64 Displacement,
    _Inout_ PSYMBOL_INFOW Symbol
    );

VOID ScanAppInfo(
    LPWSTR lpFileName,
    APPINFODATACALLBACK OutputCallback
    );
