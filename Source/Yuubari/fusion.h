#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       FUSION.H
*
*  VERSION:     1.25
*
*  DATE:        10 May 2017
*
*  Header file for the autoelevated applications scan.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define UacFusionDataCommonType         0
#define UacFusionDataRedirectedDllType  1

typedef enum {
    AutoElevateUnspecified = 0,
    AutoElevateDisabled = 1,
    AutoElevateEnabled = 2
} AUTOELEVATESTATE;

typedef struct _UAC_FUSION_DATA {
    DWORD DataType;
    LPWSTR Name;
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION RunLevel;
    AUTOELEVATESTATE AutoElevateState;
    BOOL IsFusion;
    BOOL IsDotNet;
    BOOL IsOSBinary;
    BOOL IsSignatureValidOrTrusted;
} UAC_FUSION_DATA, *PUAC_FUSION_DATA;

typedef struct _UAC_FUSION_DATA_DLL {
    DWORD DataType;
    LPWSTR FileName;
    LPWSTR DllName;
} UAC_FUSION_DATA_DLL, *PUAC_FUSION_DATA_DLL;

typedef struct _DLL_REDIRECTION_LIST_ENTRY {
    SLIST_ENTRY ListEntry;
    UNICODE_STRING DllName; //For release RtlFreeUnicodeString used, Buffer allocated in Process Heap
} DLL_REDIRECTION_LIST_ENTRY, *PDLL_REDIRECTION_ENTRY;

typedef struct _DLL_REDIRECTION_LIST {
    SLIST_HEADER Header;
    ULONG Depth;
} DLL_REDIRECTION_LIST, *PDLL_REDIRECTION_LIST;

typedef VOID(WINAPI *FUSIONCALLBACK)(UAC_FUSION_DATA *Data);

NTSTATUS SxsGetDllRedirectionFromActivationContext(
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _In_ PDLL_REDIRECTION_LIST DllList
);

VOID FusionScanDirectory(
    LPWSTR lpDirectory,
    FUSIONCALLBACK OutputCallback
    );

extern ptrWTGetSignatureInfo WTGetSignatureInfo;
