/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       FUSUTIL.H
*
*  VERSION:     3.58
*
*  DATE:        01 Dec 2021
*
*  Common header file for the Windows Fusion support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once


//
// Fusion CLI metadata structures
//
typedef struct _STORAGESIGNATURE {
    ULONG lSignature;               // "Magic" signature.
    USHORT iMajorVer;               // Major file version.
    USHORT iMinorVer;               // Minor file version.
    ULONG iExtraData;               // Offset to next structure of information 
    ULONG iVersionString;           // Length of version string
    BYTE pVersion[ANYSIZE_ARRAY];   // Version string
} STORAGESIGNATURE, * PSTORAGESIGNATURE;

typedef struct _STORAGEHEADER {
    BYTE fFlags; // STGHDR_xxx flags.
    BYTE pad;
    USHORT iStreams; // How many streams are there.
} STORAGEHEADER, * PSTORAGEHEADER;

#define MAXSTREAMNAME 32

typedef struct _STORAGESTREAM {
    ULONG iOffset;                // Offset in file for this stream.
    ULONG iSize;                  // Size of the file.
    CHAR  rcName[MAXSTREAMNAME];
} STORAGESTREAM, * PSTORAGESTREAM;

#include <pshpack1.h>
typedef struct _STORAGETABLESHEADER {
    DWORD Reserved0;
    BYTE MajorVersion;
    BYTE MinorVersion;
    BYTE HeapOffsetSizes;
    BYTE Reserved1;
    ULARGE_INTEGER Valid;
    ULARGE_INTEGER Sorted;
    ULONG Rows[ANYSIZE_ARRAY];
} STORAGETABLESHEADER, * PSTORAGETABLESHEADER;
#include <poppack.h>

#define STORAGE_MAGIC_SIG   0x424A5342  // BSJB

#define MD_STRINGS_BIT 0x1
#define MD_GUIDS_BIT   0x2
#define MD_BLOBS_BIT   0x4
#define MAX_CLR_TABLES  64

//
// Fusion metadata end
//

//
// Assembly cache scan routine and definitions.
//
typedef HRESULT(WINAPI* pfnCreateAssemblyEnum)(
    _Out_ IAssemblyEnum** pEnum,
    _In_opt_  IUnknown* pUnkReserved,
    _In_opt_  IAssemblyName* pName,
    _In_  DWORD dwFlags,
    _Reserved_  LPVOID pvReserved);

typedef HRESULT(WINAPI* pfnCreateAssemblyCache)(
    _Out_ IAssemblyCache** ppAsmCache,
    _In_  DWORD            dwReserved);

typedef struct _FUSION_SCAN_PARAM {
    _In_ GUID* ReferenceMVID;
    _Out_ LPWSTR lpFileName;
} FUSION_SCAN_PARAM, * PFUSION_SCAN_PARAM;

typedef BOOL(CALLBACK* pfnFusionScanFilesCallback)(
    LPWSTR CurrentDirectory,
    WIN32_FIND_DATA* FindData,
    PVOID UserContext);

typedef struct _UACME_FUSION_CONTEXT {
    BOOL Initialized;
    HINSTANCE hFusion;
    pfnCreateAssemblyCache CreateAssemblyCache;
    pfnCreateAssemblyEnum CreateAssemblyEnum;
} UACME_FUSION_CONTEXT, * PUACME_FUSION_CONTEXT;

BOOLEAN fusUtilInitFusion(
    _In_ DWORD dwVersion);

VOID fusUtilBinToUnicodeHex(
    _In_ const BYTE* pSrc,
    _In_ UINT cSrc,
    _Out_cap_(2 * cSrc + 1) LPWSTR pDst);

HRESULT fusUtilGetAssemblyName(
    _In_ IAssemblyName* pInterface,
    _Inout_ LPWSTR* lpName,
    _Out_opt_ PSIZE_T pcchName,
    _Inout_opt_ LPWSTR* lpDisplayName,
    _Out_opt_ PSIZE_T pcchDisplayName);

BOOL fusUtilGetAssemblyMVIDFromZapCache(
    _In_ LPCWSTR AssemblyName,
    _Inout_ GUID* ModuleVersionId);

HRESULT fusUtilGetAssemblyPath(
    _In_ IAssemblyCache* pInterface,
    _In_ LPCWSTR lpAssemblyName,
    _Inout_ LPCWSTR* lpAssemblyPath);

BOOLEAN fusUtilGetAssemblyPathByName(
    _In_ LPWSTR lpAssemblyName,
    _Inout_ LPWSTR* lpAssemblyPath);

BOOL fusUtilReferenceStreamByName(
    _In_ STORAGEHEADER* StorageHeader,
    _In_ LPCSTR StreamName,
    _Out_ PSTORAGESTREAM* StreamRef);

BOOL fusUtilGetImageMVID(
    _In_ LPCWSTR lpImageName,
    _Out_ GUID* ModuleVersionId);

BOOL fusUtilFindFileByMVIDCallback(
    _In_ LPWSTR CurrentDirectory,
    _In_ WIN32_FIND_DATA* FindData,
    _In_ PVOID UserContext);

BOOL fusUtilScanDirectory(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpExtension,
    _In_ pfnFusionScanFilesCallback pfnCallback,
    _In_opt_ PVOID pvUserContext);

VOID fusUtilCombineNativeImageCacheName(
    _In_ LPCWSTR lpAssemblyName,
    _Inout_ LPWSTR lpNativeImageName,
    _In_ DWORD cchNativeName,
    _In_ BOOLEAN fIsAux);
