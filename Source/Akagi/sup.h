/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       SUP.H
*
*  VERSION:     3.52
*
*  DATE:        28 Oct 2020
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

typedef struct _SXS_SEARCH_CONTEXT {
    LPWSTR DllName;
    LPWSTR SxsKey;
    LPWSTR FullDllPath;
} SXS_SEARCH_CONTEXT, *PSXS_SEARCH_CONTEXT;

//ntifs.h
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)

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
} STORAGESIGNATURE, *PSTORAGESIGNATURE;

typedef struct _STORAGEHEADER {
    BYTE fFlags; // STGHDR_xxx flags.
    BYTE pad;
    USHORT iStreams; // How many streams are there.
} STORAGEHEADER, *PSTORAGEHEADER;

#define MAXSTREAMNAME 32

typedef struct _STORAGESTREAM {
    ULONG iOffset;                // Offset in file for this stream.
    ULONG iSize;                  // Size of the file.
    CHAR  rcName[MAXSTREAMNAME];
} STORAGESTREAM, * PSTORAGESTREAM;

//
// Fusion metadata end
//

//
// Assembly cache scan routine and definitions.
//
typedef HRESULT(WINAPI* pfnCreateAssemblyCache)(
    _Out_ IAssemblyCache** ppAsmCache,
    _In_  DWORD            dwReserved);

typedef struct _FUSION_SCAN_PARAM {
    _In_ GUID *ReferenceMVID;
    _Out_ LPWSTR lpFileName;
} FUSION_SCAN_PARAM, * PFUSION_SCAN_PARAM;

typedef BOOL(CALLBACK* pfnFusionScanFilesCallback)(
    LPWSTR CurrentDirectory,
    WIN32_FIND_DATA* FindData,
    PVOID UserContext);

//
// Memory allocator flags.
//
#define DEFAULT_ALLOCATION_TYPE MEM_COMMIT | MEM_RESERVE
#define DEFAULT_PROTECT_TYPE PAGE_READWRITE

//
// sup* prototypes
//

VOID supSetLastErrorFromNtStatus(
    _In_ NTSTATUS LastNtStatus);

BOOLEAN supIsProcess32bit(
    _In_ HANDLE hProcess);

BOOL supGetElevationType(
    _Out_ TOKEN_ELEVATION_TYPE *lpType);

BOOL supWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_opt_ PVOID Buffer,
    _In_ DWORD BufferSize);

BOOL supDecodeAndWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ CONST PVOID Buffer,
    _In_ DWORD BufferSize,
    _In_ ULONG Key);

PBYTE supReadFileToBuffer(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize);

BOOL supRunProcess2(
    _In_ LPWSTR lpszProcessName,
    _In_opt_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpVerb,
    _In_ INT nShow,
    _In_ ULONG mTimeOut);

BOOL supRunProcess(
    _In_ LPWSTR lpszProcessName,
    _In_opt_ LPWSTR lpszParameters);

void supCopyMemory(
    _Inout_ void *dest,
    _In_ size_t cbdest,
    _In_ const void *src,
    _In_ size_t cbsrc);

LPWSTR supQueryEnvironmentVariableOffset(
    _In_ PUNICODE_STRING Value);

DWORD supCalculateCheckSumForMappedFile(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength);

BOOLEAN supVerifyMappedImageMatchesChecksum(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength);

BOOLEAN supSetCheckSumForMappedFile(
    _In_ PVOID BaseAddress,
    _In_ ULONG CheckSum);

VOID ucmShowMessageById(
    _In_ BOOL OutputToDebugger,
    _In_ ULONG MessageId);

VOID ucmShowMessage(
    _In_ BOOL OutputToDebugger,
    _In_ LPWSTR lpszMsg);

INT ucmShowQuestionById(
    _In_ ULONG MessageId);

PBYTE supLdrQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize);

VOID supMasqueradeProcess(
    _In_ BOOL Restore);

DWORD supExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _In_ LPWSTR lpDst,
    _In_ DWORD nSize);

BOOL sxsFindLoaderEntry(
    _In_ PSXS_SEARCH_CONTEXT Context);

VOID supDebugPrint(
    _In_ LPWSTR ApiName,
    _In_ DWORD status);

PVOID supVirtualAlloc(
    _Inout_ PSIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect,
    _Out_opt_ NTSTATUS *Status);

BOOL supVirtualFree(
    _In_ PVOID Memory,
    _Out_opt_ NTSTATUS *Status);

BOOL supSecureVirtualFree(
    _In_ PVOID Memory,
    _In_ SIZE_T MemorySize,
    _Out_opt_ NTSTATUS *Status);

PVOID FORCEINLINE supHeapAlloc(
    _In_ SIZE_T Size);

BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory);

BOOL supRegDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey);

BOOL supSetEnvVariableEx(
    _In_ BOOL fRemove,
    _In_opt_ LPWSTR lpKeyName,
    _In_ LPWSTR lpVariableName,
    _In_opt_ LPWSTR lpVariableData);

BOOL supSetEnvVariable(
    _In_ BOOL fRemove,
    _In_opt_ LPWSTR lpKeyName,
    _In_ LPWSTR lpVariableName,
    _In_opt_ LPWSTR lpVariableData);

BOOL supSetMountPoint(
    _In_ HANDLE hDirectory,
    _In_ LPWSTR lpTarget,
    _In_ LPWSTR lpPrintName);

BOOL supDeleteMountPoint(
    _In_ HANDLE hDirectory);

HANDLE supOpenDirectoryForReparse(
    _In_ LPWSTR lpDirectory);

BOOL supWinstationToName(
    _In_opt_ HWINSTA hWinsta,
    _In_ LPWSTR lpBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PDWORD BytesNeeded);

BOOL supDesktopToName(
    _In_opt_ HDESK hDesktop,
    _In_ LPWSTR lpBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PDWORD BytesNeeded);

BOOL supReplaceDllEntryPoint(
    _In_ PVOID DllImage,
    _In_ ULONG SizeOfDllImage,
    _In_ LPCSTR lpEntryPointName,
    _In_ BOOL fConvertToExe);

NTSTATUS supRegWriteValue(
    _In_ HANDLE hKey,
    _In_opt_ LPWSTR ValueName,
    _In_ DWORD ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueDataSize);

NTSTATUS supRegReadValue(
    _In_ HANDLE hKey,
    _In_ LPWSTR ValueName,
    _In_ DWORD ValueType,
    _Out_ PVOID *Buffer,
    _Out_ ULONG *BufferSize,
    _In_opt_ HANDLE hHeap);

BOOL supQuerySystemRoot(
    _Inout_ PVOID Context);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass);

BOOL supIsCorImageFile(
    PVOID ImageBase);

BOOL supIsConsentApprovedInterface(
    _In_ LPWSTR InterfaceName,
    _Out_ PBOOL IsApproved);

PVOID supEncodePointer(
    _In_ PVOID Pointer);

PVOID supDecodePointer(
    _In_ PVOID Pointer);

NTSTATUS supCreateDirectory(
    _Out_opt_ PHANDLE phDirectory,
    _In_ OBJECT_ATTRIBUTES *ObjectAttributes,
    _In_ ULONG DirectoryShareFlags,
    _In_ ULONG DirectoryAttributes);

BOOL supCreateSharedParametersBlock(
    _In_ PVOID ucmContext);

VOID supDestroySharedParametersBlock(
    _In_ PVOID ucmContext);

PVOID supCreateUacmeContext(
    _In_ ULONG Method,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_ ULONG OptionalParameterLength,
    _In_ PVOID DecompressRoutine,
    _In_ BOOL OutputToDebugger);

VOID supDestroyUacmeContext(
    _In_ PVOID Context);

NTSTATUS supEnableDisableWow64Redirection(
    _In_ BOOL bDisable);

BOOLEAN supIsNetfx48PlusInstalled(
    VOID);

NTSTATUS supGetProcessDebugObject(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE DebugObjectHandle);

BOOLEAN supInitFusion(
    _In_ DWORD dwVersion);

HRESULT supFusionGetAssemblyPath(
    _In_ IAssemblyCache* pInterface,
    _In_ LPWSTR lpAssemblyName,
    _Inout_ LPWSTR* lpAssemblyPath);

BOOLEAN supFusionGetAssemblyPathByName(
    _In_ LPWSTR lpAssemblyName,
    _Inout_ LPWSTR* lpAssemblyPath);

BOOL supIsProcessRunning(
    _In_ LPWSTR ProcessName);

BOOL supFusionGetImageMVID(
    _In_ LPWSTR lpImageName,
    _Out_ GUID* ModuleVersionId);

BOOL supFusionScanDirectory(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpExtension,
    _In_ pfnFusionScanFilesCallback pfnCallback,
    _In_opt_ PVOID pvUserContext);

BOOL supFusionFindFileByMVIDCallback(
    _In_ LPWSTR CurrentDirectory,
    _In_ WIN32_FIND_DATA* FindData,
    _In_ PVOID UserContext);

void supBinTextEncode(
    _In_ unsigned __int64 x,
    _Inout_ wchar_t* s);

VOID supGenerateSharedObjectName(
    _In_ WORD ObjectId,
    _Inout_ LPWSTR lpBuffer);

VOID supSetGlobalCompletionEvent(
    VOID);

VOID supWaitForGlobalCompletionEvent(
    VOID);

NTSTATUS supOpenClassesKey(
    _In_opt_ PUNICODE_STRING UserRegEntry,
    _Out_ PHANDLE KeyHandle);

NTSTATUS supRemoveRegLinkHKCU(
    _In_ LPWSTR lpszRegLink);

PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize);

PVOID supLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize);

#ifdef _DEBUG
#define supDbgMsg(Message)  OutputDebugString(Message)
#else
#define supDbgMsg(Message)  
#endif

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
