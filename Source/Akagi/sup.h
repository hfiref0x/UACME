/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       SUP.H
*
*  VERSION:     3.19
*
*  DATE:        22 May 2019
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

typedef struct tagUCM_PROCESS_MITIGATION_POLICIES {
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10 DynamicCodePolicy;
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10 SignaturePolicy;
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10 ImageLoadPolicy;
    PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10 SystemCallFilterPolicy;
    PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10 PayloadRestrictionPolicy;
} UCM_PROCESS_MITIGATION_POLICIES, *PUCM_PROCESS_MITIGATION_POLICIES;

typedef BOOL(CALLBACK *UCM_FIND_FILE_CALLBACK)(
    WIN32_FIND_DATA *fdata,
    LPWSTR lpDirectory);

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
#define DEFAULT_ALLOCATION_TYPE MEM_COMMIT | MEM_RESERVE
#define DEFAULT_PROTECT_TYPE PAGE_READWRITE

VOID supSetLastErrorFromNtStatus(
    _In_ NTSTATUS LastNtStatus);

_Success_(return == TRUE)
BOOL supQueryProcessTokenIL(
    _In_ HANDLE hProcess,
    _Out_ PULONG IntegrityLevel);

HANDLE supGetProcessWithILAsCaller(
    _In_ ACCESS_MASK UseDesiredAccess);

BOOLEAN supIsProcess32bit(
    _In_ HANDLE hProcess);

BOOL supGetElevationType(
    _Out_ TOKEN_ELEVATION_TYPE *lpType);

BOOL supWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ PVOID Buffer,
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
    _In_ BOOL fWait);

BOOL supRunProcess(
    _In_ LPWSTR lpszProcessName,
    _In_opt_ LPWSTR lpszParameters);

_Success_(return != NULL)
HANDLE NTAPI supRunProcessEx(
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _In_opt_ LPWSTR lpApplicationName,
    _Out_opt_ HANDLE *PrimaryThread);

_Success_(return != NULL)
HANDLE NTAPI supRunProcessIndirect(
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _Inout_opt_ LPWSTR lpApplicationName,
    _In_ ULONG CreationFlags,
    _In_ WORD ShowWindowFlags,
    _Out_opt_ HANDLE *PrimaryThread);

void supCopyMemory(
    _Inout_ void *dest,
    _In_ size_t cbdest,
    _In_ const void *src,
    _In_ size_t cbsrc);

DWORD supQueryEntryPointRVA(
    _In_ LPWSTR lpImageFile);

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

VOID ucmShowMessage(
    _In_ BOOL OutputToDebugger,
    _In_ LPWSTR lpszMsg);

INT ucmShowQuestion(
    _In_ LPWSTR lpszMsg);

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

PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize);

PVOID supNativeGetProcAddress(
    _In_ WCHAR *Module,
    _In_ CHAR *Routine);

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

BOOL supQueryNtBuildNumber(
    _Inout_ PULONG BuildNumber);

BOOL supReplaceDllEntryPoint(
    _In_ PVOID DllImage,
    _In_ ULONG SizeOfDllImage,
    _In_ LPCSTR lpEntryPointName,
    _In_ BOOL fConvertToExe);

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
    _In_ SYSTEM_INFORMATION_CLASS InfoClass);

BOOL supIsCorImageFile(
    PVOID ImageBase);

NTSTATUS supRegSetValueIndirectHKCU(
    _In_ LPWSTR TargetKey,
    _In_opt_ LPWSTR ValueName,
    _In_ LPWSTR lpData,
    _In_ ULONG cbData);

NTSTATUS supRemoveRegLinkHKCU(
    VOID);

BOOL supIsConsentApprovedInterface(
    _In_ LPWSTR InterfaceName,
    _Out_ PBOOL IsApproved);

BOOL supIsDebugPortPresent(
    VOID);

BOOL supGetProcessMitigationPolicy(
    _In_ HANDLE hProcess,
    _In_ PROCESS_MITIGATION_POLICY Policy,
    _In_ SIZE_T Size,
    _Out_writes_bytes_(Size) PVOID Buffer);

UCM_PROCESS_MITIGATION_POLICIES *supGetRemoteCodeExecPolicies(
    _In_ HANDLE hProcess);

BOOL supDeleteKeyValueAndFlushKey(
    _In_ HKEY hRootKey,
    _In_ LPWSTR lpKeyName,
    _In_ LPWSTR lpValueName);

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

BOOLEAN supIndirectRegAdd(
    _In_ WCHAR* pszRootKey,
    _In_ WCHAR* pszKey,
    _In_opt_ WCHAR* pszValue,
    _In_opt_ WCHAR* pszDataType,
    _In_ WCHAR* pszData);

#ifdef _DEBUG
#define supDbgMsg(Message)  OutputDebugString(Message)
#else
#define supDbgMsg(Message)  
#endif

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
