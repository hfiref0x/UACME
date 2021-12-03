/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       SUP.H
*
*  VERSION:     3.58
*
*  DATE:        01 Dec 2021
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

#define TEXT_SECTION ".text"
#define TEXT_SECTION_LEGNTH sizeof(TEXT_SECTION)

//
// Shell association start.
//

typedef enum {
    UASET_CLEAR = 0,
    UASET_APPLICATION,
    UASET_PROGID,
} UASET;

typedef HRESULT(WINAPI* pfnUserAssocSet)(
    UASET set,
    LPCWSTR pszExt,
    LPCWSTR pszSet);

typedef HRESULT(WINAPI* pfnUserAssocSet2)(
    UASET set,
    LPCWSTR pszExt,
    LPCWSTR pszSet,
    ULONG dwFlags);

typedef struct _USER_ASSOC_PTR {
    union {
        pfnUserAssocSet UserAssocSet;
        pfnUserAssocSet2 UserAssocSet2; //Win10 1904 1909
    } DUMMYUNIONNAME;
    BOOL Valid;
} USER_ASSOC_PTR, * PUSER_ASSOC_PTR;

typedef struct USER_ASSOC_PATTERN {
    PVOID Ptr;
    DWORD Size;
} USER_ASSOC_PATTERN, * PUSER_ASSOC_PATTERN;

typedef struct USER_ASSOC_SIGNATURE {
    ULONG NtBuildMin;
    ULONG NtBuildMax;
    ULONG PatternsCount;
    PVOID PatternsTable;
} USER_ASSOC_SIGNATURE, * PUSER_ASSOC_SIGNATURE;

typedef VOID(WINAPI* PSUP_UAS_ENUMERATION_CALLBACK_FUNCTION)(
    _In_     PUSER_ASSOC_SIGNATURE Signature,
    _In_opt_ PVOID Context,
    _Inout_  BOOLEAN* StopEnumeration
    );

//
// Shell association end.
//

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
    _In_ LPCWSTR lpFileName,
    _In_opt_ PVOID Buffer,
    _In_ DWORD BufferSize);

BOOL supDecodeAndWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ CONST PVOID Buffer,
    _In_ DWORD BufferSize,
    _In_ ULONG Key);

PBYTE supReadFileToBuffer(
    _In_ LPCWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize);

BOOL supRunProcess2(
    _In_ LPCWSTR lpFile,
    _In_opt_ LPCWSTR lpParameters,
    _In_opt_ LPCWSTR lpVerb,
    _In_ INT nShow,
    _In_ ULONG mTimeOut);

BOOL supRunProcess(
    _In_ LPCWSTR lpFile,
    _In_opt_ LPCWSTR lpParameters);

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
    _In_ LPCWSTR lpszMsg);

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
    _In_ LPCWSTR ApiName,
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
    _In_ LPCWSTR lpSubKey);

BOOL supSetEnvVariableEx(
    _In_ BOOL fRemove,
    _In_opt_ LPWSTR lpKeyName,
    _In_ LPCWSTR lpVariableName,
    _In_opt_ LPCWSTR lpVariableData);

BOOL supSetEnvVariable(
    _In_ BOOL fRemove,
    _In_opt_ LPWSTR lpKeyName,
    _In_ LPCWSTR lpVariableName,
    _In_opt_ LPCWSTR lpVariableData);

BOOL supSetEnvVariable2(
    _In_ BOOL fRemove,
    _In_opt_ LPWSTR lpKeyName,
    _In_ LPCWSTR lpVariableName,
    _In_opt_ LPCWSTR lpVariableData);

BOOL supSetMountPoint(
    _In_ HANDLE hDirectory,
    _In_ LPCWSTR lpTarget,
    _In_ LPCWSTR lpPrintName);

BOOL supDeleteMountPoint(
    _In_ HANDLE hDirectory);

HANDLE supOpenDirectoryForReparse(
    _In_ LPCWSTR lpDirectory);

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
    _In_ PVOID ImageBase);

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

NTSTATUS supGetProcessDebugObject(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE DebugObjectHandle);

BOOL supIsProcessRunning(
    _In_ LPWSTR ProcessName);

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

NTSTATUS supFindUserAssocSet(
    _Out_ USER_ASSOC_PTR* Function);

PUSER_ASSOC_SIGNATURE supGetUserAssocSetDB(
    _Out_opt_ PULONG SignatureCount);

VOID supEnumUserAssocSetDB(
    _In_ PSUP_UAS_ENUMERATION_CALLBACK_FUNCTION Callback,
    _In_opt_ PVOID Context);

NTSTATUS supRegisterShellAssoc(
    _In_ LPCWSTR pszExt,
    _In_ LPCWSTR pszProgId,
    _In_ USER_ASSOC_PTR* UserAssocFunc,
    _In_ LPCWSTR lpszPayload,
    _In_ BOOL fCustomURIScheme,
    _In_opt_ LPCWSTR pszDefaultValue);

NTSTATUS supUnregisterShellAssocEx(
    _In_ BOOLEAN fResetOnly,
    _In_ LPCWSTR pszExt,
    _In_opt_ LPCWSTR pszProgId,
    _In_ USER_ASSOC_PTR* UserAssocFunc);

NTSTATUS supUnregisterShellAssoc(
    _In_ LPCWSTR pszExt,
    _In_ LPCWSTR pszProgId,
    _In_ USER_ASSOC_PTR* UserAssocFunc);

NTSTATUS supResetShellAssoc(
    _In_ LPCWSTR pszExt,
    _In_opt_ LPCWSTR pszProgId,
    _In_ USER_ASSOC_PTR* UserAssocFunc);

BOOL supStopTaskByName(
    _In_ LPCWSTR TaskFolder,
    _In_ LPCWSTR TaskName);

LPWSTR supPathAddBackSlash(
    _In_ LPWSTR lpszPath);

HANDLE supOpenShellProcess(
    _In_ ULONG dwDesiredAccess);

HANDLE supRunProcessFromParent(
    _In_ HANDLE hParentProcess,
    _Inout_opt_ LPWSTR lpApplicationName,
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _In_ ULONG CreationFlags,
    _In_ WORD ShowWindowFlags,
    _Out_opt_ HANDLE* PrimaryThread);

RPC_STATUS supCreateBindingHandle(
    _In_ RPC_WSTR RpcInterfaceUuid,
    _Out_ RPC_BINDING_HANDLE* BindingHandle);

BOOL supConcatenatePaths(
    _Inout_ LPWSTR Target,
    _In_ LPCWSTR Path,
    _In_ SIZE_T TargetBufferSize);

typedef BOOL(CALLBACK* pfnEnumProcessCallback)(
    _In_ PSYSTEM_PROCESSES_INFORMATION ProcessEntry,
    _In_opt_ PVOID UserContext
    );

BOOL supEnumProcessesForSession(
    _In_ ULONG SessionId,
    _In_ pfnEnumProcessCallback Callback,
    _In_opt_ PVOID UserContext);

BOOL supRemoveDirectoryRecursive(
    _In_ LPCWSTR Path);

VOID supEnableToastForProtocol(
    _In_ LPCWSTR lpProtocol,
    _In_ BOOL fEnable);

#ifdef _DEBUG
#define supDbgMsg(Message)  OutputDebugString(Message)
#else
#define supDbgMsg(Message)  
#endif

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
