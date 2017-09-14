/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017, translated from Microsoft sources/debugger
*
*  TITLE:       NTSXS.H
*
*  VERSION:     1.01
*
*  DATE:        22 Feb 2017
*
*  Common header file for the SxS related API functions and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int

#define ACTCTX_PROCESS_DEFAULT ((void*)NULL)
#define ACTCTX_EMPTY ((void*)(LONG_PTR)-3)
#define ACTCTX_SYSTEM_DEFAULT  ((void*)(LONG_PTR)-4)
#define IS_SPECIAL_ACTCTX(x) (((((LONG_PTR)(x)) - 1) | 7) == -1)

typedef struct _ACTIVATION_CONTEXT *PACTIVATION_CONTEXT;
typedef const struct _ACTIVATION_CONTEXT *PCACTIVATION_CONTEXT;

#define INVALID_ACTIVATION_CONTEXT ((PACTIVATION_CONTEXT) ((LONG_PTR) -1))

#define RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT (0x00000001)
#define RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_ACTIVATION_CONTEXT_IS_MODULE  (0x00000002)
#define RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_ACTIVATION_CONTEXT_IS_ADDRESS (0x00000004)
#define RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_NO_ADDREF  (0x80000000)

#define FIND_ACTIVATION_CONTEXT_SECTION_KEY_RETURN_ACTIVATION_CONTEXT (0x00000001)
#define FIND_ACTIVATION_CONTEXT_SECTION_KEY_RETURN_FLAGS              (0x00000002)
#define FIND_ACTIVATION_CONTEXT_SECTION_KEY_RETURN_ASSEMBLY_METADATA  (0x00000004)

#define ACTIVATION_CONTEXT_SECTION_FORMAT_STRING   1
#define ACTIVATION_CONTEXT_SECTION_FORMAT_GUID     2

#define ACTIVATION_CONTEXT_DATA_MAGIC               0x78746341 //'xtcA'
#define ACTIVATION_CONTEXT_STRING_SECTION_MAGIC     0x64487353 //'dHsS'
#define ACTIVATION_CONTEXT_GUID_SECTION_MAGIC       0x64487347 //'dHsG'

typedef enum _ACTIVATION_CONTEXT_DATA_TYPE {
    dtUnknown,
    dtAssemblyInfo,
    dtDllRedirection,
    dtWindowClassRedirection,
    dtComDataTypeLibraryRedirection,
    dtApplicationSettings,
    dtMax
} ACTIVATION_CONTEXT_DATA_TYPE;

typedef VOID(NTAPI * PACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
    _In_ ULONG NotificationType,
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _In_ const VOID *ActivationContextData,
    _In_ PVOID NotificationContext,
    _In_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification
    );

typedef struct _ACTIVATION_CONTEXT_DATA {
    ULONG Magic; //'xtcA'
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset;
    ULONG ExtendedTocOffset;
    ULONG AssemblyRosterOffset;
    ULONG Flags;
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ACTIVATION_CONTEXT_DATA_APPLICATION_SETTINGS {
    ULONG Size;
    ULONG Flags;
    ULONG SettingNamespaceLength;
    ULONG SettingNamespaceOffset;
    ULONG SettingNameLength;
    ULONG SettingNameOffset;
    ULONG SettingValueLength;
    ULONG SettingValueOffset;
} ACTIVATION_CONTEXT_DATA_APPLICATION_SETTINGS, *PACTIVATION_CONTEXT_DATA_APPLICATION_SETTINGS;

typedef struct _ACTIVATION_CONTEXT_DATA_COM_TYPE_LIBRARY_REDIRECTION {
    ULONG Size;
    ULONG Flags;
    ULONG NameLength;
    ULONG NameOffset;
    USHORT ResourceId;
    USHORT LibraryFlags;
    ULONG HelpDirLength;
    ULONG HelpDirOffset;
} ACTIVATION_CONTEXT_DATA_COM_TYPE_LIBRARY_REDIRECTION, *PACTIVATION_CONTEXT_DATA_COM_TYPE_LIBRARY_REDIRECTION;

typedef struct _ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT {
    ULONG Length;
    ULONG Offset;
} ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT, *PACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT;

typedef struct _ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION {
    ULONG Size;
    ULONG Flags;
    ULONG TotalPathLength;
    ULONG PathSegmentCount;
    ULONG PathSegmentOffset;
} ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION, *PACTIVATION_CONTEXT_DATA_DLL_REDIRECTION;

typedef struct _ACTIVATION_CONTEXT_DATA_WINDOW_CLASS_REDIRECTION {
    ULONG Size;
    ULONG Flags;
    ULONG VersionSpecificClassNameLength;
    ULONG VersionSpecificClassNameOffset;
    ULONG DllNameLength;
    ULONG DllNameOffset;
} ACTIVATION_CONTEXT_DATA_WINDOW_CLASS_REDIRECTION, *PACTIVATION_CONTEXT_DATA_WINDOW_CLASS_REDIRECTION;

typedef struct _ACTIVATION_CONTEXT_DATA_COM_PROGID_REDIRECTION {
    ULONG Size;
    ULONG Flags;
    ULONG ConfiguredClsidOffset;
} ACTIVATION_CONTEXT_DATA_COM_PROGID_REDIRECTION, *PACTIVATION_CONTEXT_DATA_COM_PROGID_REDIRECTION;

typedef struct _ACTIVATION_CONTEXT_DATA_TOC_ENTRY {
    ULONG Id;
    ULONG Offset;
    ULONG Length;
    ULONG Format;
} ACTIVATION_CONTEXT_DATA_TOC_ENTRY, *PACTIVATION_CONTEXT_DATA_TOC_ENTRY;

typedef struct _ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY {
    GUID ExtensionGuid;
    ULONG Offset;
    ULONG Length;
} ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY, *PACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY;

typedef struct _ACTIVATION_CONTEXT_DATA_TOC_HEADER {
    ULONG HeaderSize;
    ULONG EntryCount;
    ULONG FirstEntryOffset;
    ULONG Flags;
} ACTIVATION_CONTEXT_DATA_TOC_HEADER, *PACTIVATION_CONTEXT_DATA_TOC_HEADER;

typedef struct _ACTIVATION_CONTEXT_STRING_SECTION_HASH_BUCKET {
    ULONG ChainCount;
    ULONG ChainOffset;
} ACTIVATION_CONTEXT_STRING_SECTION_HASH_BUCKET, *PACTIVATION_CONTEXT_STRING_SECTION_HASH_BUCKET;

typedef struct _ACTIVATION_CONTEXT_STRING_SECTION_HASH_TABLE {
    ULONG BucketTableEntryCount;
    ULONG BucketTableOffset;
} ACTIVATION_CONTEXT_STRING_SECTION_HASH_TABLE, *PACTIVATION_CONTEXT_STRING_SECTION_HASH_TABLE;

typedef struct _ACTIVATION_CONTEXT_STRING_SECTION_ENTRY {
    ULONG PseudoKey;
    ULONG KeyOffset;
    ULONG KeyLength;
    ULONG Offset;
    ULONG Length;
    ULONG AssemblyRosterIndex;
} ACTIVATION_CONTEXT_STRING_SECTION_ENTRY, *PACTIVATION_CONTEXT_STRING_SECTION_ENTRY;

typedef struct _ACTIVATION_CONTEXT_STRING_SECTION_HEADER {
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG DataFormatVersion;
    ULONG Flags;
    ULONG ElementCount;
    ULONG ElementListOffset;
    ULONG HashAlgorithm;
    ULONG SearchStructureOffset;
    ULONG UserDataOffset;
    ULONG UserDataSize;
} ACTIVATION_CONTEXT_STRING_SECTION_HEADER, *PACTIVATION_CONTEXT_STRING_SECTION_HEADER;

typedef struct _ACTIVATION_CONTEXT_GUID_SECTION_ENTRY {
    GUID Guid;
    ULONG Offset;
    ULONG Length;
    ULONG AssemblyRosterIndex;
} ACTIVATION_CONTEXT_GUID_SECTION_ENTRY, *PACTIVATION_CONTEXT_GUID_SECTION_ENTRY;

typedef struct _ACTIVATION_CONTEXT_GUID_SECTION_HEADER {
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG DataFormatVersion;
    ULONG Flags;
    ULONG ElementCount;
    ULONG ElementListOffset;
    ULONG HashAlgorithm;
    ULONG SearchStructureOffset;
    ULONG UserDataOffset;
    ULONG UserDataSize;
} ACTIVATION_CONTEXT_GUID_SECTION_HEADER, PACTIVATION_CONTEXT_GUID_SECTION_HEADER;

typedef struct _ACTIVATION_CONTEXT_ASSEMBLY_DATA {
    ULONG Size;
    ULONG Flags;
    WCHAR *AssemblyName;
    ULONG AssemblyNameLength;
    ULONG HashAlgorithm;
    ULONG PseudoKey;
} ACTIVATION_CONTEXT_ASSEMBLY_DATA, *PACTIVATION_CONTEXT_ASSEMBLY_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY {
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP {
    ULONG Flags;
    ULONG Count;
    ASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray[ANYSIZE_ARRAY];
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _ACTIVATION_CONTEXT {
    ULONG RefCount;
    ULONG Flags;
    LIST_ENTRY Links;
    ACTIVATION_CONTEXT_DATA *ActivationContextData;
    PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
    PVOID NotificationContext;
    ULONG SendNotifications[4];
    ULONG DisabledNotifications[4];
    ASSEMBLY_STORAGE_MAP StorageMap;
    ASSEMBLY_STORAGE_MAP_ENTRY *InlineStorageMapEntries;
    ULONG StackTraceIndex;
    PVOID StackTraces[4][4];
} ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;

typedef struct _ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY {
    ULONG Flags;
    ULONG PseudoKey;
    ULONG AssemblyNameOffset;
    ULONG AssemblyNameLength;
    ULONG AssemblyInformationOffset;
    ULONG AssemblyInformationLength;
} ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY, *PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY;

typedef struct _ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER {
    ULONG HeaderSize;
    ULONG HashAlgorithm;
    ULONG EntryCount;
    ULONG FirstEntryOffset;
    ULONG AssemblyInformationSectionOffset;
} ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER, *PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER;

#pragma pack(push,1)
typedef struct _ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION {
    ULONG Size;
    ULONG Flags;
    ULONG EncodedAssemblyIdentityLength;
    ULONG EncodedAssemblyIdentityOffset;
    ULONG ManifestPathType;
    ULONG ManifestPathLength;
    ULONG ManifestPathOffset;
    LARGE_INTEGER ManifestLastWriteTime;
    ULONG PolicyPathType;
    ULONG PolicyPathLength;
    ULONG PolicyPathOffset;
    LARGE_INTEGER PolicyLastWriteTime;
    ULONG MetadataSatelliteRosterIndex;
    ULONG Unused2;
    ULONG ManifestVersionMajor;
    ULONG ManifestVersionMinor;
    ULONG PolicyVersionMajor;
    ULONG PolicyVersionMinor;
    ULONG AssemblyDirectoryNameLength;
    ULONG AssemblyDirectoryNameOffset;
    ULONG NumOfFilesInAssembly;
    ULONG LanguageLength;
    ULONG LanguageOffset;
    ACTCTX_REQUESTED_RUN_LEVEL RunLevel;
    ULONG UiAccess;
} ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION, *PACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION;
#pragma pack(pop)

typedef struct _ACTIVATION_CONTEXT_SECTION_KEYED_DATA_ASSEMBLY_METADATA {
    PVOID Information;
    PVOID SectionBase;
    ULONG SectionLength;
    PVOID SectionGlobalDataBase;
    ULONG SectionGlobalDataLength;
} ACTIVATION_CONTEXT_SECTION_KEYED_DATA_ASSEMBLY_METADATA, *PACTIVATION_CONTEXT_SECTION_KEYED_DATA_ASSEMBLY_METADATA;

typedef const ACTIVATION_CONTEXT_SECTION_KEYED_DATA_ASSEMBLY_METADATA *PCACTIVATION_CONTEXT_SECTION_KEYED_DATA_ASSEMBLY_METADATA;

typedef struct _ACTIVATION_CONTEXT_SECTION_KEYED_DATA {
    ULONG Size;
    ULONG DataFormatVersion;
    PVOID Data;
    ULONG Length;
    PVOID SectionGlobalData;
    ULONG SectionGlobalDataLength;
    PVOID SectionBase;
    ULONG SectionTotalLength;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG AssemblyRosterIndex;
    ULONG Flags;
    ACTIVATION_CONTEXT_SECTION_KEYED_DATA_ASSEMBLY_METADATA AssemblyMetadata;
} ACTIVATION_CONTEXT_SECTION_KEYED_DATA, *PACTIVATION_CONTEXT_SECTION_KEYED_DATA;

typedef const ACTIVATION_CONTEXT_SECTION_KEYED_DATA * PCACTIVATION_CONTEXT_SECTION_KEYED_DATA;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
    RTL_ACTIVATION_CONTEXT_STACK_FRAME *ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

NTSTATUS NTAPI RtlQueryInformationActivationContext(
    _In_ ULONG Flags,
    _In_ PCACTIVATION_CONTEXT ActivationContext,
    _In_opt_ PVOID SubInstanceIndex,
    _In_ ACTIVATION_CONTEXT_INFO_CLASS ActivationContextInformationClass,
    _Out_ PVOID ActivationContextInformation,
    _In_ SIZE_T ActivationContextInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

NTSTATUS NTAPI RtlQueryInformationActiveActivationContext(
    _In_ ACTIVATION_CONTEXT_INFO_CLASS ActivationContextInformationClass,
    _Out_ PVOID ActivationContextInformation,
    _In_ SIZE_T ActivationContextInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

NTSTATUS NTAPI RtlCreateActivationContext(
    _In_ ULONG Flags,
    _In_ const PACTIVATION_CONTEXT_DATA ActivationContextData,
    _In_opt_ ULONG ExtraBytes,
    _In_opt_ PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine,
    _In_opt_ PVOID NotificationContext,
    _Out_ PACTIVATION_CONTEXT *ActivationContext
);

VOID NTAPI RtlAddRefActivationContext(
    _In_ PACTIVATION_CONTEXT AppCtx
);

VOID NTAPI RtlReleaseActivationContext(
    _In_ PACTIVATION_CONTEXT AppCtx
);

NTSTATUS NTAPI RtlZombifyActivationContext(
    _In_ PACTIVATION_CONTEXT ActivationContext
);

NTSTATUS NTAPI RtlGetActiveActivationContext(
    _Out_ PACTIVATION_CONTEXT *ActivationContext
);

BOOLEAN NTAPI RtlIsActivationContextActive(
    _In_ PACTIVATION_CONTEXT ActivationContext
);

NTSTATUS NTAPI RtlQueryActivationContextApplicationSettings(
    _In_opt_      DWORD dwFlags,
    _In_opt_      HANDLE hActCtx,
    _In_opt_      PCWSTR settingsNameSpace,
    _In_          PCWSTR settingName,
    _Out_writes_bytes_to_opt_(dwBuffer, *pdwWrittenOrRequired) PWSTR pvBuffer,
    _In_      SIZE_T dwBuffer,
    _Out_opt_ SIZE_T *pdwWrittenOrRequired
);

NTSTATUS NTAPI RtlFindActivationContextSectionString(
    _In_        ULONG Flags,
    _In_opt_    CONST GUID *ExtensionGuid,
    _In_        ULONG SectionId,
    _In_        PCUNICODE_STRING StringToFind,
    _Inout_     PACTIVATION_CONTEXT_SECTION_KEYED_DATA ReturnedData
);
