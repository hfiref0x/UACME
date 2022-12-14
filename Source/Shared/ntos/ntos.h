/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022 
*  Translated from Microsoft sources/debugger or mentioned elsewhere.
*
*  TITLE:       NTOS.H
*
*  VERSION:     1.201
*
*  DATE:        17 Aug 2022
*
*  Common header file for the ntos API functions and definitions.
*
*  Only projects required API/definitions.
*
*  Depends on:    Windows.h
*                 NtStatus.h
*
*  Include:       Windows.h
*                 NtStatus.h
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int

#ifndef NTOS_RTL
#define NTOS_RTL

//
// NTOS_RTL HEADER BEGIN
//

//
// Enable LIST_ENTRY macroses.
//
#define NTOS_ENABLE_LIST_ENTRY_MACRO

#if defined(__cplusplus)

#ifndef MICROSOFT_WINDOWS_WINBASE_H_DEFINE_INTERLOCKED_CPLUSPLUS_OVERLOADS
#define MICROSOFT_WINDOWS_WINBASE_H_DEFINE_INTERLOCKED_CPLUSPLUS_OVERLOADS 0
#endif

extern "C" {
#endif

#pragma comment(lib, "ntdll.lib")

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000ull
#endif

#ifndef ABSOLUTE_TIME
#define ABSOLUTE_TIME(wait) (wait)
#endif

#ifndef RELATIVE_TIME
#define RELATIVE_TIME(wait) (-(wait))
#endif

#ifndef NANOSECONDS
#define NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100L)
#endif

#ifndef MICROSECONDS
#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000L))
#endif

#ifndef MILLISECONDS
#define MILLISECONDS(milli) (((signed __int64)(milli)) * MICROSECONDS(1000L))
#endif

#ifndef SECONDS
#define SECONDS(seconds) (((signed __int64)(seconds)) * MILLISECONDS(1000L))
#endif

#ifndef POI //poi-poi
#define POI(addr) *(ULONG *)(addr)
#endif

typedef char CCHAR;
typedef unsigned char UCHAR;
typedef CCHAR KPROCESSOR_MODE;
typedef UCHAR KIRQL;
typedef KIRQL *PKIRQL;
typedef ULONG CLONG;
typedef LONG KPRIORITY;
typedef short CSHORT;
typedef ULONGLONG REGHANDLE, *PREGHANDLE;
typedef PVOID *PDEVICE_MAP;
typedef PVOID PHEAD;
typedef PVOID PEJOB;
typedef struct _IO_TIMER* PIO_TIMER;
typedef LARGE_INTEGER PHYSICAL_ADDRESS;
typedef struct _EJOB* PESILO;

#ifndef _WIN32_WINNT_WIN10
#define _WIN32_WINNT_WIN10 0x0A00
#endif
#if (_WIN32_WINNT < _WIN32_WINNT_WIN10)
typedef PVOID PMEM_EXTENDED_PARAMETER;
#endif

#ifndef IN_REGION
#define IN_REGION(x, Base, Size) (((ULONG_PTR)(x) >= (ULONG_PTR)(Base)) && \
            ((ULONG_PTR)(x) <= (ULONG_PTR)(Base) + (ULONG_PTR)(Size)))
#endif

//
// Define alignment macros to align structure sizes and pointers up and down.
//

#ifndef ALIGN_UP_TYPE
#define ALIGN_UP_TYPE(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#endif

#ifndef ALIGN_UP
#define ALIGN_UP(Address, Type) ALIGN_UP_TYPE(Address, sizeof(Type))
#endif

#ifndef ALIGN_DOWN_TYPE
#define ALIGN_DOWN_TYPE(Address, Align) ((ULONG_PTR)(Address) & ~((ULONG_PTR)(Align) - 1))
#endif

#ifndef ALIGN_DOWN
#define ALIGN_DOWN(Address, Type) ALIGN_DOWN_TYPE(Address, sizeof(Type))
#endif

#ifndef ALIGN_UP_BY
#define ALIGN_UP_BY(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#endif

#ifndef ALIGN_DOWN_BY
#define ALIGN_DOWN_BY(Address, Align) ((ULONG_PTR)(Address) & ~((ULONG_PTR)(Align) - 1))
#endif

#ifndef ALIGN_UP_POINTER_BY
#define ALIGN_UP_POINTER_BY(Pointer, Align) ((PVOID)ALIGN_UP_BY(Pointer, Align))
#endif

#ifndef ALIGN_DOWN_POINTER_BY
#define ALIGN_DOWN_POINTER_BY(Pointer, Align) ((PVOID)ALIGN_DOWN_BY(Pointer, Align))
#endif

#ifndef ALIGN_UP_POINTER
#define ALIGN_UP_POINTER(Pointer, Type) ((PVOID)ALIGN_UP(Pointer, Type))
#endif

#ifndef ALIGN_DOWN_POINTER
#define ALIGN_DOWN_POINTER(Pointer, Type) ((PVOID)ALIGN_DOWN(Pointer, Type))
#endif

#ifndef ARGUMENT_PRESENT
#define ARGUMENT_PRESENT(ArgumentPointer)    (\
    (CHAR *)((ULONG_PTR)(ArgumentPointer)) != (CHAR *)(NULL) )
#endif

#ifndef LOGICAL
#define LOGICAL ULONG
#endif

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()

//Valid Only for Windows 8+
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) 
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5)
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) //GetCurrentThreadEffectiveToken

//
// ntdef.h begin
//
#ifndef RTL_CONSTANT_STRING
char _RTL_CONSTANT_STRING_type_check(const void *s);
#define _RTL_CONSTANT_STRING_remove_const_macro(s) (s)
#define RTL_CONSTANT_STRING(s) \
{ \
    sizeof( s ) - sizeof( (s)[0] ), \
    sizeof( s ) / sizeof(_RTL_CONSTANT_STRING_type_check(s)), \
    _RTL_CONSTANT_STRING_remove_const_macro(s) \
}
#endif

#ifndef RTL_CONSTANT_OBJECT_ATTRIBUTES
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) \
    { sizeof(OBJECT_ATTRIBUTES), NULL, RTL_CONST_CAST(PUNICODE_STRING)(n), a, NULL, NULL }
#endif

// This synonym is more appropriate for initializing what isn't actually const.
#ifndef RTL_INIT_OBJECT_ATTRIBUTES
#define RTL_INIT_OBJECT_ATTRIBUTES(n, a) RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)
#endif

//
// ntdef.h end
//
#ifndef RtlOffsetToPointer
#define RtlOffsetToPointer(Base, Offset)  ((PCHAR)( ((PCHAR)(Base)) + ((ULONG_PTR)(Offset))  ))
#endif

#ifndef RtlPointerToOffset
#define RtlPointerToOffset(Base, Pointer)  ((ULONG)( ((PCHAR)(Pointer)) - ((PCHAR)(Base))  ))
#endif

//
// Valid values for the OBJECT_ATTRIBUTES.Attributes field
//
#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define OBJ_PROTECT_CLOSE                   0x00000001L
#define OBJ_AUDIT_OBJECT_CLOSE              0x00000004L

//
// Callback Object Rights
//
#define CALLBACK_MODIFY_STATE    0x0001
#define CALLBACK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|CALLBACK_MODIFY_STATE )

//
// CompositionSurface Access Rights
//
#ifndef COMPOSITIONSURFACE_READ
#define COMPOSITIONSURFACE_READ         0x0001L
#endif

#ifndef COMPOSITIONSURFACE_WRITE
#define COMPOSITIONSURFACE_WRITE        0x0002L
#endif

#ifndef COMPOSITIONSURFACE_ALL_ACCESS
#define COMPOSITIONSURFACE_ALL_ACCESS   (COMPOSITIONSURFACE_READ | COMPOSITIONSURFACE_WRITE)
#endif

//
// Debug Object Access Rights
//
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
                              DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

//
// Directory Object Access Rights
//
#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

//
// Event Object Access Rights
//
#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE       0x0001
#endif

#ifndef EVENT_MODIFY_STATE      //SDK compatibility
#define EVENT_MODIFY_STATE      0x0002  
#endif

#ifndef EVENT_ALL_ACCESS        //SDK compatibility
#define EVENT_ALL_ACCESS(EVENT_QUERY_STATE | EVENT_MODIFY_STATE | STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE)
#endif

//
// EventPair Object Access Rights
//
#define EVENT_PAIR_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE)

//
// I/O Completion Object Access Rights
//
#define IO_COMPLETION_QUERY_STATE   0x0001
#define IO_COMPLETION_MODIFY_STATE  0x0002  
#define IO_COMPLETION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3) 

//
// KeyedEvent Object Access Rights
//
#define KEYEDEVENT_WAIT 0x0001
#define KEYEDEVENT_WAKE 0x0002
#define KEYEDEVENT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | KEYEDEVENT_WAIT | KEYEDEVENT_WAKE)

//
// Mutant Object Access Rights
//
#ifndef MUTANT_QUERY_STATE      //SDK compatibility
#define MUTANT_QUERY_STATE      0x0001
#endif

#ifndef MUTANT_ALL_ACCESS //SDK compatibility
#define MUTANT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|MUTANT_QUERY_STATE)
#endif

//
// Port Object Access Rights
//
#define PORT_CONNECT (0x0001)
#define PORT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | PORT_CONNECT)

//
// Filter Port Access Rights
//
#define FLT_PORT_CONNECT 0x0001
#define FLT_PORT_ALL_ACCESS (FLT_PORT_CONNECT|STANDARD_RIGHTS_ALL)

//
// Profile Object Access Rights
//
#define PROFILE_CONTROL (0x0001)
#define PROFILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | PROFILE_CONTROL)

//
// Semaphore Object Access Rights
//
#ifndef SEMAPHORE_QUERY_STATE       //SDK compatibility
#define SEMAPHORE_QUERY_STATE       0x0001
#endif

#ifndef SEMAPHORE_MODIFY_STATE      //SDK compatibility
#define SEMAPHORE_MODIFY_STATE      0x0002 
#endif

#ifndef SEMAPHORE_ALL_ACCESS //SDK compatibility
#define SEMAPHORE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|SEMAPHORE_QUERY_STATE|SEMAPHORE_MODIFY_STATE)
#endif

//
// Time Object Access rights
//
#ifndef TIMER_QUERY_STATE
#define TIMER_QUERY_STATE 0x0001
#endif

#ifndef TIMER_MODIFY_STATE
#define TIMER_MODIFY_STATE 0x0002
#endif

#ifndef TIMER_ALL_ACCESS
#define TIMER_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|TIMER_QUERY_STATE|TIMER_MODIFY_STATE)
#endif

//
// SymbolicLink Object Access Rights
//
#define SYMBOLIC_LINK_QUERY 0x0001
#define SYMBOLIC_LINK_SET   0x0002
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY)
#define SYMBOLIC_LINK_ALL_ACCESS_EX (STANDARD_RIGHTS_REQUIRED | 0xFFFF)

//
// Thread Object Access Rights
//
#define THREAD_ALERT   (0x0004)

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED        0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH      0x00000002 
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER      0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET  0x00000020
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE   0x00000040
#define THREAD_CREATE_FLAGS_INITIAL_THREAD          0x00000080

//
// Worker Factory Object Access Rights
//
#define WORKER_FACTORY_RELEASE_WORKER       0x0001
#define WORKER_FACTORY_WAIT                 0x0002
#define WORKER_FACTORY_SET_INFORMATION      0x0004
#define WORKER_FACTORY_QUERY_INFORMATION    0x0008
#define WORKER_FACTORY_READY_WORKER         0x0010
#define WORKER_FACTORY_SHUTDOWN             0x0020

#define WORKER_FACTORY_ALL_ACCESS ( \
    STANDARD_RIGHTS_REQUIRED | \
    WORKER_FACTORY_RELEASE_WORKER | \
    WORKER_FACTORY_WAIT | \
    WORKER_FACTORY_SET_INFORMATION | \
    WORKER_FACTORY_QUERY_INFORMATION | \
    WORKER_FACTORY_READY_WORKER | \
    WORKER_FACTORY_SHUTDOWN \
    )

//
// Type Object Access Rights
//
#define OBJECT_TYPE_CREATE (0x0001)
#define OBJECT_TYPE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | OBJECT_TYPE_CREATE)

//
// WMI Object Access Rights
//
#define WMIGUID_QUERY                 0x0001
#define WMIGUID_SET                   0x0002
#define WMIGUID_NOTIFICATION          0x0004
#define WMIGUID_READ_DESCRIPTION      0x0008
#define WMIGUID_EXECUTE               0x0010
#define TRACELOG_CREATE_REALTIME      0x0020
#define TRACELOG_CREATE_ONDISK        0x0040
#define TRACELOG_GUID_ENABLE          0x0080
#define TRACELOG_ACCESS_KERNEL_LOGGER 0x0100
#define TRACELOG_LOG_EVENT            0x0200 // used on Vista and greater
#define TRACELOG_CREATE_INPROC        0x0200 // used pre-Vista
#define TRACELOG_ACCESS_REALTIME      0x0400
#define TRACELOG_REGISTER_GUIDS       0x0800
#define TRACELOG_JOIN_GROUP           0x1000

//
// Memory Partition Object Access Rights
//
#ifndef MEMORY_PARTITION_QUERY_ACCESS
#define MEMORY_PARTITION_QUERY_ACCESS  0x0001
#define MEMORY_PARTITION_MODIFY_ACCESS 0x0002

#define MEMORY_PARTITION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED |         \
                                     SYNCHRONIZE |                      \
                                     MEMORY_PARTITION_QUERY_ACCESS |    \
                                     MEMORY_PARTITION_MODIFY_ACCESS)
#endif

//
// Define special ByteOffset parameters for read and write operations
//
#ifndef FILE_WRITE_TO_END_OF_FILE
#define FILE_WRITE_TO_END_OF_FILE       0xffffffff
#endif
#ifndef FILE_USE_FILE_POINTER_POSITION
#define FILE_USE_FILE_POINTER_POSITION  0xfffffffe
#endif

#ifndef FILE_SHARE_VALID_FLAGS
#define FILE_SHARE_VALID_FLAGS FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
#endif

//
// This is the maximum MaximumLength for a UNICODE_STRING.
//
#ifndef MAXUSHORT
#define MAXUSHORT   0xffff     
#endif
#ifndef MAX_USTRING
#define MAX_USTRING ( sizeof(WCHAR) * (MAXUSHORT/sizeof(WCHAR)) )
#endif

typedef struct _EX_RUNDOWN_REF {
    union
    {
        ULONG Count;
        PVOID Ptr;
    };
} EX_RUNDOWN_REF, *PEX_RUNDOWN_REF;

#ifdef _WIN64
#define MAX_FAST_REFS 15
#else
#define MAX_FAST_REFS 7
#endif

typedef struct _EX_FAST_REF {
    union {
        PVOID Object;
#if defined (_WIN64)
        ULONG_PTR RefCnt : 4;
#else
        ULONG_PTR RefCnt : 3;
#endif
        ULONG_PTR Value;
    };
} EX_FAST_REF, *PEX_FAST_REF;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#ifndef STATIC_UNICODE_STRING
#define STATIC_UNICODE_STRING(string, value) \
  static UNICODE_STRING string = { sizeof(value) - sizeof(WCHAR), sizeof(value), value };
#endif

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef CONST char *PCSZ;

typedef struct _CSTRING {
    USHORT Length;
    USHORT MaximumLength;
    CONST char *Buffer;
} CSTRING;
typedef CSTRING *PCSTRING;
#define ANSI_NULL ((CHAR)0)

typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#ifndef INTERFACE_TYPE
typedef enum _INTERFACE_TYPE {
    InterfaceTypeUndefined = -1,
    Internal = 0,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    VMEBus,
    NuBus,
    PCMCIABus,
    CBus,
    MPIBus,
    MPSABus,
    ProcessorInternal,
    InternalPowerBus,
    PNPISABus,
    PNPBus,
    Vmcs,
    ACPIBus,
    MaximumInterfaceType
} INTERFACE_TYPE, * PINTERFACE_TYPE;
#endif

/*
** FileCache and MemoryList START
*/

typedef enum _SYSTEM_MEMORY_LIST_COMMAND {
    MemoryCaptureAccessedBits,
    MemoryCaptureAndResetAccessedBits,
    MemoryEmptyWorkingSets,
    MemoryFlushModifiedList,
    MemoryPurgeStandbyList,
    MemoryPurgeLowPriorityStandbyList,
    MemoryCommandMax
} SYSTEM_MEMORY_LIST_COMMAND;

typedef struct _SYSTEM_FILECACHE_INFORMATION {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

/*
** FileCache and MemoryList END
*/

/*
** Processes START
*/

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

typedef enum _THREAD_STATE {
    StateInitialized,
    StateReady,
    StateRunning,
    StateStandby,
    StateTerminated,
    StateWait,
    StateTransition,
    StateUnknown
} THREAD_STATE;

typedef enum _KWAIT_REASON {
    Executive = 0,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair, //has no effect after 7
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    WrIoRing,
    WrMdlCache,
    MaximumWaitReason
} KWAIT_REASON;

typedef VOID KSTART_ROUTINE(
    _In_ PVOID StartContext
);
typedef KSTART_ROUTINE *PKSTART_ROUTINE;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _CLIENT_ID64 {
    ULONG64 UniqueProcess;
    ULONG64 UniqueThread;
} CLIENT_ID64, *PCLIENT_ID64;

typedef struct _CLIENT_ID32 {
    ULONG32 UniqueProcess;
    ULONG32 UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
} VM_COUNTERS;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitchCount;
    THREAD_STATE State;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION {
    SYSTEM_THREAD_INFORMATION ThreadInfo;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32StartAddress;
    PVOID TebBase;
    ULONG_PTR Reserved2;
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESSES_INFORMATION {
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    VM_COUNTERS VmCounters;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESSES_INFORMATION, *PSYSTEM_PROCESSES_INFORMATION;

typedef enum _SYSTEM_PROCESS_CLASSIFICATION {
    SystemProcessClassificationNormal,
    SystemProcessClassificationSystem,
    SystemProcessClassificationSecureSystem,
    SystemProcessClassificationMemCompression,
    SystemProcessClassificationRegistry,
    SystemProcessClassificationMaximum
} SYSTEM_PROCESS_CLASSIFICATION;

typedef struct _PROCESS_DISK_COUNTERS {
    ULONGLONG BytesRead;
    ULONGLONG BytesWritten;
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG FlushOperationCount;
} PROCESS_DISK_COUNTERS, *PPROCESS_DISK_COUNTERS;

typedef union _ENERGY_STATE_DURATION {
    union
    {
        ULONGLONG Value;
        ULONG LastChangeTime;
    };

    ULONG Duration : 31;
    ULONG IsInState : 1;
} ENERGY_STATE_DURATION, *PENERGY_STATE_DURATION;

typedef struct _PROCESS_ENERGY_VALUES {
    ULONGLONG Cycles[2][4];
    ULONGLONG DiskEnergy;
    ULONGLONG NetworkTailEnergy;
    ULONGLONG MBBTailEnergy;
    ULONGLONG NetworkTxRxBytes;
    ULONGLONG MBBTxRxBytes;
    union
    {
        ENERGY_STATE_DURATION Durations[3];
        struct
        {
            ENERGY_STATE_DURATION ForegroundDuration;
            ENERGY_STATE_DURATION DesktopVisibleDuration;
            ENERGY_STATE_DURATION PSMForegroundDuration;
        };
    };
    ULONG CompositionRendered;
    ULONG CompositionDirtyGenerated;
    ULONG CompositionDirtyPropagated;
    ULONG Reserved1;
    ULONGLONG AttributedCycles[4][2];
    ULONGLONG WorkOnBehalfCycles[4][2];
} PROCESS_ENERGY_VALUES, *PPROCESS_ENERGY_VALUES;

typedef struct _SYSTEM_PROCESS_INFORMATION_EXTENSION {
    PROCESS_DISK_COUNTERS DiskCounters;
    ULONGLONG ContextSwitches;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG HasStrongId : 1;
            ULONG Classification : 4; // SYSTEM_PROCESS_CLASSIFICATION
            ULONG BackgroundActivityModerated : 1;
            ULONG Spare : 26;
        };
    };
    ULONG UserSidOffset;
    ULONG PackageFullNameOffset;
    PROCESS_ENERGY_VALUES EnergyValues;
    ULONG AppIdOffset;
    SIZE_T SharedCommitCharge;
    ULONG JobObjectId;
    ULONG SpareUlong;
    ULONGLONG ProcessSequenceNumber;
} SYSTEM_PROCESS_INFORMATION_EXTENSION, *PSYSTEM_PROCESS_INFORMATION_EXTENSION;

typedef struct _SYSTEM_PROCESSES_FULL_INFORMATION {
    SYSTEM_PROCESSES_INFORMATION ProcessAndThreads;
    SYSTEM_PROCESS_INFORMATION_EXTENSION ExtendedInfo;
} SYSTEM_PROCESSES_FULL_INFORMATION, *PSYSTEM_PROCESSES_FULL_INFORMATION;

typedef struct _SYSTEM_PROCESS_ID_INFORMATION {
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION;

typedef struct _SYSTEM_SECUREBOOT_INFORMATION {
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootCapable;
} SYSTEM_SECUREBOOT_INFORMATION, *PSYSTEM_SECUREBOOT_INFORMATION;

typedef struct _SYSTEM_SECUREBOOT_POLICY_INFORMATION {
    GUID PolicyPublisher;
    ULONG PolicyVersion;
    ULONG PolicyOptions;
} SYSTEM_SECUREBOOT_POLICY_INFORMATION, *PSYSTEM_SECUREBOOT_POLICY_INFORMATION;

typedef struct _SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION {
    SYSTEM_SECUREBOOT_POLICY_INFORMATION PolicyInformation;
    ULONG PolicySize;
    UCHAR Policy[1];
} SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION, *PSYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_ISOLATED_USER_MODE_INFORMATION {
    BOOLEAN SecureKernelRunning : 1;
    BOOLEAN HvciEnabled : 1;
    BOOLEAN HvciStrictMode : 1;
    BOOLEAN DebugEnabled : 1;
    BOOLEAN FirmwarePageProtection : 1;
    BOOLEAN EncryptionKeyAvailable : 1;
    BOOLEAN SpareFlags : 2;
    BOOLEAN TrustletRunning : 1;
    BOOLEAN HvciDisableAllowed : 1;
    BOOLEAN SpareFlags2 : 6;
    BOOLEAN Spare0[6];
    ULONGLONG Spare1;
} SYSTEM_ISOLATED_USER_MODE_INFORMATION, *PSYSTEM_ISOLATED_USER_MODE_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_FEATURES_INFORMATION { //chappell
    ULONGLONG ProcessorFeatureBits;
    ULONGLONG Reserved[3];
} SYSTEM_PROCESSOR_FEATURES_INFORMATION, * PSYSTEM_PROCESSOR_FEATURES_INFORMATION;

typedef struct _SYSTEM_POOL_ENTRY {
    BOOLEAN Allocated;
    BOOLEAN Spare0;
    USHORT AllocatorBackTraceIndex;
    ULONG Size;
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
        PVOID ProcessChargedQuota;
    };
} SYSTEM_POOL_ENTRY, * PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION {
    SIZE_T TotalSize;
    PVOID FirstEntry;
    USHORT EntryOverhead;
    BOOLEAN PoolTagPresent;
    BOOLEAN Spare0;
    ULONG NumberOfEntries;
    SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, * PSYSTEM_POOL_INFORMATION;

typedef struct _SYSTEM_POOLTAG {
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, * PSYSTEM_POOLTAG;

typedef struct _SYSTEM_BIGPOOL_ENTRY {
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    SIZE_T SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_POOLTAG_INFORMATION {
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, * PSYSTEM_POOLTAG_INFORMATION;

typedef struct _SYSTEM_SESSION_POOLTAG_INFORMATION {
    SIZE_T NextEntryOffset;
    ULONG SessionId;
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_SESSION_POOLTAG_INFORMATION, * PSYSTEM_SESSION_POOLTAG_INFORMATION;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION {
    PCHAR SymbolicBackTrace;
    ULONG TraceCount;
    USHORT Index;
    USHORT Depth;
    PVOID BackTrace[32];
} RTL_PROCESS_BACKTRACE_INFORMATION, * PRTL_PROCESS_BACKTRACE_INFORMATION;

typedef struct _RTL_PROCESS_BACKTRACES {
    ULONG CommittedMemory;
    ULONG ReservedMemory;
    ULONG NumberOfBackTraceLookups;
    ULONG NumberOfBackTraces;
    RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
} RTL_PROCESS_BACKTRACES, * PRTL_PROCESS_BACKTRACES;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22,
    ProcessDeviceMap = 23,
    ProcessSessionInformation = 24,
    ProcessForegroundInformation = 25,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    ProcessTlsInformation = 35,
    ProcessCookie = 36,
    ProcessImageInformation = 37,
    ProcessCycleTime = 38,
    ProcessPagePriority = 39,
    ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41,
    ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43,
    ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45,
    ProcessMemoryAllocationMode = 46,
    ProcessGroupInformation = 47,
    ProcessTokenVirtualizationEnabled = 48,
    ProcessOwnerInformation = 49,
    ProcessWindowInformation = 50,
    ProcessHandleInformation = 51,
    ProcessMitigationPolicy = 52,
    ProcessDynamicFunctionTableInformation = 53,
    ProcessHandleCheckingMode = 54,
    ProcessKeepAliveCount = 55,
    ProcessRevokeFileHandles = 56,
    ProcessWorkingSetControl = 57,
    ProcessHandleTable = 58,
    ProcessCheckStackExtentsMode = 59,
    ProcessCommandLineInformation = 60,
    ProcessProtectionInformation = 61,
    ProcessMemoryExhaustion = 62,
    ProcessFaultInformation = 63,
    ProcessTelemetryIdInformation = 64,
    ProcessCommitReleaseInformation = 65,
    ProcessDefaultCpuSetsInformation = 66,
    ProcessAllowedCpuSetsInformation = 67,
    ProcessSubsystemProcess = 68,
    ProcessJobMemoryInformation = 69,
    ProcessInPrivate = 70,
    ProcessRaiseUMExceptionOnInvalidHandleClose = 71,
    ProcessIumChallengeResponse = 72,
    ProcessChildProcessInformation = 73,
    ProcessHighGraphicsPriorityInformation = 74,
    ProcessSubsystemInformation = 75,
    ProcessEnergyValues = 76,
    ProcessActivityThrottleState = 77,
    ProcessActivityThrottlePolicy = 78,
    ProcessWin32kSyscallFilterInformation = 79,
    ProcessDisableSystemAllowedCpuSets = 80,
    ProcessWakeInformation = 81,
    ProcessEnergyTrackingState = 82,
    ProcessManageWritesToExecutableMemory = 83,
    ProcessCaptureTrustletLiveDump = 84,
    ProcessTelemetryCoverage = 85,
    ProcessEnclaveInformation = 86,
    ProcessEnableReadWriteVmLogging = 87,
    ProcessUptimeInformation = 88,
    ProcessImageSection = 89,
    ProcessDebugAuthInformation = 90,
    ProcessSystemResourceManagement = 91,
    ProcessSequenceNumber = 92,
    ProcessLoaderDetour = 93,
    ProcessSecurityDomainInformation = 94,
    ProcessCombineSecurityDomainsInformation = 95,
    ProcessEnableLogging = 96,
    ProcessLeapSecondInformation = 97,
    ProcessFiberShadowStackAllocation = 98,
    ProcessFreeFiberShadowStackAllocation = 99,
    ProcessAltSystemCallInformation = 100,
    ProcessDynamicEHContinuationTargets = 101,
    ProcessDynamicEnforcedCetCompatibleRanges = 102,
    ProcessCreateStateChange = 103,
    ProcessApplyStateChange = 104,
    ProcessEnableOptionalXStateFeatures = 105,
    ProcessAltPrefetchParam = 106,
    ProcessAssignCpuPartitions = 107,
    ProcessPriorityClassEx = 108,
    ProcessMembershipInformation = 109,
    ProcessEffectiveIoPriority = 110,
    ProcessEffectivePagePriority = 111,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    ThreadCpuAccountingInformation,
    ThreadSuspendCount,
    ThreadHeterogeneousCpuPolicy,
    ThreadContainerId,
    ThreadNameInformation,
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation,
    ThreadActualGroupAffinity,
    ThreadDynamicCodePolicyInfo,
    ThreadExplicitCaseSensitivity,
    ThreadWorkOnBehalfTicket,
    ThreadSubsystemInformation,
    ThreadDbgkWerReportActive,
    ThreadAttachContainer,
    ThreadManageWritesToExecutableMemory,
    ThreadPowerThrottlingState,
    ThreadWorkloadClass,
    ThreadCreateStateChange,
    ThreadApplyStateChange,
    ThreadStrongerBadHandleChecks,
    ThreadEffectiveIoPriority,
    ThreadEffectivePagePriority,
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _THREAD_NAME_INFORMATION {
    UNICODE_STRING ThreadName;
} THREAD_NAME_INFORMATION, * PTHREAD_NAME_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
    SIZE_T Size;
    PROCESS_BASIC_INFORMATION BasicInfo;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG IsProtectedProcess : 1;
            ULONG IsWow64Process : 1;
            ULONG IsProcessDeleting : 1;
            ULONG IsCrossSessionCreate : 1;
            ULONG IsFrozen : 1;
            ULONG IsBackground : 1;
            ULONG IsStronglyNamed : 1;
            ULONG IsSecureProcess : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG SpareBits : 23;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;

typedef struct _PROCESS_ACCESS_TOKEN {
    HANDLE Token;
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG NumberOfHandles;
    ULONG Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef enum _PROCESS_STATE_CHANGE_TYPE {
    ProcessStateChangeSuspend,
    ProcessStateChangeResume,
    ProcessStateChangeMax,
} PROCESS_STATE_CHANGE_TYPE, *PPROCESS_STATE_CHANGE_TYPE;

typedef enum _THREAD_STATE_CHANGE_TYPE {
    ThreadStateChangeSuspend,
    ThreadStateChangeResume,
    ThreadStateChangeMax,
} THREAD_STATE_CHANGE_TYPE, *PTHREAD_STATE_CHANGE_TYPE;

//
// Process/Thread System and User Time
//  NtQueryInformationProcess using ProcessTimes
//  NtQueryInformationThread using ThreadTimes
//
typedef struct _KERNEL_USER_TIMES {
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef enum _PS_MITIGATION_OPTION {
    PS_MITIGATION_OPTION_NX,
    PS_MITIGATION_OPTION_SEHOP,
    PS_MITIGATION_OPTION_FORCE_RELOCATE_IMAGES,
    PS_MITIGATION_OPTION_HEAP_TERMINATE,
    PS_MITIGATION_OPTION_BOTTOM_UP_ASLR,
    PS_MITIGATION_OPTION_HIGH_ENTROPY_ASLR,
    PS_MITIGATION_OPTION_STRICT_HANDLE_CHECKS,
    PS_MITIGATION_OPTION_WIN32K_SYSTEM_CALL_DISABLE,
    PS_MITIGATION_OPTION_EXTENSION_POINT_DISABLE,
    PS_MITIGATION_OPTION_PROHIBIT_DYNAMIC_CODE,
    PS_MITIGATION_OPTION_CONTROL_FLOW_GUARD,
    PS_MITIGATION_OPTION_BLOCK_NON_MICROSOFT_BINARIES,
    PS_MITIGATION_OPTION_FONT_DISABLE,
    PS_MITIGATION_OPTION_IMAGE_LOAD_NO_REMOTE,
    PS_MITIGATION_OPTION_IMAGE_LOAD_NO_LOW_LABEL,
    PS_MITIGATION_OPTION_IMAGE_LOAD_PREFER_SYSTEM32,
    PS_MITIGATION_OPTION_RETURN_FLOW_GUARD,
    PS_MITIGATION_OPTION_LOADER_INTEGRITY_CONTINUITY,
    PS_MITIGATION_OPTION_STRICT_CONTROL_FLOW_GUARD,
    PS_MITIGATION_OPTION_RESTRICT_SET_THREAD_CONTEXT,
    PS_MITIGATION_OPTION_ROP_STACKPIVOT,
    PS_MITIGATION_OPTION_ROP_CALLER_CHECK,
    PS_MITIGATION_OPTION_ROP_SIMEXEC,
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER,
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER_PLUS,
    PS_MITIGATION_OPTION_RESTRICT_CHILD_PROCESS_CREATION,
    PS_MITIGATION_OPTION_IMPORT_ADDRESS_FILTER,
    PS_MITIGATION_OPTION_MODULE_TAMPERING_PROTECTION,
    PS_MITIGATION_OPTION_RESTRICT_INDIRECT_BRANCH_PREDICTION,
    PS_MITIGATION_OPTION_SPECULATIVE_STORE_BYPASS_DISABLE,
    PS_MITIGATION_OPTION_ALLOW_DOWNGRADE_DYNAMIC_CODE_POLICY,
    PS_MITIGATION_OPTION_CET_SHADOW_STACKS,
    PS_MITIGATION_OPTION_USER_CET_SET_CONTEXT_IP_VALIDATION,
    PS_MITIGATION_OPTION_BLOCK_NON_CET_BINARIES,
    PS_MITIGATION_OPTION_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY,
    PS_MITIGATION_OPTION_REDIRECTION_TRUST
} PS_MITIGATION_OPTION;

typedef enum _PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        struct
        {
            HANDLE FileHandle;
        } FailSection;

        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1;
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE {
    ULONG Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone,
    PsProtectedTypeProtectedLight,
    PsProtectedTypeProtected,
    PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

#define PS_PROTECTED_SIGNER_MASK 0xFF
#define PS_PROTECTED_AUDIT_MASK 0x08
#define PS_PROTECTED_TYPE_MASK 0x07

// from ph2
#define PsProtectedValue(aSigner, aAudit, aType) ( \
    (((aSigner) & PS_PROTECTED_SIGNER_MASK) << 4) | \
    (((aAudit) & PS_PROTECTED_AUDIT_MASK) << 3) | \
    ((aType) & PS_PROTECTED_TYPE_MASK)\
    )

#define InitializePsProtection(aProtectionLevelPtr, aSigner, aAudit, aType) { \
    (aProtectionLevelPtr)->Signer = aSigner; \
    (aProtectionLevelPtr)->Audit = aAudit; \
    (aProtectionLevelPtr)->Type = aType; \
    }

typedef struct _PS_PROTECTION {
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;

// begin_rev
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 
#define PS_ATTRIBUTE_INPUT 0x00020000 
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 
// end_rev

typedef enum _PS_ATTRIBUTE_NUM {
    PsAttributeParentProcess,
    PsAttributeDebugPort,
    PsAttributeToken,
    PsAttributeClientId,
    PsAttributeTebAddress,
    PsAttributeImageName,
    PsAttributeImageInfo,
    PsAttributeMemoryReserve,
    PsAttributePriorityClass,
    PsAttributeErrorMode,
    PsAttributeStdHandleInfo,
    PsAttributeHandleList,
    PsAttributeGroupAffinity,
    PsAttributePreferredNode,
    PsAttributeIdealProcessor,
    PsAttributeUmsThread,
    PsAttributeMitigationOptions,
    PsAttributeProtectionLevel,
    PsAttributeSecureProcess,
    PsAttributeJobList,
    PsAttributeChildProcessPolicy,
    PsAttributeAllApplicationPackagesPolicy,
    PsAttributeWin32kFilter,
    PsAttributeSafeOpenPromptOriginClaim,
    PsAttributeBnoIsolation,
    PsAttributeDesktopAppPolicy,
    PsAttributeChpe,
    PsAttributeMitigationAuditOptions,
    PsAttributeMachineType,
    PsAttributeComponentFilter,
    PsAttributeEnableOptionalXStateFeatures,
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

#define PsAttributeValue(Number, Thread, Input, Unknown) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Unknown) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_OBJECT \
    PsAttributeValue(PsAttributeDebugObject, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER \
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION \
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY \
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHPE \
    PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS \
    PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_MACHINE_TYPE \
    PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_COMPONENT_FILTER \
    PsAttributeValue(PsAttributeComponentFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES \
    PsAttributeValue(PsAttributeEnableOptionalXStateFeatures, TRUE, TRUE, FALSE)

#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001
#define RTL_USER_PROC_PROFILE_USER          0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL        0x00000004
#define RTL_USER_PROC_PROFILE_SERVER        0x00000008
#define RTL_USER_PROC_RESERVE_1MB           0x00000020
#define RTL_USER_PROC_RESERVE_16MB          0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE        0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT  0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING     0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS         0x00020000

typedef struct _PROCESS_HANDLE_TRACING_ENABLE {
    ULONG Flags;
} PROCESS_HANDLE_TRACING_ENABLE, * PPROCESS_HANDLE_TRACING_ENABLE;

#define PROCESS_HANDLE_TRACING_MAX_SLOTS 0x20000

typedef struct _PROCESS_HANDLE_TRACING_ENABLE_EX {
    ULONG Flags;
    ULONG TotalSlots;
} PROCESS_HANDLE_TRACING_ENABLE_EX, * PPROCESS_HANDLE_TRACING_ENABLE_EX;

#define PROCESS_HANDLE_TRACING_MAX_STACKS 16

#define PROCESS_HANDLE_TRACE_TYPE_OPEN      1
#define PROCESS_HANDLE_TRACE_TYPE_CLOSE     2
#define PROCESS_HANDLE_TRACE_TYPE_BADREF    3

typedef struct _PROCESS_HANDLE_TRACING_ENTRY {
    HANDLE Handle;
    CLIENT_ID ClientId;
    ULONG Type;
    PVOID Stacks[PROCESS_HANDLE_TRACING_MAX_STACKS];
} PROCESS_HANDLE_TRACING_ENTRY, * PPROCESS_HANDLE_TRACING_ENTRY;

typedef struct _PROCESS_HANDLE_TRACING_QUERY {
    HANDLE Handle;
    ULONG TotalTraces;
    PROCESS_HANDLE_TRACING_ENTRY HandleTrace[1];
} PROCESS_HANDLE_TRACING_QUERY, * PPROCESS_HANDLE_TRACING_QUERY;

typedef struct _PROCESS_WS_WATCH_INFORMATION {
    PVOID FaultingPc;
    PVOID FaultingVa;
} PROCESS_WS_WATCH_INFORMATION, * PPROCESS_WS_WATCH_INFORMATION;

typedef struct _PROCESS_WS_WATCH_INFORMATION_EX {
    PROCESS_WS_WATCH_INFORMATION BasicInfo;
    ULONG_PTR FaultingThreadId;
    ULONG_PTR Flags;
} PROCESS_WS_WATCH_INFORMATION_EX, * PPROCESS_WS_WATCH_INFORMATION_EX;

/*
** Processes END
*/

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformationObsolete = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemThreadPriorityClientIdInformation = 82,
    SystemProcessorIdleCycleTimeInformation = 83,
    SystemVerifierCancellationInformation = 84,
    SystemProcessorPowerInformationEx = 85,
    SystemRefTraceInformation = 86,
    SystemSpecialPoolInformation = 87,
    SystemProcessIdInformation = 88,
    SystemErrorPortInformation = 89,
    SystemBootEnvironmentInformation = 90,
    SystemHypervisorInformation = 91,
    SystemVerifierInformationEx = 92,
    SystemTimeZoneInformation = 93,
    SystemImageFileExecutionOptionsInformation = 94,
    SystemCoverageInformation = 95,
    SystemPrefetchPatchInformation = 96,
    SystemVerifierFaultsInformation = 97,
    SystemSystemPartitionInformation = 98,
    SystemSystemDiskInformation = 99,
    SystemProcessorPerformanceDistribution = 100,
    SystemNumaProximityNodeInformation = 101,
    SystemDynamicTimeZoneInformation = 102,
    SystemCodeIntegrityInformation = 103,
    SystemProcessorMicrocodeUpdateInformation = 104,
    SystemProcessorBrandString = 105,
    SystemVirtualAddressInformation = 106,
    SystemLogicalProcessorAndGroupInformation = 107,
    SystemProcessorCycleTimeInformation = 108,
    SystemStoreInformation = 109,
    SystemRegistryAppendString = 110,
    SystemAitSamplingValue = 111,
    SystemVhdBootInformation = 112,
    SystemCpuQuotaInformation = 113,
    SystemNativeBasicInformation = 114,
    SystemErrorPortTimeouts = 115,
    SystemLowPriorityIoInformation = 116,
    SystemBootEntropyInformation = 117,
    SystemVerifierCountersInformation = 118,
    SystemPagedPoolInformationEx = 119,
    SystemSystemPtesInformationEx = 120,
    SystemNodeDistanceInformation = 121,
    SystemAcpiAuditInformation = 122,
    SystemBasicPerformanceInformation = 123,
    SystemQueryPerformanceCounterInformation = 124,
    SystemSessionBigPoolInformation = 125,
    SystemBootGraphicsInformation = 126,
    SystemScrubPhysicalMemoryInformation = 127,
    SystemBadPageInformation = 128,
    SystemProcessorProfileControlArea = 129,
    SystemCombinePhysicalMemoryInformation = 130,
    SystemEntropyInterruptTimingInformation = 131,
    SystemConsoleInformation = 132,
    SystemPlatformBinaryInformation = 133,
    SystemPolicyInformation = 134,
    SystemHypervisorProcessorCountInformation = 135,
    SystemDeviceDataInformation = 136,
    SystemDeviceDataEnumerationInformation = 137,
    SystemMemoryTopologyInformation = 138,
    SystemMemoryChannelInformation = 139,
    SystemBootLogoInformation = 140,
    SystemProcessorPerformanceInformationEx = 141,
    SystemSpare0 = 142,
    SystemSecureBootPolicyInformation = 143,
    SystemPageFileInformationEx = 144,
    SystemSecureBootInformation = 145,
    SystemEntropyInterruptTimingRawInformation = 146,
    SystemPortableWorkspaceEfiLauncherInformation = 147,
    SystemFullProcessInformation = 148,
    SystemKernelDebuggerInformationEx = 149,
    SystemBootMetadataInformation = 150,
    SystemSoftRebootInformation = 151,
    SystemElamCertificateInformation = 152,
    SystemOfflineDumpConfigInformation = 153,
    SystemProcessorFeaturesInformation = 154,
    SystemRegistryReconciliationInformation = 155,
    SystemEdidInformation = 156,
    SystemManufacturingInformation = 157,
    SystemEnergyEstimationConfigInformation = 158,
    SystemHypervisorDetailInformation = 159,
    SystemProcessorCycleStatsInformation = 160,
    SystemVmGenerationCountInformation = 161,
    SystemTrustedPlatformModuleInformation = 162,
    SystemKernelDebuggerFlags = 163,
    SystemCodeIntegrityPolicyInformation = 164,
    SystemIsolatedUserModeInformation = 165,
    SystemHardwareSecurityTestInterfaceResultsInformation = 166,
    SystemSingleModuleInformation = 167,
    SystemAllowedCpuSetsInformation = 168,
    SystemVsmProtectionInformation = 169, //ex SystemDmaProtectionInformation
    SystemInterruptCpuSetsInformation = 170,
    SystemSecureBootPolicyFullInformation = 171,
    SystemCodeIntegrityPolicyFullInformation = 172,
    SystemAffinitizedInterruptProcessorInformation = 173,
    SystemRootSiloInformation = 174,
    SystemCpuSetInformation = 175,
    SystemCpuSetTagInformation = 176,
    SystemWin32WerStartCallout = 177,
    SystemSecureKernelProfileInformation = 178,
    SystemCodeIntegrityPlatformManifestInformation = 179,
    SystemInterruptSteeringInformation = 180,
    SystemSupportedProcessorArchitectures = 181,
    SystemMemoryUsageInformation = 182,
    SystemCodeIntegrityCertificateInformation = 183,
    SystemPhysicalMemoryInformation = 184,
    SystemControlFlowTransition = 185,
    SystemKernelDebuggingAllowed = 186,
    SystemActivityModerationExeState = 187,
    SystemActivityModerationUserSettings = 188,
    SystemCodeIntegrityPoliciesFullInformation = 189,
    SystemCodeIntegrityUnlockInformation = 190,
    SystemIntegrityQuotaInformation = 191,
    SystemFlushInformation = 192,
    SystemProcessorIdleMaskInformation = 193,
    SystemSecureDumpEncryptionInformation = 194,
    SystemWriteConstraintInformation = 195,
    SystemKernelVaShadowInformation = 196,
    SystemHypervisorSharedPageInformation = 197,
    SystemFirmwareBootPerformanceInformation = 198,
    SystemCodeIntegrityVerificationInformation = 199,
    SystemFirmwarePartitionInformation = 200,
    SystemSpeculationControlInformation = 201,
    SystemDmaGuardPolicyInformation = 202,
    SystemEnclaveLaunchControlInformation = 203,
    SystemWorkloadAllowedCpuSetsInformation = 204,
    SystemCodeIntegrityUnlockModeInformation = 205,
    SystemLeapSecondInformation = 206,
    SystemFlags2Information = 207,
    SystemSecurityModelInformation = 208,
    SystemCodeIntegritySyntheticCacheInformation = 209,
    SystemFeatureConfigurationInformation = 210,
    SystemFeatureConfigurationSectionInformation = 211,
    SystemFeatureUsageSubscriptionInformation = 212,
    SystemSecureSpeculationControlInformation = 213,
    SystemSpacesBootInformation = 214,
    SystemFwRamdiskInformation = 215,
    SystemWheaIpmiHardwareInformation = 216,
    SystemDifSetRuleClassInformation = 217,
    SystemDifClearRuleClassInformation = 218,
    SystemDifApplyPluginVerificationOnDriver = 219,
    SystemDifRemovePluginVerificationOnDriver = 220,
    SystemShadowStackInformation = 221,
    SystemBuildVersionInformation = 222,
    SystemPoolLimitInformation = 223,
    SystemCodeIntegrityAddDynamicStore = 224,
    SystemCodeIntegrityClearDynamicStores = 225,
    SystemDifPoolTrackingInformation = 226,
    SystemPoolZeroingInformation = 227,
    SystemDpcWatchdogInformation = 228,
    SystemDpcWatchdogInformation2 = 229,
    SystemSupportedProcessorArchitectures2 = 230,
    SystemSingleProcessorRelationshipInformation = 231,
    SystemXfgCheckFailureInformation = 232,
    SystemIommuStateInformation = 233,
    SystemHypervisorMinrootInformation = 234,
    SystemHypervisorBootPagesInformation = 235,
    SystemPointerAuthInformation = 236,
    SystemSecureKernelDebuggerInformation = 237,
    SystemOriginalImageFeatureInformation = 238,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_VSM_PROTECTION_INFORMATION {
    CHAR DmaProtectionsAvailable;
    CHAR DmaProtectionsInUse;
    CHAR HardwareMbecAvailable;
    CHAR ApicVirtualizationAvailable;
} SYSTEM_VSM_PROTECTION_INFORMATION, * PSYSTEM_VSM_PROTECTION_INFORMATION;

//msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx
typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION {
    union {
        ULONG Flags;
        struct {
            ULONG BpbEnabled : 1;
            ULONG BpbDisabledSystemPolicy : 1;
            ULONG BpbDisabledNoHardwareSupport : 1;
            ULONG SpecCtrlEnumerated : 1;
            ULONG SpecCmdEnumerated : 1;
            ULONG IbrsPresent : 1;
            ULONG StibpPresent : 1;
            ULONG SmepPresent : 1;
            ULONG SpeculativeStoreBypassDisableAvailable : 1;
            ULONG SpeculativeStoreBypassDisableSupported : 1;
            ULONG SpeculativeStoreBypassDisabledSystemWide : 1;
            ULONG SpeculativeStoreBypassDisabledKernel : 1;
            ULONG SpeculativeStoreBypassDisableRequired : 1;
            ULONG BpbDisabledKernelToUser : 1;
            ULONG SpecCtrlRetpolineEnabled : 1;
            ULONG SpecCtrlImportOptimizationEnabled : 1;
            ULONG EnhancedIbrs : 1;
            ULONG HvL1tfStatusAvailable : 1;
            ULONG HvL1tfProcessorNotAffected : 1;
            ULONG HvL1tfMigitationEnabled : 1;
            ULONG HvL1tfMigitationNotEnabled_Hardware : 1;
            ULONG HvL1tfMigitationNotEnabled_LoadOption : 1;
            ULONG HvL1tfMigitationNotEnabled_CoreScheduler : 1;
            ULONG EnhancedIbrsReported : 1;
            ULONG MdsHardwareProtected : 1;
            ULONG MbClearEnabled : 1;
            ULONG MbClearReported : 1;
            ULONG TsxCtrlStatus : 2;
            ULONG TsxCtrlReported : 1;
            ULONG TaaHardwareImmune : 1;
            ULONG Reserved : 1;
        } SpeculationControlFlags;
    };
} SYSTEM_SPECULATION_CONTROL_INFORMATION, *PSYSTEM_SPECULATION_CONTROL_INFORMATION;

typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION_V2 {
    union {
        ULONG Flags;
        struct {
            ULONG BpbEnabled : 1;
            ULONG BpbDisabledSystemPolicy : 1;
            ULONG BpbDisabledNoHardwareSupport : 1;
            ULONG SpecCtrlEnumerated : 1;
            ULONG SpecCmdEnumerated : 1;
            ULONG IbrsPresent : 1;
            ULONG StibpPresent : 1;
            ULONG SmepPresent : 1;
            ULONG SpeculativeStoreBypassDisableAvailable : 1;
            ULONG SpeculativeStoreBypassDisableSupported : 1;
            ULONG SpeculativeStoreBypassDisabledSystemWide : 1;
            ULONG SpeculativeStoreBypassDisabledKernel : 1;
            ULONG SpeculativeStoreBypassDisableRequired : 1;
            ULONG BpbDisabledKernelToUser : 1;
            ULONG SpecCtrlRetpolineEnabled : 1;
            ULONG SpecCtrlImportOptimizationEnabled : 1;
            ULONG EnhancedIbrs : 1;
            ULONG HvL1tfStatusAvailable : 1;
            ULONG HvL1tfProcessorNotAffected : 1;
            ULONG HvL1tfMigitationEnabled : 1;
            ULONG HvL1tfMigitationNotEnabled_Hardware : 1;
            ULONG HvL1tfMigitationNotEnabled_LoadOption : 1;
            ULONG HvL1tfMigitationNotEnabled_CoreScheduler : 1;
            ULONG EnhancedIbrsReported : 1;
            ULONG MdsHardwareProtected : 1;
            ULONG MbClearEnabled : 1;
            ULONG MbClearReported : 1;
            ULONG TsxCtrlStatus : 2;
            ULONG TsxCtrlReported : 1;
            ULONG TaaHardwareImmune : 1;
            ULONG Reserved : 1;
        } SpeculationControlFlags;
    };
    union {
        ULONG Flags2;
        struct {
            ULONG SbdrSsdpHardwareProtected : 1;
            ULONG FbsdpHardwareProtected : 1;
            ULONG PsdpHardwareProtected : 1;
            ULONG FbClearEnabled : 1;
            ULONG FbClearReported : 1;
            ULONG Reserved : 27;
        } SpeculationControlFlags2;
    };
} SYSTEM_SPECULATION_CONTROL_INFORMATION_V2, * PSYSTEM_SPECULATION_CONTROL_INFORMATION_V2;

typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION {
    union {
        ULONG Flags;
        struct {
            ULONG KvaShadowEnabled : 1;
            ULONG KvaShadowUserGlobal : 1;
            ULONG KvaShadowPcid : 1;
            ULONG KvaShadowInvpcid : 1;
            ULONG KvaShadowRequired : 1;
            ULONG KvaShadowRequiredAvailable : 1;
            ULONG InvalidPteBit : 6;
            ULONG L1DataCacheFlushSupported : 1;
            ULONG L1TerminalFaultMitigationPresent : 1;
            ULONG Reserved : 18;
        } KvaShadowFlags;
    };
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, *PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG  Length;
    ULONG  CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

#define CODEINTEGRITY_OPTION_ENABLED                      0x01
#define CODEINTEGRITY_OPTION_TESTSIGN                     0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED                 0x04
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED       0x08
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED  0x10
#define CODEINTEGRITY_OPTION_TEST_BUILD                   0x20
#define CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD          0x40
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED            0x80
#define CODEINTEGRITY_OPTION_FLIGHT_BUILD                 0x100
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED            0x200
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED            0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED  0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED 0x1000
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED             0x2000
#define CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED     0x4000
#define CODEINTEGRITY_OPTION_WHQL_AUDITMODE_ENABLED       0x8000

typedef VOID(NTAPI *PIO_APC_ROUTINE)(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef struct _SYSTEM_VHD_BOOT_INFORMATION {
    BOOLEAN OsDiskIsVhd;
    ULONG OsVhdFilePathOffset;
    WCHAR OsVhdParentVolume[ANYSIZE_ARRAY];
} SYSTEM_VHD_BOOT_INFORMATION, *PSYSTEM_VHD_BOOT_INFORMATION;

typedef struct _SYSTEM_OBJECTTYPE_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfObjects;
    ULONG NumberOfHandles;
    ULONG TypeIndex;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG PoolType;
    BOOLEAN SecurityRequired;
    BOOLEAN WaitableObject;
    UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION {
    ULONG NextEntryOffset;
    PVOID Object;
    HANDLE CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Flags;
    LONG PointerCount;
    LONG HandleCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    HANDLE ExclusiveProcessId;
    PVOID SecurityDescriptor;
    UNICODE_STRING NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

/*
** Boot Entry START
*/

typedef struct _FILE_PATH {
    ULONG Version;
    ULONG Length;
    ULONG Type;
    UCHAR FilePath[ANYSIZE_ARRAY];
} FILE_PATH, *PFILE_PATH;

typedef struct _BOOT_ENTRY {
    ULONG Version;
    ULONG Length;
    ULONG Id;
    ULONG Attributes;
    ULONG FriendlyNameOffset;
    ULONG BootFilePathOffset;
    ULONG OsOptionsLength;
    UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _BOOT_ENTRY_LIST {
    ULONG NextEntryOffset;
    BOOT_ENTRY BootEntry;
} BOOT_ENTRY_LIST, *PBOOT_ENTRY_LIST;

/*
** Boot Entry END
*/

/*
** File start
*/

#define FILE_SUPERSEDE                          0x00000000
#define FILE_OPEN                               0x00000001
#define FILE_CREATE                             0x00000002
#define FILE_OPEN_IF                            0x00000003
#define FILE_OVERWRITE                          0x00000004
#define FILE_OVERWRITE_IF                       0x00000005
#define FILE_MAXIMUM_DISPOSITION                0x00000005

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000


#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileDispositionInformationEx,
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation,
    FileStatInformation,
    FileMemoryPartitionInformation,
    FileStatLxInformation,
    FileCaseSensitiveInformation,
    FileLinkInformationEx,
    FileLinkInformationExBypassAccessCheck,
    FileStorageReserveIdInformation,
    FileCaseSensitiveInformationForceAccessCheck,
    FileKnownFolderInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _FSINFOCLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsSectorSizeInformation,
    FileFsDataCopyInformation,
    FileFsMetadataSizeInformation,
    FileFsFullSizeInformationEx,
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    UCHAR DeletePending;
    UCHAR Directory;
} FILE_STANDARD_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION_EX {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
    BOOLEAN AlternateStream;
    BOOLEAN MetadataAttribute;
} FILE_STANDARD_INFORMATION_EX, *PFILE_STANDARD_INFORMATION_EX;

typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {
    ULONG FileAttributes;
    ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;

typedef struct _FILE_ALLOCATION_INFORMATION {
    LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;

typedef struct _FILE_COMPRESSION_INFORMATION {
    LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION {
    LARGE_INTEGER ValidDataLength;
} FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;

typedef struct _FILE_LINK_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

typedef struct _FILE_MOVE_CLUSTER_INFORMATION {
    ULONG ClusterCount;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_MOVE_CLUSTER_INFORMATION, *PFILE_MOVE_CLUSTER_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_STREAM_INFORMATION {
    ULONG NextEntryOffset;
    ULONG StreamNameLength;
    LARGE_INTEGER StreamSize;
    LARGE_INTEGER StreamAllocationSize;
    WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;

typedef struct _FILE_TRACKING_INFORMATION {
    HANDLE DestinationFile;
    ULONG ObjectInformationLength;
    CHAR ObjectInformation[1];
} FILE_TRACKING_INFORMATION, *PFILE_TRACKING_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID Key;
} FILE_COMPLETION_INFORMATION, *PFILE_COMPLETION_INFORMATION;

//
// Define the NamedPipeType flags for NtCreateNamedPipeFile
//

#define FILE_PIPE_BYTE_STREAM_TYPE      0x00000000
#define FILE_PIPE_MESSAGE_TYPE          0x00000001

//
// Define the CompletionMode flags for NtCreateNamedPipeFile
//

#define FILE_PIPE_QUEUE_OPERATION       0x00000000
#define FILE_PIPE_COMPLETE_OPERATION    0x00000001

//
// Define the ReadMode flags for NtCreateNamedPipeFile
//

#define FILE_PIPE_BYTE_STREAM_MODE      0x00000000
#define FILE_PIPE_MESSAGE_MODE          0x00000001

//
// Define the NamedPipeConfiguration flags for NtQueryInformation
//

#define FILE_PIPE_INBOUND               0x00000000
#define FILE_PIPE_OUTBOUND              0x00000001
#define FILE_PIPE_FULL_DUPLEX           0x00000002

//
// Define the NamedPipeState flags for NtQueryInformation
//

#define FILE_PIPE_DISCONNECTED_STATE    0x00000001
#define FILE_PIPE_LISTENING_STATE       0x00000002
#define FILE_PIPE_CONNECTED_STATE       0x00000003
#define FILE_PIPE_CLOSING_STATE         0x00000004

//
// Define the NamedPipeEnd flags for NtQueryInformation
//

#define FILE_PIPE_CLIENT_END            0x00000000
#define FILE_PIPE_SERVER_END            0x00000001


typedef struct _FILE_PIPE_INFORMATION {
    ULONG ReadMode;
    ULONG CompletionMode;
} FILE_PIPE_INFORMATION, *PFILE_PIPE_INFORMATION;

typedef struct _FILE_PIPE_LOCAL_INFORMATION {
    ULONG NamedPipeType;
    ULONG NamedPipeConfiguration;
    ULONG MaximumInstances;
    ULONG CurrentInstances;
    ULONG InboundQuota;
    ULONG ReadDataAvailable;
    ULONG OutboundQuota;
    ULONG WriteQuotaAvailable;
    ULONG NamedPipeState;
    ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;

typedef struct _FILE_PIPE_REMOTE_INFORMATION {
    LARGE_INTEGER CollectDataTime;
    ULONG MaximumCollectionCount;
} FILE_PIPE_REMOTE_INFORMATION, *PFILE_PIPE_REMOTE_INFORMATION;

typedef struct _FILE_MAILSLOT_QUERY_INFORMATION {
    ULONG MaximumMessageSize;
    ULONG MailslotQuota;
    ULONG NextMessageSize;
    ULONG MessagesAvailable;
    LARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_QUERY_INFORMATION, *PFILE_MAILSLOT_QUERY_INFORMATION;

typedef struct _FILE_MAILSLOT_SET_INFORMATION {
    PLARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_SET_INFORMATION, *PFILE_MAILSLOT_SET_INFORMATION;

typedef struct _FILE_REPARSE_POINT_INFORMATION {
    LONGLONG FileReference;
    ULONG Tag;
} FILE_REPARSE_POINT_INFORMATION, *PFILE_REPARSE_POINT_INFORMATION;

typedef struct _FILE_LINK_ENTRY_INFORMATION {
    ULONG NextEntryOffset;
    LONGLONG ParentFileId;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_ENTRY_INFORMATION, *PFILE_LINK_ENTRY_INFORMATION;

typedef struct _FILE_LINKS_INFORMATION {
    ULONG BytesNeeded;
    ULONG EntriesReturned;
    FILE_LINK_ENTRY_INFORMATION Entry;
} FILE_LINKS_INFORMATION, *PFILE_LINKS_INFORMATION;

typedef struct _FILE_NETWORK_PHYSICAL_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NETWORK_PHYSICAL_NAME_INFORMATION, *PFILE_NETWORK_PHYSICAL_NAME_INFORMATION;

typedef struct _FILE_STANDARD_LINK_INFORMATION {
    ULONG NumberOfAccessibleLinks;
    ULONG TotalNumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_LINK_INFORMATION, *PFILE_STANDARD_LINK_INFORMATION;

typedef struct _FILE_SFIO_RESERVE_INFORMATION {
    ULONG RequestsPerPeriod;
    ULONG Period;
    BOOLEAN RetryFailures;
    BOOLEAN Discardable;
    ULONG RequestSize;
    ULONG NumOutstandingRequests;
} FILE_SFIO_RESERVE_INFORMATION, *PFILE_SFIO_RESERVE_INFORMATION;

typedef struct _FILE_SFIO_VOLUME_INFORMATION {
    ULONG MaximumRequestsPerPeriod;
    ULONG MinimumPeriod;
    ULONG MinimumTransferSize;
} FILE_SFIO_VOLUME_INFORMATION, *PFILE_SFIO_VOLUME_INFORMATION;

//
// Define the flags for NtSet(Query)EaFile service structure entries
//

#define FILE_NEED_EA                    0x00000080

//
// Define EA type values
//

#define FILE_EA_TYPE_BINARY             0xfffe
#define FILE_EA_TYPE_ASCII              0xfffd
#define FILE_EA_TYPE_BITMAP             0xfffb
#define FILE_EA_TYPE_METAFILE           0xfffa
#define FILE_EA_TYPE_ICON               0xfff9
#define FILE_EA_TYPE_EA                 0xffee
#define FILE_EA_TYPE_MVMT               0xffdf
#define FILE_EA_TYPE_MVST               0xffde
#define FILE_EA_TYPE_ASN1               0xffdd
#define FILE_EA_TYPE_FAMILY_IDS         0xff01

typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

typedef struct _FILE_GET_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    SID Sid;
} FILE_GET_QUOTA_INFORMATION, *PFILE_GET_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER QuotaUsed;
    LARGE_INTEGER QuotaThreshold;
    LARGE_INTEGER QuotaLimit;
    SID Sid;
} FILE_QUOTA_INFORMATION, *PFILE_QUOTA_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_OBJECTID_INFORMATION {
    LONGLONG FileReference;
    UCHAR ObjectId[16];
    union {
        struct {
            UCHAR BirthVolumeId[16];
            UCHAR BirthObjectId[16];
            UCHAR DomainId[16];
        };
        UCHAR ExtendedInfo[48];
    };
} FILE_OBJECTID_INFORMATION, *PFILE_OBJECTID_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION {
    LARGE_INTEGER VolumeCreationTime;
    ULONG         VolumeSerialNumber;
    ULONG         VolumeLabelLength;
    BOOLEAN       SupportsObjects;
    WCHAR         VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _FILE_ID_GLOBAL_TX_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    LARGE_INTEGER FileId;
    GUID LockingTransactionId;
    ULONG TxInfoFlags;
    WCHAR FileName[1];
} FILE_ID_GLOBAL_TX_DIR_INFORMATION, *PFILE_ID_GLOBAL_TX_DIR_INFORMATION;

/*
** File END
*/

/*
** Section START
*/

typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation,
    SectionImageInformation,
    SectionRelocationInformation,
    SectionOriginalBaseInformation,
    SectionInternalImageInformation,
    MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef struct _SECTION_BASIC_INFO {
    PVOID BaseAddress;
    ULONG AllocationAttributes;
    LARGE_INTEGER MaximumSize;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    union
    {
        struct
        {
            USHORT MajorOperatingSystemVersion;
            USHORT MinorOperatingSystemVersion;
        };
        ULONG OperatingSystemVersion;
    };
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    union
    {
        UCHAR ImageFlags;
        struct
        {
            UCHAR ComPlusNativeReady : 1;
            UCHAR ComPlusILOnly : 1;
            UCHAR ImageDynamicallyRelocated : 1;
            UCHAR ImageMappedFlat : 1;
            UCHAR BaseBelow4gb : 1;
            UCHAR ComPlusPrefer32bit : 1;
            UCHAR Reserved : 2;
        };
    };
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _MI_EXTRA_IMAGE_INFORMATION {
    ULONG SizeOfHeaders;
    ULONG SizeOfImage;
} MI_EXTRA_IMAGE_INFORMATION, *PMI_EXTRA_IMAGE_INFORMATION;

typedef struct _MI_SECTION_IMAGE_INFORMATION {
    SECTION_IMAGE_INFORMATION ExportedImageInformation;
    MI_EXTRA_IMAGE_INFORMATION InternalImageInformation;
} MI_SECTION_IMAGE_INFORMATION, *PMI_SECTION_IMAGE_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION64 {
    ULONGLONG TransferAddress;
    ULONG ZeroBits;
    ULONGLONG MaximumStackSize;
    ULONGLONG CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    union
    {
        struct
        {
            USHORT MajorOperatingSystemVersion;
            USHORT MinorOperatingSystemVersion;
        };
        ULONG OperatingSystemVersion;
    };
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    union
    {
        UCHAR ImageFlags;
        struct
        {
            UCHAR ComPlusNativeReady : 1;
            UCHAR ComPlusILOnly : 1;
            UCHAR ImageDynamicallyRelocated : 1;
            UCHAR ImageMappedFlat : 1;
            UCHAR BaseBelow4gb : 1;
            UCHAR ComPlusPrefer32bit : 1;
            UCHAR Reserved : 2;
        };
    };
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION64, *PSECTION_IMAGE_INFORMATION64;

typedef struct _SECTION_INTERNAL_IMAGE_INFORMATION {
    SECTION_IMAGE_INFORMATION SectionInformation;
    union
    {
        ULONG ExtendedFlags;
        struct
        {
            ULONG ImageExportSuppressionEnabled : 1;
            ULONG ImageCetShadowStacksReady : 1; // 20H1
            ULONG ImageXfgEnabled : 1; // 20H2
            ULONG ImageCetShadowStacksStrictMode : 1;
            ULONG ImageCetSetContextIpValidationRelaxedMode : 1;
            ULONG ImageCetDynamicApisAllowInProc : 1;
            ULONG ImageCetDowngradeReserved1 : 1;
            ULONG ImageCetDowngradeReserved2 : 1;
            ULONG Reserved : 24;
        };
    };
} SECTION_INTERNAL_IMAGE_INFORMATION, * PSECTION_INTERNAL_IMAGE_INFORMATION;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

#ifndef SEC_BASED
#define SEC_BASED          0x200000
#endif

#ifndef SEC_NO_IMAGE
#define SEC_NO_CHANGE      0x400000
#endif

#ifndef SEC_FILE
#define SEC_FILE           0x800000     
#endif

#ifndef SEC_IMAGE
#define SEC_IMAGE         0x1000000     
#endif

#ifndef SEC_RESERVE
#define SEC_RESERVE       0x4000000     
#endif

#ifndef SEC_COMMIT
#define SEC_COMMIT        0x8000000     
#endif

#ifndef SEC_NOCACHE
#define SEC_NOCACHE      0x10000000     
#endif

#ifndef SEC_GLOBAL
#define SEC_GLOBAL       0x20000000
#endif

#ifndef SEC_LARGE_PAGES
#define SEC_LARGE_PAGES  0x80000000    
#endif

/*
** Section END
*/

/*
** System Table START
*/
#define NUMBER_SERVICE_TABLES 2
#define NTOS_SERVICE_INDEX   0
#define WIN32K_SERVICE_INDEX 1
#define SERVICE_NUMBER_MASK ((1 << 12) -  1)

#if defined(_WIN64)

#if defined(_AMD64_)

#define SERVICE_TABLE_SHIFT (12 - 4)
#define SERVICE_TABLE_MASK (((1 << 1) - 1) << 4)
#define SERVICE_TABLE_TEST (WIN32K_SERVICE_INDEX << 4)

#else

#define SERVICE_TABLE_SHIFT (12 - 5)
#define SERVICE_TABLE_MASK (((1 << 1) - 1) << 5)
#define SERVICE_TABLE_TEST (WIN32K_SERVICE_INDEX << 5)

#endif

#else

#define SERVICE_TABLE_SHIFT (12 - 4)
#define SERVICE_TABLE_MASK (((1 << 1) - 1) << 4)
#define SERVICE_TABLE_TEST (WIN32K_SERVICE_INDEX << 4)

#endif

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    ULONG_PTR Base; //e.g. KiServiceTable
    PULONG Count;
    ULONG Limit;//e.g. KiServiceLimit
    PUCHAR Number; //e.g. KiArgumentTable
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
/*
** System Table END
*/

/*
** System Boot Environment START
*/

// Size=20
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1 {
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1;

// Size=32
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
    union
    {
        ULONGLONG BootFlags;
        struct
        {
            ULONGLONG DbgMenuOsSelection : 1; // RS4
            ULONGLONG DbgHiberBoot : 1;
            ULONGLONG DbgSoftBoot : 1;
            ULONGLONG DbgMeasuredLaunch : 1;
            ULONGLONG DbgMeasuredLaunchCapable : 1; // 19H1
            ULONGLONG DbgSystemHiveReplace : 1;
            ULONGLONG DbgMeasuredLaunchSmmProtections : 1;
            ULONGLONG DbgMeasuredLaunchSmmLevel : 7; // 20H1
        };
    };
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

/*
** System Boot Environment END
*/

/*
** Key START
*/

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyTrustInformation,
    KeyLayerInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_SET_INFORMATION_CLASS {
    KeyWriteTimeInformation,
    KeyWow64FlagsInformation,
    KeyControlFlagsInformation,
    KeySetVirtualizationInformation,
    KeySetDebugInformation,
    KeySetHandleTagsInformation,
    KeySetLayerInformation,
    MaxKeySetInfoClass
} KEY_SET_INFORMATION_CLASS;

typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   ClassOffset;
    ULONG   ClassLength;
    ULONG   SubKeys;
    ULONG   MaxNameLen;
    ULONG   MaxClassLen;
    ULONG   Values;
    ULONG   MaxValueNameLen;
    ULONG   MaxValueDataLen;
    WCHAR   Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataOffset;
    ULONG   DataLength;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
    //          Data[1];            // Variable size data not declared
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 {
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

typedef struct _KEY_VALUE_ENTRY {
    PUNICODE_STRING ValueName;
    ULONG           DataLength;
    ULONG           DataOffset;
    ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

/*
** Key END
*/


/*
** TIME_FIELDS START
*/

typedef struct _TIME_FIELDS {
    CSHORT Year;        // range [1601...]
    CSHORT Month;       // range [1..12]
    CSHORT Day;         // range [1..31]
    CSHORT Hour;        // range [0..23]
    CSHORT Minute;      // range [0..59]
    CSHORT Second;      // range [0..59]
    CSHORT Milliseconds;// range [0..999]
    CSHORT Weekday;     // range [0..6] == [Sunday..Saturday]
} TIME_FIELDS;
typedef TIME_FIELDS *PTIME_FIELDS;

/*
** TIME_FIELDS END
*/

/*
** HANDLE START
*/

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

/*
** HANDLE END
*/

// Privileges

#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE (36L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE

//
// Generic test for success on any status value (non-negative numbers
// indicate success).
//

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

//
// Generic test for information on any status value.
//

#define NT_INFORMATION(Status) ((ULONG)(Status) >> 30 == 1)

//
// Generic test for warning on any status value.
//

#define NT_WARNING(Status) ((ULONG)(Status) >> 30 == 2)

//
// Generic test for error on any status value.
//

#define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)


/*
** OBJECT MANAGER START
*/

//
// Header flags
//

#define OB_FLAG_NEW_OBJECT              0x01
#define OB_FLAG_KERNEL_OBJECT           0x02
#define OB_FLAG_CREATOR_INFO            0x04
#define OB_FLAG_EXCLUSIVE_OBJECT        0x08
#define OB_FLAG_PERMANENT_OBJECT        0x10
#define OB_FLAG_DEFAULT_SECURITY_QUOTA  0x20
#define OB_FLAG_SINGLE_HANDLE_ENTRY     0x40
#define OB_FLAG_DELETED_INLINE          0x80

//
// InfoMask values
//

#define OB_INFOMASK_PROCESS_INFO    0x10
#define OB_INFOMASK_QUOTA           0x08
#define OB_INFOMASK_HANDLE          0x04
#define OB_INFOMASK_NAME            0x02
#define OB_INFOMASK_CREATOR_INFO    0x01

#define OBJ_INVALID_SESSION_ID 0xFFFFFFFF
#define NUMBER_HASH_BUCKETS 37

typedef struct _OBJECT_DIRECTORY_ENTRY {
    PVOID ChainLink;
    PVOID Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _EX_PUSH_LOCK {
    union {
        struct {
            ULONG_PTR Locked : 1;
            ULONG_PTR Waiting : 1;
            ULONG_PTR Waking : 1;
            ULONG_PTR MultipleShared : 1;
            ULONG_PTR Shared : sizeof(ULONG_PTR) * 8 - 4;
        };
        ULONG_PTR Value;
        PVOID Ptr;
    };
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef struct _EX_PUSH_LOCK_AUTO_EXPAND_STATE {
    union {
        struct {
            ULONG Expanded : 1;
            ULONG Transitioning : 1;
            ULONG Pageable : 1;
        };
        ULONG Value;
    };
} EX_PUSH_LOCK_AUTO_EXPAND_STATE, *PEX_PUSH_LOCK_AUTO_EXPAND_STATE; /* size: 0x0004 */

typedef struct _EX_PUSH_LOCK_AUTO_EXPAND {
    EX_PUSH_LOCK LocalLock;
    EX_PUSH_LOCK_AUTO_EXPAND_STATE State;
    ULONG Stats;
} EX_PUSH_LOCK_AUTO_EXPAND, *PEX_PUSH_LOCK_AUTO_EXPAND; /* size: 0x0010 */

typedef struct _OBJECT_NAMESPACE_LOOKUPTABLE {
    LIST_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
    EX_PUSH_LOCK Lock;
    ULONG NumberOfPrivateSpaces;
} OBJECT_NAMESPACE_LOOKUPTABLE, *POBJECT_NAMESPACE_LOOKUPTABLE;

typedef struct _OBJECT_NAMESPACE_ENTRY {
    LIST_ENTRY ListEntry;
    PVOID NamespaceRootDirectory;
    ULONG SizeOfBoundaryInformation;
    ULONG Reserved;
    UCHAR HashValue;
    ULONG_PTR Alignment;
} OBJECT_NAMESPACE_ENTRY, *POBJECT_NAMESPACE_ENTRY;

typedef enum _BOUNDARY_ENTRY_TYPE {
    OBNS_Invalid = 0,
    OBNS_Name = 1,
    OBNS_SID = 2,
    OBNS_IntegrityLabel = 3
} BOUNDARY_ENTRY_TYPE;

typedef struct _OBJECT_BOUNDARY_ENTRY {
    BOUNDARY_ENTRY_TYPE EntryType;
    ULONG EntrySize;
} OBJECT_BOUNDARY_ENTRY, *POBJECT_BOUNDARY_ENTRY;

typedef struct _OBJECT_BOUNDARY_DESCRIPTOR {
    ULONG Version;
    ULONG Items;
    ULONG TotalSize;
    ULONG Reserved;
} OBJECT_BOUNDARY_DESCRIPTOR, *POBJECT_BOUNDARY_DESCRIPTOR;

typedef struct _OBJECT_DIRECTORY {
    POBJECT_DIRECTORY_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
    EX_PUSH_LOCK Lock;
    PDEVICE_MAP DeviceMap;
    ULONG SessionId;
    PVOID NamespaceEntry;
    ULONG Flags;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _OBJECT_DIRECTORY_V2 {
    POBJECT_DIRECTORY_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
    EX_PUSH_LOCK Lock;
    PDEVICE_MAP DeviceMap;
    POBJECT_DIRECTORY ShadowDirectory;
    ULONG SessionId;
    PVOID NamespaceEntry;
    ULONG Flags;
    LONG Padding[1];
} OBJECT_DIRECTORY_V2, *POBJECT_DIRECTORY_V2;

typedef struct _OBJECT_DIRECTORY_V3 {
    POBJECT_DIRECTORY_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
    EX_PUSH_LOCK Lock;
    PDEVICE_MAP DeviceMap;
    POBJECT_DIRECTORY ShadowDirectory;
    PVOID NamespaceEntry;
    PVOID SessionObject;
    ULONG Flags;
    ULONG SessionId;
} OBJECT_DIRECTORY_V3, *POBJECT_DIRECTORY_V3;

typedef struct _OBJECT_HEADER_NAME_INFO {
    POBJECT_DIRECTORY Directory;
    UNICODE_STRING Name;
    ULONG QueryReferences;
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;

typedef struct _OBJECT_HEADER_CREATOR_INFO {// Size=32
    LIST_ENTRY TypeList; // Size=16 Offset=0
    PVOID CreatorUniqueProcess; // Size=8 Offset=16
    USHORT CreatorBackTraceIndex; // Size=2 Offset=24
    USHORT Reserved; // Size=2 Offset=26
} OBJECT_HEADER_CREATOR_INFO, *POBJECT_HEADER_CREATOR_INFO;

typedef struct _OBJECT_HANDLE_COUNT_ENTRY {// Size=16
    PVOID Process; // Size=8 Offset=0
    struct
    {
        unsigned long HandleCount : 24; // Size=4 Offset=8 BitOffset=0 BitCount=24
        unsigned long LockCount : 8; // Size=4 Offset=8 BitOffset=24 BitCount=8
    };
} OBJECT_HANDLE_COUNT_ENTRY, *POBJECT_HANDLE_COUNT_ENTRY;

typedef struct _OBJECT_HEADER_HANDLE_INFO { // Size=16
    union {
        PVOID HandleCountDataBase; // Size=8 Offset=0
        struct _OBJECT_HANDLE_COUNT_ENTRY SingleEntry; // Size=16 Offset=0
    };
} OBJECT_HEADER_HANDLE_INFO, *POBJECT_HEADER_HANDLE_INFO;

typedef struct _OBJECT_HEADER_PROCESS_INFO { // Size=16
    PVOID ExclusiveProcess; // Size=8 Offset=0
    PVOID Reserved; // Size=8 Offset=8
} OBJECT_HEADER_PROCESS_INFO, *POBJECT_HEADER_PROCESS_INFO;

typedef struct _OBJECT_HEADER_QUOTA_INFO {
    ULONG PagedPoolCharge; //4
    ULONG NonPagedPoolCharge; //4 
    ULONG SecurityDescriptorCharge; //4
    PVOID SecurityDescriptorQuotaBlock; //sizeof(pointer)
    unsigned __int64 Reserved; //sizeof(uint64)
} OBJECT_HEADER_QUOTA_INFO, *POBJECT_HEADER_QUOTA_INFO;

typedef struct _OBJECT_HEADER_PADDING_INFO {
    ULONG PaddingAmount;
} OBJECT_HEADER_PADDING_INFO, *POBJECT_HEADER_PADDING_INFO;

typedef struct _OBJECT_HEADER_AUDIT_INFO {
    PVOID SecurityDescriptor;
    PVOID Reserved;
} OBJECT_HEADER_AUDIT_INFO, *POBJECT_HEADER_AUDIT_INFO;

typedef struct _OBJECT_HEADER_EXTENDED_INFO {
    struct _OBJECT_FOOTER *Footer;
    PVOID Reserved;
} OBJECT_HEADER_EXTENDED_INFO, POBJECT_HEADER_EXTENDED_INFO;

typedef struct _OB_HANDLE_REVOCATION_BLOCK
{
    LIST_ENTRY RevocationInfos;
    struct _EX_PUSH_LOCK Lock;
    struct _EX_RUNDOWN_REF Rundown;
} OB_HANDLE_REVOCATION_BLOCK, *POB_HANDLE_REVOCATION_BLOCK;

typedef struct _OBJECT_HEADER_HANDLE_REVOCATION_INFO {
    LIST_ENTRY ListEntry;
    OB_HANDLE_REVOCATION_BLOCK* RevocationBlock;
    unsigned char Padding1[4];
    unsigned char Padding2[4];
} OBJECT_HEADER_HANDLE_REVOCATION_INFO, *POBJECT_HEADER_HANDLE_REVOCATION_INFO;

typedef struct _QUAD {
    union {
        INT64 UseThisFieldToCopy;
        float DoNotUseThisField;
    };
} QUAD, *PQUAD;

typedef struct _OBJECT_CREATE_INFORMATION {
    ULONG Attributes;
    PVOID RootDirectory;
    CHAR ProbeMode;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG SecurityDescriptorCharge;
    PVOID SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQos;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;

typedef struct _SECURITY_CLIENT_CONTEXT {
    struct _SECURITY_QUALITY_OF_SERVICE SecurityQos;
    void* ClientToken;
    UCHAR DirectlyAccessClientToken;
    UCHAR DirectAccessEffectiveOnly;
    UCHAR ServerIsRemote;
    struct _TOKEN_CONTROL ClientTokenControl;
    LONG __PADDING__[1];
} SECURITY_CLIENT_CONTEXT, *PSECURITY_CLIENT_CONTEXT;

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32
} POOL_TYPE;

//
// WARNING this structure is incomplete, refer to complete definitions below if you need actual full variant.
//
typedef struct _OBJECT_TYPE_INITIALIZER_COMPATIBLE {// Size=120
    USHORT Length; // Size=2 Offset=0
    UCHAR ObjectTypeFlags; // Size=1 Offset=2
    ULONG ObjectTypeCode; // Size=4 Offset=4
    ULONG InvalidAttributes; // Size=4 Offset=8
    GENERIC_MAPPING GenericMapping; // Size=16 Offset=12
    ULONG ValidAccessMask; // Size=4 Offset=28
    ULONG RetainAccess; // Size=4 Offset=32
    POOL_TYPE PoolType; // Size=4 Offset=36
    ULONG DefaultPagedPoolCharge; // Size=4 Offset=40
    ULONG DefaultNonPagedPoolCharge; // Size=4 Offset=44
    PVOID DumpProcedure; // Size=8 Offset=48
    PVOID OpenProcedure; // Size=8 Offset=56
    PVOID CloseProcedure; // Size=8 Offset=64
    PVOID DeleteProcedure; // Size=8 Offset=72
    PVOID ParseProcedure; // Size=8 Offset=80
    PVOID SecurityProcedure; // Size=8 Offset=88
    PVOID QueryNameProcedure; // Size=8 Offset=96
    PVOID OkayToCloseProcedure; // Size=8 Offset=104
} OBJECT_TYPE_INITIALIZER_COMPATIBLE, *POBJECT_TYPE_INITIALIZER_COMPATIBLE;

//
// WARNING this structure is incomplete, refer to complete definitions below if you need actual full variant.
//
typedef struct _OBJECT_TYPE_COMPATIBLE {
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER_COMPATIBLE TypeInfo;
} OBJECT_TYPE_COMPATIBLE, *POBJECT_TYPE_COMPATIBLE;
typedef POBJECT_TYPE_COMPATIBLE POBJECT_TYPE;

//
// Complete definitions of OBJECT_TYPE + OBJECT_TYPE_INITIALIZER per Windows version.
//

typedef struct _OBJECT_TYPE_INITIALIZER_7 {
    USHORT Length;
    union
    {
        UCHAR ObjectTypeFlags;
        struct
        {
            UCHAR CaseInsensitive : 1;
            UCHAR UnnamedObjectsOnly : 1;
            UCHAR UseDefaultObject : 1;
            UCHAR SecurityRequired : 1;
            UCHAR MaintainHandleCount : 1;
            UCHAR MaintainTypeList : 1;
            UCHAR SupportsObjectCallbacks : 1;
        };
    };
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    PVOID ParseProcedure;
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER_7, *POBJECT_TYPE_INITIALIZER_7;

//
// Windows 8, new object type flag, WaitObject* members added
//
typedef struct _OBJECT_TYPE_INITIALIZER_8 {
    USHORT Length;
    union
    {
        UCHAR ObjectTypeFlags;
        struct
        {
            UCHAR CaseInsensitive : 1;
            UCHAR UnnamedObjectsOnly : 1;
            UCHAR UseDefaultObject : 1;
            UCHAR SecurityRequired : 1;
            UCHAR MaintainHandleCount : 1;
            UCHAR MaintainTypeList : 1;
            UCHAR SupportsObjectCallbacks : 1;
            UCHAR CacheAligned : 1;
        };
    };
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    PVOID ParseProcedure;
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
    ULONG WaitObjectFlagMask;
    USHORT WaitObjectFlagOffset;
    USHORT WaitObjectPointerOffset;
} OBJECT_TYPE_INITIALIZER_8, *POBJECT_TYPE_INITIALIZER_8;

//
// Windows 10 RS1, new ObjectTypeFlags2 flag added, 
// ParseProcedure now has two variants with different parameters.
//
typedef struct _OBJECT_TYPE_INITIALIZER_RS1 {
    USHORT Length;
    union
    {
        UCHAR ObjectTypeFlags;
        struct
        {
            UCHAR CaseInsensitive : 1;
            UCHAR UnnamedObjectsOnly : 1;
            UCHAR UseDefaultObject : 1;
            UCHAR SecurityRequired : 1;
            UCHAR MaintainHandleCount : 1;
            UCHAR MaintainTypeList : 1;
            UCHAR SupportsObjectCallbacks : 1;
            UCHAR CacheAligned : 1;
        };
    };
    union
    {
        UCHAR ObjectTypeFlags2; //for ParseProcedureEx
        struct
        {
            UCHAR UseExtendedParameters : 1;
            UCHAR Reserved : 7;
        };
    };
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    union {
        PVOID ParseProcedure;
        PVOID ParseProcedureEx;
    };
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
    ULONG WaitObjectFlagMask;
    USHORT WaitObjectFlagOffset;
    USHORT WaitObjectPointerOffset;
} OBJECT_TYPE_INITIALIZER_RS1, *POBJECT_TYPE_INITIALIZER_RS1;

//
// ObjectTypeFlags2 moved to extended to USHORT ObjectTypeFlags field.
// It was that hard to do this since beginning?
//
typedef struct _OBJECT_TYPE_INITIALIZER_RS2 {
    USHORT Length;
    union
    {
        USHORT ObjectTypeFlags;
        struct
        {
            UCHAR CaseInsensitive : 1;
            UCHAR UnnamedObjectsOnly : 1;
            UCHAR UseDefaultObject : 1;
            UCHAR SecurityRequired : 1;
            UCHAR MaintainHandleCount : 1;
            UCHAR MaintainTypeList : 1;
            UCHAR SupportsObjectCallbacks : 1;
            UCHAR CacheAligned : 1;
        };
        struct
        {
            UCHAR UseExtendedParameters : 1;//for ParseProcedureEx
            UCHAR Reserved : 7;
        };
    };
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    union {
        PVOID ParseProcedure;
        PVOID ParseProcedureEx;
    };
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
    ULONG WaitObjectFlagMask;
    USHORT WaitObjectFlagOffset;
    USHORT WaitObjectPointerOffset;
} OBJECT_TYPE_INITIALIZER_RS2, *POBJECT_TYPE_INITIALIZER_RS2;

//
// OBJECT_TYPE definition vary only because of OBJECT_TYPE_INITIALIZER changes.
//
typedef struct _OBJECT_TYPE_7 {
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER_7 TypeInfo;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE_7, POBJECT_TYPE_7;

typedef struct _OBJECT_TYPE_8 {
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER_8 TypeInfo;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE_8, POBJECT_TYPE_8;

typedef struct _OBJECT_TYPE_RS1 {
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER_RS1 TypeInfo;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE_RS1, POBJECT_TYPE_RS1;

typedef struct _OBJECT_TYPE_RS2 {
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER_RS2 TypeInfo;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE_RS2, POBJECT_TYPE_RS2;

/*
** brand new header starting from 6.1
*/

typedef struct _OBJECT_HEADER {
    LONG_PTR PointerCount;
    union
    {
        LONG_PTR HandleCount;
        PVOID NextToFree;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;
    UCHAR TraceFlags;
    UCHAR InfoMask;
    UCHAR Flags;
    union
    {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };
    PVOID SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

//
// Actual object header from windows 10-11.
//
typedef struct _OBJECT_HEADER_X {
    LONG_PTR PointerCount;
    union
    {
        LONG_PTR HandleCount;
        PVOID NextToFree;
    };

    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;

    union
    {
        UCHAR TraceFlags;
        struct
        {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
        };
    };

    UCHAR InfoMask;

    union
    {
        UCHAR Flags;
        struct
        {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };

    ULONG Reserved;

    union
    {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };

    PVOID SecurityDescriptor;
    QUAD Body;

} OBJECT_HEADER_X, * POBJECT_HEADER_X;

#define OBJECT_TO_OBJECT_HEADER(obj) \
    CONTAINING_RECORD( (obj), OBJECT_HEADER, Body )

#define DOSDEVICE_DRIVE_UNKNOWN     0
#define DOSDEVICE_DRIVE_CALCULATE   1 //e.g. symlink
#define DOSDEVICE_DRIVE_REMOVABLE   2
#define DOSDEVICE_DRIVE_FIXED       3
#define DOSDEVICE_DRIVE_REMOTE      4
#define DOSDEVICE_DRIVE_CDROM       5
#define DOSDEVICE_DRIVE_RAMDISK     6

typedef struct _DEVICE_MAP_V1 {
    OBJECT_DIRECTORY* DosDevicesDirectory;
    OBJECT_DIRECTORY* GlobalDosDevicesDirectory;
    PVOID DosDevicesDirectoryHandle;
    ULONG ReferenceCount;
    ULONG DriveMap;
    UCHAR DriveType[32];
} DEVICE_MAP_V1, * PDEVICE_MAP_V1;

typedef struct _DEVICE_MAP_V1 DEVICE_MAP_COMPATIBLE;
typedef struct _DEVICE_MAP_V1* PDEVICE_MAP_COMPATIBLE;

//Since REDSTONE1 (14393)
typedef struct _DEVICE_MAP_V2 {
    OBJECT_DIRECTORY* DosDevicesDirectory;
    OBJECT_DIRECTORY* GlobalDosDevicesDirectory;
    PVOID DosDevicesDirectoryHandle;
    volatile LONG ReferenceCount;
    ULONG DriveMap;
    UCHAR DriveType[32];
    PEJOB ServerSilo;
} DEVICE_MAP_V2, * PDEVICE_MAP_V2;

//Since W11 (22000)
typedef struct _DEVICE_MAP_V3 {
    OBJECT_DIRECTORY* DosDevicesDirectory;
    OBJECT_DIRECTORY* GlobalDosDevicesDirectory;
    PEJOB ServerSilo;
    struct _DEVICE_MAP* GlobalDeviceMap;
    EX_FAST_REF DriveObject[26];
    LONGLONG ReferenceCount;
    PVOID DosDevicesDirectoryHandle;
    ULONG DriveMap;
    UCHAR DriveType[32];
} DEVICE_MAP_V3, PDEVICE_MAP_V3;

/*
** OBJECT MANAGER END
*/

/*
* WDM START
*/
#define TIMER_TOLERABLE_DELAY_BITS      6
#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5

typedef struct _DISPATCHER_HEADER {
    union {
        union {
            volatile LONG Lock;
            LONG LockNV;
        } DUMMYUNIONNAME;

        struct {                            // Events, Semaphores, Gates, etc.
            UCHAR Type;                     // All (accessible via KOBJECT_TYPE)
            UCHAR Signalling;
            UCHAR Size;
            UCHAR Reserved1;
        } DUMMYSTRUCTNAME;

        struct {                            // Timer
            UCHAR TimerType;
            union {
                UCHAR TimerControlFlags;
                struct {
                    UCHAR Absolute : 1;
                    UCHAR Wake : 1;
                    UCHAR EncodedTolerableDelay : TIMER_TOLERABLE_DELAY_BITS;
                } DUMMYSTRUCTNAME;
            };

            UCHAR Hand;
            union {
                UCHAR TimerMiscFlags;
                struct {

#if !defined(KENCODED_TIMER_PROCESSOR)

                    UCHAR Index : TIMER_EXPIRED_INDEX_BITS;

#else

                    UCHAR Index : 1;
                    UCHAR Processor : TIMER_PROCESSOR_INDEX_BITS;

#endif

                    UCHAR Inserted : 1;
                    volatile UCHAR Expired : 1;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;
        } DUMMYSTRUCTNAME2;

        struct {                            // Timer2
            UCHAR Timer2Type;
            union {
                UCHAR Timer2Flags;
                struct {
                    UCHAR Timer2Inserted : 1;
                    UCHAR Timer2Expiring : 1;
                    UCHAR Timer2CancelPending : 1;
                    UCHAR Timer2SetPending : 1;
                    UCHAR Timer2Running : 1;
                    UCHAR Timer2Disabled : 1;
                    UCHAR Timer2ReservedFlags : 2;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;

            UCHAR Timer2Reserved1;
            UCHAR Timer2Reserved2;
        } DUMMYSTRUCTNAME3;

        struct {                            // Queue
            UCHAR QueueType;
            union {
                UCHAR QueueControlFlags;
                struct {
                    UCHAR Abandoned : 1;
                    UCHAR DisableIncrement : 1;
                    UCHAR QueueReservedControlFlags : 6;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;

            UCHAR QueueSize;
            UCHAR QueueReserved;
        } DUMMYSTRUCTNAME4;

        struct {                            // Thread
            UCHAR ThreadType;
            UCHAR ThreadReserved;
            union {
                UCHAR ThreadControlFlags;
                struct {
                    UCHAR CycleProfiling : 1;
                    UCHAR CounterProfiling : 1;
                    UCHAR GroupScheduling : 1;
                    UCHAR AffinitySet : 1;
                    UCHAR ThreadReservedControlFlags : 4;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;

            union {
                UCHAR DebugActive;

#if !defined(_X86_)

                struct {
                    BOOLEAN ActiveDR7 : 1;
                    BOOLEAN Instrumented : 1;
                    BOOLEAN Minimal : 1;
                    BOOLEAN Reserved4 : 3;
                    BOOLEAN UmsScheduled : 1;
                    BOOLEAN UmsPrimary : 1;
                } DUMMYSTRUCTNAME;

#endif

            } DUMMYUNIONNAME2;
        } DUMMYSTRUCTNAME5;

        struct {                         // Mutant
            UCHAR MutantType;
            UCHAR MutantSize;
            BOOLEAN DpcActive;
            UCHAR MutantReserved;
        } DUMMYSTRUCTNAME6;
    } DUMMYUNIONNAME;

    LONG SignalState;                   // Object lock
    LIST_ENTRY WaitListHead;            // Object lock
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef struct _KEVENT {
    DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT, *PRKEVENT;

typedef struct _FAST_MUTEX {
    LONG_PTR Count;
    void *Owner;
    ULONG Contention;
    struct _KEVENT Event;
    ULONG OldIrql;
    LONG __PADDING__[1];
} FAST_MUTEX, *PFAST_MUTEX;

typedef struct _KMUTANT {
    DISPATCHER_HEADER Header;
    LIST_ENTRY MutantListEntry;
    struct _KTHREAD *OwnerThread;
    BOOLEAN Abandoned;
    UCHAR ApcDisable;
} KMUTANT, *PKMUTANT, *PRKMUTANT, KMUTEX, *PKMUTEX, *PRKMUTEX;

typedef struct _KSEMAPHORE {
    DISPATCHER_HEADER Header;
    LONG Limit;
} KSEMAPHORE, *PKSEMAPHORE, *PRKSEMAPHORE;

typedef struct _KTIMER {
    DISPATCHER_HEADER Header;
    ULARGE_INTEGER DueTime;
    LIST_ENTRY TimerListEntry;
    struct _KDPC *Dpc;
    ULONG Processor;
    LONG Period;
} KTIMER, *PKTIMER, *PRKTIMER;

typedef struct _KDEVICE_QUEUE_ENTRY {
    LIST_ENTRY DeviceListEntry;
    ULONG SortKey;
    BOOLEAN Inserted;
} KDEVICE_QUEUE_ENTRY, *PKDEVICE_QUEUE_ENTRY, *PRKDEVICE_QUEUE_ENTRY;

typedef enum _KDPC_IMPORTANCE {
    LowImportance,
    MediumImportance,
    HighImportance
} KDPC_IMPORTANCE;

typedef struct _KDPC {
    union {
        ULONG TargetInfoAsUlong;
        struct {
            UCHAR Type;
            UCHAR Importance;
            volatile USHORT Number;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    SINGLE_LIST_ENTRY DpcListEntry;
    KAFFINITY ProcessorHistory;
    PVOID DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    __volatile PVOID DpcData;
} KDPC, *PKDPC, *PRKDPC;

typedef struct _WAIT_CONTEXT_BLOCK {
    union {
        KDEVICE_QUEUE_ENTRY WaitQueueEntry;
        struct {
            LIST_ENTRY DmaWaitEntry;
            ULONG NumberOfChannels;
            ULONG SyncCallback : 1;
            ULONG DmaContext : 1;
            ULONG Reserved : 30;
        };
    };
    PVOID DeviceRoutine;
    PVOID DeviceContext;
    ULONG NumberOfMapRegisters;
    PVOID DeviceObject;
    PVOID CurrentIrp;
    PKDPC BufferChainingDpc;
} WAIT_CONTEXT_BLOCK, *PWAIT_CONTEXT_BLOCK;

#define MAXIMUM_VOLUME_LABEL_LENGTH  (32 * sizeof(WCHAR)) // 32 characters

typedef struct _VPB {
    CSHORT Type;
    CSHORT Size;
    USHORT Flags;
    USHORT VolumeLabelLength; // in bytes
    struct _DEVICE_OBJECT *DeviceObject;
    struct _DEVICE_OBJECT *RealDevice;
    ULONG SerialNumber;
    ULONG ReferenceCount;
    WCHAR VolumeLabel[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
} VPB, *PVPB;

typedef struct _KQUEUE {
    DISPATCHER_HEADER Header;
    LIST_ENTRY EntryListHead;
    ULONG CurrentCount;
    ULONG MaximumCount;
    LIST_ENTRY ThreadListHead;
} KQUEUE, *PKQUEUE;

typedef struct _KDEVICE_QUEUE {
    CSHORT Type;
    CSHORT Size;
    LIST_ENTRY DeviceListHead;
    KSPIN_LOCK Lock;

#if defined(_AMD64_)

    union {
        BOOLEAN Busy;
        struct {
            LONG64 Reserved : 8;
            LONG64 Hint : 56;
        };
    };

#else

    BOOLEAN Busy;

#endif

} KDEVICE_QUEUE, *PKDEVICE_QUEUE, *PRKDEVICE_QUEUE;

enum _KOBJECTS {
    EventNotificationObject = 0x0,
    EventSynchronizationObject = 0x1,
    MutantObject = 0x2,
    ProcessObject = 0x3,
    QueueObject = 0x4,
    SemaphoreObject = 0x5,
    ThreadObject = 0x6,
    GateObject = 0x7,
    TimerNotificationObject = 0x8,
    TimerSynchronizationObject = 0x9,
    Spare2Object = 0xa,
    Spare3Object = 0xb,
    Spare4Object = 0xc,
    Spare5Object = 0xd,
    Spare6Object = 0xe,
    Spare7Object = 0xf,
    Spare8Object = 0x10,
    Spare9Object = 0x11,
    ApcObject = 0x12,
    DpcObject = 0x13,
    DeviceQueueObject = 0x14,
    EventPairObject = 0x15,
    InterruptObject = 0x16,
    ProfileObject = 0x17,
    ThreadedDpcObject = 0x18,
    MaximumKernelObject = 0x19,
};

#define DO_VERIFY_VOLUME                0x00000002      // ntddk nthal ntifs wdm
#define DO_BUFFERED_IO                  0x00000004      // ntddk nthal ntifs wdm
#define DO_EXCLUSIVE                    0x00000008      // ntddk nthal ntifs wdm
#define DO_DIRECT_IO                    0x00000010      // ntddk nthal ntifs wdm
#define DO_MAP_IO_BUFFER                0x00000020      // ntddk nthal ntifs wdm
#define DO_DEVICE_HAS_NAME              0x00000040      // ntddk nthal ntifs
#define DO_DEVICE_INITIALIZING          0x00000080      // ntddk nthal ntifs wdm
#define DO_SYSTEM_BOOT_PARTITION        0x00000100      // ntddk nthal ntifs
#define DO_LONG_TERM_REQUESTS           0x00000200      // ntddk nthal ntifs
#define DO_NEVER_LAST_DEVICE            0x00000400      // ntddk nthal ntifs
#define DO_SHUTDOWN_REGISTERED          0x00000800      // ntddk nthal ntifs wdm
#define DO_BUS_ENUMERATED_DEVICE        0x00001000      // ntddk nthal ntifs wdm
#define DO_POWER_PAGABLE                0x00002000      // ntddk nthal ntifs wdm
#define DO_POWER_INRUSH                 0x00004000      // ntddk nthal ntifs wdm
#define DO_POWER_NOOP                   0x00008000
#define DO_LOW_PRIORITY_FILESYSTEM      0x00010000      // ntddk nthal ntifs
#define DO_XIP                          0x00020000
#define DO_DEVICE_TO_BE_RESET           0x04000000      
#define DO_DAX_VOLUME                   0x10000000    

#define FILE_REMOVABLE_MEDIA                        0x00000001
#define FILE_READ_ONLY_DEVICE                       0x00000002
#define FILE_FLOPPY_DISKETTE                        0x00000004
#define FILE_WRITE_ONCE_MEDIA                       0x00000008
#define FILE_REMOTE_DEVICE                          0x00000010
#define FILE_DEVICE_IS_MOUNTED                      0x00000020
#define FILE_VIRTUAL_VOLUME                         0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME              0x00000080
#define FILE_DEVICE_SECURE_OPEN                     0x00000100
#define FILE_CHARACTERISTIC_PNP_DEVICE              0x00000800
#define FILE_CHARACTERISTIC_TS_DEVICE               0x00001000
#define FILE_CHARACTERISTIC_WEBDAV_DEVICE           0x00002000
#define FILE_CHARACTERISTIC_CSV                     0x00010000
#define FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL    0x00020000
#define FILE_PORTABLE_DEVICE                        0x00040000

#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026
#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_FIPS                0x0000003A
#define FILE_DEVICE_INFINIBAND          0x0000003B
#define FILE_DEVICE_VMBUS               0x0000003E
#define FILE_DEVICE_CRYPT_PROVIDER      0x0000003F
#define FILE_DEVICE_WPD                 0x00000040
#define FILE_DEVICE_BLUETOOTH           0x00000041
#define FILE_DEVICE_MT_COMPOSITE        0x00000042
#define FILE_DEVICE_MT_TRANSPORT        0x00000043
#define FILE_DEVICE_BIOMETRIC           0x00000044
#define FILE_DEVICE_PMI                 0x00000045
#define FILE_DEVICE_EHSTOR              0x00000046
#define FILE_DEVICE_DEVAPI              0x00000047
#define FILE_DEVICE_GPIO                0x00000048
#define FILE_DEVICE_USBEX               0x00000049
#define FILE_DEVICE_CONSOLE             0x00000050
#define FILE_DEVICE_NFP                 0x00000051
#define FILE_DEVICE_SYSENV              0x00000052
#define FILE_DEVICE_VIRTUAL_BLOCK       0x00000053
#define FILE_DEVICE_POINT_OF_SERVICE    0x00000054
#define FILE_DEVICE_STORAGE_REPLICATION 0x00000055
#define FILE_DEVICE_TRUST_ENV           0x00000056
#define FILE_DEVICE_UCM                 0x00000057
#define FILE_DEVICE_UCMTCPCI            0x00000058
#define FILE_DEVICE_PERSISTENT_MEMORY   0x00000059
#define FILE_DEVICE_NVDIMM              0x0000005a
#define FILE_DEVICE_HOLOGRAPHIC         0x0000005b
#define FILE_DEVICE_SDFXHCI             0x0000005c
#define FILE_DEVICE_UCMUCSI             0x0000005d

#define FILE_BYTE_ALIGNMENT             0x00000000
#define FILE_WORD_ALIGNMENT             0x00000001
#define FILE_LONG_ALIGNMENT             0x00000003
#define FILE_QUAD_ALIGNMENT             0x00000007
#define FILE_OCTA_ALIGNMENT             0x0000000f
#define FILE_32_BYTE_ALIGNMENT          0x0000001f
#define FILE_64_BYTE_ALIGNMENT          0x0000003f
#define FILE_128_BYTE_ALIGNMENT         0x0000007f
#define FILE_256_BYTE_ALIGNMENT         0x000000ff
#define FILE_512_BYTE_ALIGNMENT         0x000001ff

#define DPC_NORMAL 0
#define DPC_THREADED 1

#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4324) // structure was padded due to __declspec(align())
#endif

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT {
    CSHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    struct _DRIVER_OBJECT* DriverObject;
    struct _DEVICE_OBJECT* NextDevice;
    struct _DEVICE_OBJECT* AttachedDevice;
    struct _IRP* CurrentIrp;
    PIO_TIMER Timer;
    ULONG Flags;                                // See above:  DO_...
    ULONG Characteristics;                      // See ntioapi:  FILE_...
    __volatile PVPB Vpb;
    PVOID DeviceExtension;
    DEVICE_TYPE DeviceType;
    CCHAR StackSize;
    union {
        LIST_ENTRY ListEntry;
        WAIT_CONTEXT_BLOCK Wcb;
    } Queue;
    ULONG AlignmentRequirement;
    KDEVICE_QUEUE DeviceQueue;
    KDPC Dpc;

    //
    //  The following field is for exclusive use by the filesystem to keep
    //  track of the number of Fsp threads currently using the device
    //

    ULONG ActiveThreadCount;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    KEVENT DeviceLock;

    USHORT SectorSize;
    USHORT Spare1;

    struct _DEVOBJ_EXTENSION* DeviceObjectExtension;
    PVOID  Reserved;

} DEVICE_OBJECT;

typedef struct _DEVICE_OBJECT* PDEVICE_OBJECT;

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

typedef struct _DEVOBJ_EXTENSION {

    CSHORT          Type;
    USHORT          Size;

    //
    // Public part of the DeviceObjectExtension structure
    //

    PDEVICE_OBJECT  DeviceObject;               // owning device object

    // end_ntddk end_nthal end_ntifs end_wdm end_ntosp

    //
    // Universal Power Data - all device objects must have this
    //

    ULONG           PowerFlags;             // see ntos\po\pop.h
    // WARNING: Access via PO macros
    // and with PO locking rules ONLY.

    //
    // Pointer to the non-universal power data
    //  Power data that only some device objects need is stored in the
    //  device object power extension -> DOPE
    //  see po.h
    //

    struct          _DEVICE_OBJECT_POWER_EXTENSION  *Dope;

    //
    // power state information
    //

    //
    // Device object extension flags.  Protected by the IopDatabaseLock.
    //

    ULONG ExtensionFlags;

    //
    // PnP manager fields
    //

    PVOID           DeviceNode;

    //
    // AttachedTo is a pointer to the device object that this device
    // object is attached to.  The attachment chain is now doubly
    // linked: this pointer and DeviceObject->AttachedDevice provide the
    // linkage.
    //

    PDEVICE_OBJECT  AttachedTo;

    //
    // The next two fields are used to prevent recursion in IoStartNextPacket
    // interfaces.
    //

    LONG           StartIoCount;       // Used to keep track of number of pending start ios.
    LONG           StartIoKey;         // Next startio key
    ULONG          StartIoFlags;       // Start Io Flags. Need a separate flag so that it can be accessed without locks
    PVPB           Vpb;                // If not NULL contains the VPB of the mounted volume.
    // Set in the filesystem's volume device object.
    // This is a reverse VPB pointer.

    // begin_ntddk begin_wdm begin_nthal begin_ntifs begin_ntosp

} DEVOBJ_EXTENSION, *PDEVOBJ_EXTENSION;

typedef struct _FAST_IO_DISPATCH {
    ULONG SizeOfFastIoDispatch;
    PVOID FastIoCheckIfPossible;
    PVOID FastIoRead;
    PVOID FastIoWrite;
    PVOID FastIoQueryBasicInfo;
    PVOID FastIoQueryStandardInfo;
    PVOID FastIoLock;
    PVOID FastIoUnlockSingle;
    PVOID FastIoUnlockAll;
    PVOID FastIoUnlockAllByKey;
    PVOID FastIoDeviceControl;
    PVOID AcquireFileForNtCreateSection;
    PVOID ReleaseFileForNtCreateSection;
    PVOID FastIoDetachDevice;
    PVOID FastIoQueryNetworkOpenInfo;
    PVOID AcquireForModWrite;
    PVOID MdlRead;
    PVOID MdlReadComplete;
    PVOID PrepareMdlWrite;
    PVOID MdlWriteComplete;
    PVOID FastIoReadCompressed;
    PVOID FastIoWriteCompressed;
    PVOID MdlReadCompleteCompressed;
    PVOID MdlWriteCompleteCompressed;
    PVOID FastIoQueryOpen;
    PVOID ReleaseForModWrite;
    PVOID AcquireForCcFlush;
    PVOID ReleaseForCcFlush;
} FAST_IO_DISPATCH, *PFAST_IO_DISPATCH;

#define IO_TYPE_ADAPTER                 0x00000001
#define IO_TYPE_CONTROLLER              0x00000002
#define IO_TYPE_DEVICE                  0x00000003
#define IO_TYPE_DRIVER                  0x00000004
#define IO_TYPE_FILE                    0x00000005
#define IO_TYPE_IRP                     0x00000006
#define IO_TYPE_MASTER_ADAPTER          0x00000007
#define IO_TYPE_OPEN_PACKET             0x00000008
#define IO_TYPE_TIMER                   0x00000009
#define IO_TYPE_VPB                     0x0000000a
#define IO_TYPE_ERROR_LOG               0x0000000b
#define IO_TYPE_ERROR_MESSAGE           0x0000000c
#define IO_TYPE_DEVICE_OBJECT_EXTENSION 0x0000000d

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_PNP_POWER                IRP_MJ_PNP      
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

// Public structure
typedef struct _DRIVER_EXTENSION {

    //
    // Back pointer to Driver Object
    //

    struct _DRIVER_OBJECT *DriverObject;

    //
    // The AddDevice entry point is called by the Plug & Play manager
    // to inform the driver when a new device instance arrives that this
    // driver must control.
    //

    PVOID AddDevice;

    //
    // The count field is used to count the number of times the driver has
    // had its registered reinitialization routine invoked.
    //

    ULONG Count;

    //
    // The service name field is used by the pnp manager to determine
    // where the driver related info is stored in the registry.
    //

    UNICODE_STRING ServiceKeyName;

} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

// Private, since 7.1
typedef struct _DRIVER_EXTENSION_V2 {
    struct _DRIVER_OBJECT* DriverObject;
    PVOID AddDevice;
    ULONG Count;
    UNICODE_STRING ServiceKeyName;
    struct _IO_CLIENT_EXTENSION* ClientDriverExtension;
    struct _FS_FILTER_CALLBACKS* FsFilterCallbacks;
} DRIVER_EXTENSION_V2, * PDRIVER_EXTENSION_V2;

// Private, since 8.0
typedef struct _DRIVER_EXTENSION_V3 {
    struct _DRIVER_OBJECT* DriverObject;
    PVOID AddDevice;
    ULONG Count;
    UNICODE_STRING ServiceKeyName;
    struct _IO_CLIENT_EXTENSION* ClientDriverExtension;
    struct _FS_FILTER_CALLBACKS* FsFilterCallbacks;
    PVOID KseCallbacks; //KernelShimEngine
    PVOID DvCallbacks; //DriverVerifier
} DRIVER_EXTENSION_V3, * PDRIVER_EXTENSION_V3;

// Private, since 8.1
typedef struct _DRIVER_EXTENSION_V4 {
    struct _DRIVER_OBJECT* DriverObject;
    PVOID AddDevice;
    ULONG Count;
    UNICODE_STRING ServiceKeyName;
    struct _IO_CLIENT_EXTENSION* ClientDriverExtension;
    struct _FS_FILTER_CALLBACKS* FsFilterCallbacks;
    PVOID KseCallbacks; //KernelShimEngine
    PVOID DvCallbacks; //DriverVerifier
    PVOID VerifierContext;
} DRIVER_EXTENSION_V4, * PDRIVER_EXTENSION_V4;

#define DRVO_UNLOAD_INVOKED             0x00000001
#define DRVO_LEGACY_DRIVER              0x00000002
#define DRVO_BUILTIN_DRIVER             0x00000004    // Driver objects for Hal, PnP Mgr
#define DRVO_REINIT_REGISTERED          0x00000008
#define DRVO_INITIALIZED                0x00000010
#define DRVO_BOOTREINIT_REGISTERED      0x00000020
#define DRVO_LEGACY_RESOURCES           0x00000040
// end_ntddk end_nthal end_ntifs end_ntosp
#define DRVO_BASE_FILESYSTEM_DRIVER     0x00000080   // A driver that is at the bottom of the filesystem stack.
// begin_ntddk begin_nthal begin_ntifs begin_ntosp

typedef struct _DRIVER_OBJECT {
    CSHORT Type;
    CSHORT Size;

    //
    // The following links all of the devices created by a single driver
    // together on a list, and the Flags word provides an extensible flag
    // location for driver objects.
    //

    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;

    //
    // The following section describes where the driver is loaded.  The count
    // field is used to count the number of times the driver has had its
    // registered reinitialization routine invoked.
    //

    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection; //PLDR_DATA_TABLE_ENTRY
    PDRIVER_EXTENSION DriverExtension;

    //
    // The driver name field is used by the error log thread
    // determine the name of the driver that an I/O request is/was bound.
    //

    UNICODE_STRING DriverName;

    //
    // The following section is for registry support.  Thise is a pointer
    // to the path to the hardware information in the registry
    //

    PUNICODE_STRING HardwareDatabase;

    //
    // The following section contains the optional pointer to an array of
    // alternate entry points to a driver for "fast I/O" support.  Fast I/O
    // is performed by invoking the driver routine directly with separate
    // parameters, rather than using the standard IRP call mechanism.  Note
    // that these functions may only be used for synchronous I/O, and when
    // the file is cached.
    //

    PFAST_IO_DISPATCH FastIoDispatch;

    //
    // The following section describes the entry points to this particular
    // driver.  Note that the major function dispatch table must be the last
    // field in the object so that it remains extensible.
    //

    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PVOID MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];

} DRIVER_OBJECT;
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT;

//
// The following structure is pointed to by the SectionObject pointer field
// of a file object, and is allocated by the various NT file systems.
//

typedef struct _SECTION_OBJECT_POINTERS {
    PVOID DataSectionObject;
    PVOID SharedCacheMap;
    PVOID ImageSectionObject;
} SECTION_OBJECT_POINTERS;
typedef SECTION_OBJECT_POINTERS* PSECTION_OBJECT_POINTERS;

//
// Define the format of a completion message.
//

typedef struct _IO_COMPLETION_CONTEXT {
    PVOID Port;
    PVOID Key;
} IO_COMPLETION_CONTEXT, * PIO_COMPLETION_CONTEXT;

typedef struct _FILE_OBJECT {
    CSHORT Type;
    CSHORT Size;
    PDEVICE_OBJECT DeviceObject;
    PVPB Vpb;
    PVOID FsContext;
    PVOID FsContext2;
    PSECTION_OBJECT_POINTERS SectionObjectPointer;
    PVOID PrivateCacheMap;
    NTSTATUS FinalStatus;
    struct _FILE_OBJECT* RelatedFileObject;
    BOOLEAN LockOperation;
    BOOLEAN DeletePending;
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
    UNICODE_STRING FileName;
    LARGE_INTEGER CurrentByteOffset;
    __volatile ULONG Waiters;
    __volatile ULONG Busy;
    PVOID LastLock;
    KEVENT Lock;
    KEVENT Event;
    __volatile PIO_COMPLETION_CONTEXT CompletionContext;
    KSPIN_LOCK IrpListLock;
    LIST_ENTRY IrpList;
    __volatile PVOID FileObjectExtension;
} FILE_OBJECT;
typedef struct _FILE_OBJECT* PFILE_OBJECT;

typedef ULONG_PTR ERESOURCE_THREAD;
typedef ERESOURCE_THREAD* PERESOURCE_THREAD;

typedef struct _OWNER_ENTRY {
    ERESOURCE_THREAD OwnerThread;
    union {
        LONG OwnerCount;
        ULONG TableSize;
    };

} OWNER_ENTRY, *POWNER_ENTRY;

typedef struct _ERESOURCE {
    LIST_ENTRY SystemResourcesList;
    POWNER_ENTRY OwnerTable;
    SHORT ActiveCount;
    USHORT Flag;
    PKSEMAPHORE SharedWaiters;
    PKEVENT ExclusiveWaiters;
    OWNER_ENTRY OwnerThreads[2];
    ULONG ContentionCount;
    USHORT NumberOfSharedWaiters;
    USHORT NumberOfExclusiveWaiters;
    union {
        PVOID Address;
        ULONG_PTR CreatorBackTraceIndex;
    };

    KSPIN_LOCK SpinLock;
} ERESOURCE, *PERESOURCE;

/*
* WDM END
*/

/*
* MM START
*/
typedef ULONG MMSECTION_FLAGS2;

typedef struct _MMEXTEND_INFO {
    ULONG_PTR CommittedSize;
    ULONG ReferenceCount;
} MMEXTEND_INFO, * PMMEXTEND_INFO; /* size: 0x0010 */

//
// Flags definitions valid only for Windows 10.
//
typedef struct _MMSECTION_FLAGS {
    struct {
        UINT BeingDeleted : 1; /* bit position: 0 */
        UINT BeingCreated : 1; /* bit position: 1 */
        UINT BeingPurged : 1; /* bit position: 2 */
        UINT NoModifiedWriting : 1; /* bit position: 3 */
        UINT FailAllIo : 1; /* bit position: 4 */
        UINT Image : 1; /* bit position: 5 */
        UINT Based : 1; /* bit position: 6 */
        UINT File : 1; /* bit position: 7 */
        UINT AttemptingDelete : 1; /* bit position: 8 */
        UINT PrefetchCreated : 1; /* bit position: 9 */
        UINT PhysicalMemory : 1; /* bit position: 10 */
        UINT ImageControlAreaOnRemovableMedia : 1; /* bit position: 11 */  //CopyOnWrite
        UINT Reserve : 1; /* bit position: 12 */
        UINT Commit : 1; /* bit position: 13 */
        UINT NoChange : 1; /* bit position: 14 */
        UINT WasPurged : 1; /* bit position: 15 */
        UINT UserReference : 1; /* bit position: 16 */
        UINT GlobalMemory : 1; /* bit position: 17 */
        UINT DeleteOnClose : 1; /* bit position: 18 */
        UINT FilePointerNull : 1; /* bit position: 19 */
        UINT PreferredNode : 6; /* bit position: 20 */
        UINT GlobalOnlyPerSession : 1; /* bit position: 26 */
        UINT UserWritable : 1; /* bit position: 27 */
        UINT SystemVaAllocated : 1; /* bit position: 28 */
        UINT PreferredFsCompressionBoundary : 1; /* bit position: 29 */
        UINT UsingFileExtents : 1; /* bit position: 30 */
        UINT PageSize64K : 1; /* bit position: 31 */
    };
} MMSECTION_FLAGS, * PMMSECTION_FLAGS; /* size: 0x0004 */

//
// Flags definitions valid only for Windows 10.
//
typedef struct _SEGMENT_FLAGS {
    union {
        struct {
            USHORT TotalNumberOfPtes4132 : 10; /* bit position: 0 */
            USHORT Spare0 : 2; /* bit position: 10 */
            USHORT LargePages : 1; /* bit position: 12 */
            USHORT DebugSymbolsLoaded : 1; /* bit position: 13 */
            USHORT WriteCombined : 1; /* bit position: 14 */
            USHORT NoCache : 1; /* bit position: 15 */
        }; 
        USHORT Short0;
    }; /* size: 0x0002 */
    union {
        struct {
            UCHAR FloppyMedia : 1; /* bit position: 0 */
            UCHAR DefaultProtectionMask : 5; /* bit position: 1 */
            UCHAR Binary32 : 1; /* bit position: 6 */
            UCHAR ContainsDebug : 1; /* bit position: 7 */
        };
        UCHAR UChar1;
    }; /* size: 0x0001 */
    union {
        struct {
            UCHAR ForceCollision : 1; /* bit position: 0 */
            UCHAR ImageSigningType : 3; /* bit position: 1 */
            UCHAR ImageSigningLevel : 4; /* bit position: 4 */
        };
        UCHAR UChar2;
    };
} SEGMENT_FLAGS, * PSEGMENT_FLAGS; /* size: 0x0004 */

typedef struct _MI_SYSTEM_CACHE_VIEW_ATTRIBUTES {
    union {
        ULONGLONG NumberOfPtes : 6;
        ULONGLONG PartitionId : 10;
        ULONGLONG Spare : 2;
        ULONGLONG SectionOffset : 48;
    } u1;
} MI_SYSTEM_CACHE_VIEW_ATTRIBUTES, * PMI_SYSTEM_CACHE_VIEW_ATTRIBUTES;

#define VIEW_MAP_TYPE_PROCESS         1
#define VIEW_MAP_TYPE_SESSION         2
#define VIEW_MAP_TYPE_SYSTEM_CACHE    3

typedef struct _MI_REVERSE_VIEW_MAP {
    struct _LIST_ENTRY ViewLinks;
    union {
        VOID* SystemCacheVa;
        VOID* SessionViewVa;
        struct _EPROCESS* VadsProcess;
        ULONG Type : 2;
    } u1;
    union {
        struct _SUBSECTION* Subsection;
        ULONG SubsectionType : 1;
    } u2;
    union {
        struct _MI_SYSTEM_CACHE_VIEW_ATTRIBUTES SystemCacheAttributes;
        ULONGLONG AllAttributes; //Since W11
        ULONGLONG SectionOffset;
    } u3;
} MI_REVERSE_VIEW_MAP, * PMI_REVERSE_VIEW_MAP; /* size: 0x0028 */

typedef struct _RTL_BALANCED_NODE {
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _SEGMENT {

    struct _CONTROL_AREA* ControlArea;
    unsigned long TotalNumberOfPtes;
    SEGMENT_FLAGS SegmentFlags;
    ULONG_PTR NumberOfCommittedPages;
    ULONG_PTR SizeOfSegment;

    union {
        struct _MMEXTEND_INFO* ExtendInfo;
        void* BasedAddress;
    } u1;

    EX_PUSH_LOCK SegmentLock;

    union {
        union {
            ULONG_PTR ImageCommitment;
            ULONG CreatingProcessId;
        };
    } u2;

    union {
        union {
            struct _MI_SECTION_IMAGE_INFORMATION* ImageInformation;
            void* FirstMappedVa;
        };
    } u3;

    struct _MMPTE* PrototypePte;

} SEGMENT, * PSEGMENT;  /* size: 0x0048 */

typedef struct _CONTROL_AREA_COMPAT {

    SEGMENT* Segment;
    LIST_ENTRY ListHead;
    ULONG_PTR NumberOfSectionReferences;
    ULONG_PTR NumberOfPfnReferences;
    ULONG_PTR NumberOfMappedViews;
    ULONG_PTR NumberOfUserReferences;

    union {
        union {
            ULONG LongFlags;
            MMSECTION_FLAGS Flags;
        };
    } u;

    union {
        union {
            ULONG LongFlags;
            MMSECTION_FLAGS2 Flags;
        };
    } u1;

    EX_FAST_REF FilePointer;
    volatile LONG ControlAreaLock;
    ULONG ModifiedWriteCount;
    struct _MI_CONTROL_AREA_WAIT_BLOCK* WaitList;

    union
    {
        struct
        {
            union
            {
                ULONG NumberOfSystemCacheViews;
                ULONG ImageRelocationStartBit;
            };
            union
            {
                volatile LONG WritableUserReferences;
                struct // version dependent, this bitset is not valid for w11
                {
                    unsigned long ImageRelocationSizeIn64k : 16; /* bit position: 0 */
                    unsigned long LargePage : 1; /* bit position: 16 */
                    unsigned long SystemImage : 1; /* bit position: 17 */
                    unsigned long StrongCode : 2; /* bit position: 18 */
                    unsigned long CantMove : 1; /* bit position: 20 */
                    unsigned long BitMap : 2; /* bit position: 21 */
                    unsigned long ImageActive : 1; /* bit position: 23 */
                };
            };
            union
            {
                ULONG FlushInProgressCount;
                ULONG NumberOfSubsections;
                struct _MI_IMAGE_SECURITY_REFERENCE* SeImageStub;
            };
        } e2;
    } u2;

    //
    // Incomplete definition, tail is version dependent.
    //

} CONTROL_AREA_COMPAT, * PCONTROL_AREA_COMPAT;

//
// N.B. 
// Only valid for Win10.
// Change between Win10 versions.
//
typedef struct _MMVAD_SHORT {
    union
    {
        struct
        {
            struct _MMVAD_SHORT* NextVad;
            void* ExtraCreateInfo;
        };
        struct _RTL_BALANCED_NODE VadNode;
    };

    ULONG StartingVpn;
    ULONG EndingVpn;
    UCHAR StartingVpnHigh;
    UCHAR EndingVpnHigh;
    UCHAR CommitChargeHigh;
    UCHAR SpareNT64VadUChar;
    LONG ReferenceCount;
    EX_PUSH_LOCK PushLock;

    ULONG LongFlags;
    ULONG LongFlags1;

    struct _MI_VAD_EVENT_BLOCK* EventList;

} MMVAD_SHORT, * PMMVAD_SHORT;  /* size: 0x0040 */

typedef struct _MI_VAD_SEQUENTIAL_INFO {

    struct {
#if defined(_AMD64_)
        ULONG_PTR Length : 12; /* bit position: 0 */
        ULONG_PTR Vpn : 52; /* bit position: 12 */
#else
        ULONG Length : 11; /* bit position: 0 */
        ULONG Vpn : 21; /* bit position: 11 */
#endif
    };

} MI_VAD_SEQUENTIAL_INFO, * PMI_VAD_SEQUENTIAL_INFO;

//
// N.B. 
// Only valid for Win10.
// Flags meanings change between Win10 versions.
//
typedef struct _MMVAD_FLAGS {
    struct
    {
        ULONG VadType : 3; /* bit position: 0 */
        ULONG Protection : 5; /* bit position: 3 */
        ULONG PreferredNode : 6; /* bit position: 8 */
        ULONG PrivateMemory : 1; /* bit position: 14 */
        ULONG PrivateFixup : 1; /* bit position: 15 */
        ULONG Enclave : 1; /* bit position: 16 */
        ULONG PageSize64K : 1; /* bit position: 17 */
        ULONG RfgControlStack : 1; /* bit position: 18 */
        ULONG Spare : 8; /* bit position: 19 */
        ULONG NoChange : 1; /* bit position: 27 */
        ULONG ManySubsections : 1; /* bit position: 28 */
        ULONG DeleteInProgress : 1; /* bit position: 29 */
        ULONG LockContended : 1; /* bit position: 30 */
        ULONG Lock : 1; /* bit position: 31 */
    };
} MMVAD_FLAGS, * PMMVAD_FLAGS; /* size: 0x0004 */

//
// N.B. 
// Only valid for Win10.
// Flags meanings change between Win10 versions.
//
typedef struct _MMVAD_FLAGS1 {
    struct
    {
        ULONG CommitCharge : 31; /* bit position: 0 */
        ULONG MemCommit : 1; /* bit position: 31 */
    };
} MMVAD_FLAGS1, * PMMVAD_FLAGS1; /* size: 0x0004 */

//
// N.B. 
// Only valid for Win10.
// Flags meanings change between Win10 versions.
//
typedef struct _MMVAD_FLAGS2 {
    struct
    {
        ULONG FileOffset : 24; /* bit position: 0 */
        ULONG Large : 1; /* bit position: 24 */
        ULONG TrimBehind : 1; /* bit position: 25 */
        ULONG Inherit : 1; /* bit position: 26 */
        ULONG NoValidationNeeded : 1; /* bit position: 27 */
        ULONG PrivateDemandZero : 1; /* bit position: 28 */
        ULONG Spare : 3; /* bit position: 29 */
    };
} MMVAD_FLAGS2, * PMMVAD_FLAGS2; /* size: 0x0004 */

typedef struct _MMVAD {

    struct _MMVAD_SHORT Core;

    union
    {
        union
        {
            ULONG LongFlags2;
            volatile struct _MMVAD_FLAGS2 VadFlags2;
        };
    } u2;

    struct _SUBSECTION* Subsection;
    struct _MMPTE* FirstPrototypePte;
    struct _MMPTE* LastContiguousPte;
    LIST_ENTRY ViewLinks;
    struct _EPROCESS* VadsProcess;

    union
    {
        union
        {
            struct _MI_VAD_SEQUENTIAL_INFO SequentialVa;
            struct _MMEXTEND_INFO* ExtendedInfo;
        };
    } u4;

    FILE_OBJECT* FileObject;

} MMVAD, * PMMVAD; /* size: 0x0088 */

typedef struct _MMVIEW {
    ULONGLONG Entry;
    union {
        ULONGLONG Writable : 1;
        struct _CONTROL_AREA* ControlArea; 
    };
    LIST_ENTRY ViewLinks; 
    PVOID SessionViewVa;
    ULONG SessionId;
} MMVIEW, *PMMVIEW;

typedef struct _MI_IMAGE_ENTRY_IN_SESSION {
    LIST_ENTRY Link;
    PVOID Address;

    //
    // Incomplete and incorrect.
    //

} MI_IMAGE_ENTRY_IN_SESSION, * PMI_IMAGE_ENTRY_IN_SESSION;

typedef struct _SUBSECTION_COMPAT {

    struct _CONTROL_AREA* ControlArea;
    struct _MMPTE* SubsectionBase;
    struct _SUBSECTION* NextSubsection;

    //
    // Incomplete definition.
    //

} SUBSECTION_COMPAT, * PSUBSECTION_COMPAT;

//
// This is Windows 10 only Section Object definition.
// 
// N.B. It completely differs from anything else.
//
typedef struct _SECTION_COMPAT {

    RTL_BALANCED_NODE SectionNode;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;

    union {
        union {
            struct _CONTROL_AREA* ControlArea;
            struct _FILE_OBJECT* FileObject;
            struct {
                ULONG_PTR RemoteImageFileObject : 1; /* bit position: 0 */
                ULONG_PTR RemoteDataFileObject : 1; /* bit position: 1 */
            };
        };
    } u1;

    ULONG_PTR SizeOfSection;

    union {
        ULONG LongFlags;
        MMSECTION_FLAGS Flags;
    } u;

    struct {
        ULONG InitialPageProtection : 12; /* bit position: 0 */
        ULONG SessionId : 19; /* bit position: 12 */
        ULONG NoValidationNeeded : 1; /* bit position: 31 */
    };

} SECTION_COMPAT, * PSECTION_COMPAT;  /* size: 0x0040 */

/*
* MM END
*/

/*
*  Configuration Manager control vector
*/
typedef struct _CM_SYSTEM_CONTROL_VECTOR_V1 {
    PWSTR  KeyPath;
    PWSTR  ValueName;
    PVOID  Buffer;
    PULONG BufferLength;
    PULONG Type;
} CM_SYSTEM_CONTROL_VECTOR_V1, * PCM_SYSTEM_CONTROL_VECTOR_V1;

//
// Since Windows 10 RS4
//
typedef struct _CM_SYSTEM_CONTROL_VECTOR_V2 {
    PWSTR  KeyPath;
    PWSTR  ValueName;
    PVOID  Buffer;
    PULONG BufferLength;
    PULONG Type;
    ULONG Flags; //0 or 1 depends on flag from LOADER_PARAMETER_BLOCK attached hives
    ULONG Spare0;
} CM_SYSTEM_CONTROL_VECTOR_V2, * PCM_SYSTEM_CONTROL_VECTOR_V2;

/*
** Callbacks START
*/

typedef NTSTATUS(*PEX_CALLBACK_FUNCTION) (
    IN PVOID CallbackContext,
    IN PVOID Argument1,
    IN PVOID Argument2
    );

typedef VOID(NTAPI* PEX_HOST_NOTIFICATION) (
    _In_ ULONG NotificationType,
    _In_opt_ PVOID Context);

typedef struct _EX_EXTENSION_INFORMATION {
    USHORT Id;
    USHORT Version;
    USHORT FunctionCount;
} EX_EXTENSION_INFORMATION, * PEX_EXTENSION_INFORMATION;

typedef struct _EX_HOST_PARAMS {
    EX_EXTENSION_INFORMATION HostInformation;
    POOL_TYPE PoolType;
    PVOID HostTable;
    PVOID NotificationRoutine;
    PVOID NotificationContext;
} EX_HOST_PARAMS, * PEX_HOST_PARAMS;

typedef struct _EX_HOST_ENTRY {
    LIST_ENTRY ListEntry;
    LONG RefCounter;
    EX_HOST_PARAMS HostParameters;
    EX_RUNDOWN_REF RundownProtection;
    EX_PUSH_LOCK PushLock;
    PVOID FunctionTable; //callbacks
    ULONG Flags;
} EX_HOST_ENTRY, * PEX_HOST_ENTRY;

typedef struct _EX_EXTENSION_REGISTRATION {
    EX_EXTENSION_INFORMATION Information;
    PVOID FunctionTable;
    PVOID* HostTable;
    PDRIVER_OBJECT DriverObject;
} EX_EXTENSION_REGISTRATION, * PEX_EXTENSION_REGISTRATION;

typedef struct _EX_CALLBACK {
    EX_FAST_REF RoutineBlock;
} EX_CALLBACK, *PEX_CALLBACK;

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF RundownProtect;
    PVOID Function; //PEX_CALLBACK_FUNCTION
    PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

typedef struct _KBUGCHECK_CALLBACK_RECORD {
    LIST_ENTRY Entry;
    PVOID CallbackRoutine;
    PVOID Buffer;
    ULONG Length;
    PUCHAR Component;
    ULONG_PTR Checksum;
    UCHAR State;
} KBUGCHECK_CALLBACK_RECORD, *PKBUGCHECK_CALLBACK_RECORD;

typedef enum _KBUGCHECK_CALLBACK_REASON {
    KbCallbackInvalid,
    KbCallbackReserved1,
    KbCallbackSecondaryDumpData,
    KbCallbackDumpIo,
    KbCallbackAddPages,
    KbCallbackSecondaryMultiPartDumpData,
    KbCallbackRemovePages,
    KbCallbackTriageDumpData
} KBUGCHECK_CALLBACK_REASON;

typedef struct _KBUGCHECK_REASON_CALLBACK_RECORD {
    LIST_ENTRY Entry;
    PVOID CallbackRoutine;
    PUCHAR Component;
    ULONG_PTR Checksum;
    KBUGCHECK_CALLBACK_REASON Reason;
    UCHAR State;
} KBUGCHECK_REASON_CALLBACK_RECORD, *PKBUGCHECK_REASON_CALLBACK_RECORD;

typedef struct _CM_CALLBACK_CONTEXT_BLOCK {
    LIST_ENTRY CallbackListEntry;
    LONG PreCallListHead;
    LARGE_INTEGER Cookie;
    PVOID CallerContext; 
    PEX_CALLBACK_FUNCTION Function;
    UNICODE_STRING Altitude;
    LIST_ENTRY ObjectContextListHead;
} CM_CALLBACK_CONTEXT_BLOCK, *PCM_CALLBACK_CONTEXT_BLOCK;

typedef struct _SEP_LOGON_SESSION_TERMINATED_NOTIFICATION {
    struct _SEP_LOGON_SESSION_TERMINATED_NOTIFICATION *Next;
    PVOID CallbackRoutine; //PSE_LOGON_SESSION_TERMINATED_ROUTINE
} SEP_LOGON_SESSION_TERMINATED_NOTIFICATION, *PSEP_LOGON_SESSION_TERMINATED_NOTIFICATION;

typedef struct _NOTIFICATION_PACKET {
    LIST_ENTRY ListEntry;
    PVOID DriverObject; //PDRIVER_OBJECT
    PVOID NotificationRoutine; //PDRIVER_FS_NOTIFICATION
} NOTIFICATION_PACKET, *PNOTIFICATION_PACKET;

typedef struct _SHUTDOWN_PACKET {
    LIST_ENTRY ListEntry;
    PVOID DeviceObject; //PDEVICE_OBJECT
} SHUTDOWN_PACKET, *PSHUTDOWN_PACKET;

#define EX_CALLBACK_SIGNATURE 'llaC'

typedef struct _CALLBACK_OBJECT {
    ULONG Signature;
    KSPIN_LOCK Lock;
    LIST_ENTRY RegisteredCallbacks;
    BOOLEAN AllowMultipleCallbacks;
    UCHAR reserved[3];
} CALLBACK_OBJECT, *PCALLBACK_OBJECT;

// Since 8.1
typedef struct _CALLBACK_OBJECT_V2 {
    ULONG Signature;
    KSPIN_LOCK Lock;
    LIST_ENTRY RegisteredCallbacks;
    BOOLEAN AllowMultipleCallbacks;
    LIST_ENTRY ExpCallbackList;
} CALLBACK_OBJECT_V2, * PCALLBACK_OBJECT_V2;

typedef struct _CALLBACK_REGISTRATION {
    LIST_ENTRY Link;
    PCALLBACK_OBJECT CallbackObject;
    PVOID CallbackFunction; //PCALLBACK_FUNCTION
    PVOID CallbackContext;
    ULONG Busy;
    BOOLEAN UnregisterWaiting;
} CALLBACK_REGISTRATION, *PCALLBACK_REGISTRATION;

typedef ULONG OB_OPERATION;

#define OB_OPERATION_HANDLE_CREATE              0x00000001
#define OB_OPERATION_HANDLE_DUPLICATE           0x00000002

typedef struct _OB_CALLBACK_CONTEXT_BLOCK {
    LIST_ENTRY CallbackListEntry;
    OB_OPERATION Operations;
    ULONG Flags;
    struct _OB_REGISTRATION* Registration;
    POBJECT_TYPE ObjectType;
    PVOID PreCallback;
    PVOID PostCallback;
    EX_RUNDOWN_REF RundownReference;
} OB_CALLBACK_CONTEXT_BLOCK, *POB_CALLBACK_CONTEXT_BLOCK;

typedef struct _OB_REGISTRATION {
    USHORT Version;
    USHORT RegistrationCount;
    PVOID  RegistrationContext;
    UNICODE_STRING Altitude;
    OB_CALLBACK_CONTEXT_BLOCK* CallbackContext;
} OB_REGISTRATION, * POB_REGISTRATION;

#define PO_POWER_SETTINGS_REGISTRATION_TAG 'teSP'

typedef struct _POP_POWER_SETTING_REGISTRATION_V1 {
    LIST_ENTRY Link;
    ULONG Tag;
    PVOID CallbackThread; //PKTHREAD
    UCHAR UnregisterOnReturn;
    UCHAR UnregisterPending;
    GUID Guid;
    PVOID LastValue; //PPOP_POWER_SETTING_VALUE
    PVOID Callback;
    PVOID Context;
    PDEVICE_OBJECT DeviceObject;
} POP_POWER_SETTING_REGISTRATION_V1, *PPOP_POWER_SETTING_REGISTRATION_V1;

//
// WARNING: this structure definition is incomplete. 
// Tail is incorrect/incomplete for newest Win10 versions.
//
typedef struct _POP_POWER_SETTING_REGISTRATION_V2 {
    LIST_ENTRY Link;
    ULONG Tag;
    PVOID CallbackThread; //PKTHREAD   
    UCHAR UnregisterOnReturn;
    UCHAR UnregisterPending;
    GUID Guid;
    GUID Guid2;
    PVOID LastValue; //PPOP_POWER_SETTING_VALUE
    PVOID Callback;
    PVOID Context;
    PDEVICE_OBJECT DeviceObject;
} POP_POWER_SETTING_REGISTRATION_V2, *PPOP_POWER_SETTING_REGISTRATION_V2;

typedef struct _RTL_CALLBACK_REGISTER {
    ULONG Flags;
    EX_RUNDOWN_REF RundownReference;
    PVOID DebugPrintCallback;
    LIST_ENTRY ListEntry;
} RTL_CALLBACK_REGISTER, *PRTL_CALLBACK_REGISTER;

typedef
VOID
(*PPO_COALESCING_CALLBACK) (
    _In_ ULONG Reason,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Context);

typedef struct _PO_COALESCING_CALLBACK_V1 {
    EX_PUSH_LOCK PushLock;
    PVOID CoalescingCallback;
    PVOID SelfPtr;
    PPO_COALESCING_CALLBACK Callback;
    BOOLEAN ClientOrServer;
    PVOID Context;
} PO_COALESCING_CALLBACK_V1, * PPO_COALESCING_CALLBACK_V1;

typedef struct _PO_COALESCING_CALLBACK_V2 {
    EX_PUSH_LOCK PushLock;
    PVOID CoalescingCallback;
    PVOID SelfPtr;
    PPO_COALESCING_CALLBACK Callback;
    BOOLEAN ClientOrServer;
    PVOID Context;
    LIST_ENTRY Link;
    EX_CALLBACK ExCallback;
} PO_COALESCING_CALLBACK_V2, * PPO_COALESCING_CALLBACK_V2;

typedef
BOOLEAN
(*PNMI_CALLBACK)(
    __in_opt PVOID Context,
    __in BOOLEAN Handled
    );

typedef struct _KNMI_HANDLER_CALLBACK {
    struct _KNMI_HANDLER_CALLBACK* Next;
    PNMI_CALLBACK Callback;
    PVOID Context;
    PVOID Handle;
} KNMI_HANDLER_CALLBACK, * PKNMI_HANDLER_CALLBACK;

typedef
NTSTATUS
(NTAPI* SILO_MONITOR_CREATE_CALLBACK)(
    _In_ PESILO Silo
    );

typedef
VOID
(NTAPI* SILO_MONITOR_TERMINATE_CALLBACK)(
    _In_ PESILO Silo
    );

#define SILO_MONITOR_REGISTRATION_VERSION (1)

typedef struct _SERVER_SILO_MONITOR {
    LIST_ENTRY ListEntry;
    UCHAR Version;
    BOOLEAN MonitorHost;
    BOOLEAN MonitorExistingSilos;
    UCHAR Reserved[5];
    SILO_MONITOR_CREATE_CALLBACK CreateCallback;
    SILO_MONITOR_TERMINATE_CALLBACK TerminateCallback;
    union {
        PUNICODE_STRING DriverObjectName;
        PUNICODE_STRING ComponentName;
    };
} SERVER_SILO_MONITOR, * PSERVER_SILO_MONITOR;

//
// Errata Manager
//
typedef struct _EMP_CALLBACK_DB_RECORD {
    GUID CallbackId;
    PVOID CallbackFunc;
    LONG_PTR CallbackFuncReference;
    PVOID Context;
    SINGLE_LIST_ENTRY List;
    SINGLE_LIST_ENTRY CallbackDependencyListHead;
    ULONG NumberOfStrings;
    ULONG NumberOfNumerics;
    ULONG NumberOfEntries;
    struct _EMP_ENTRY_DB_RECORD* EntryList[1];
} EMP_CALLBACK_DB_RECORD, * PEMP_CALLBACK_DB_RECORD;

typedef struct _EMP_CALLBACK_LIST_ENTRY {
    EMP_CALLBACK_DB_RECORD* CallbackRecord;
    SINGLE_LIST_ENTRY CallbackListEntry;
} EMP_CALLBACK_LIST_ENTRY, * PEMP_CALLBACK_LIST_ENTRY;

/*
** Callbacks END
*/

/*
*  NTQSI Modules START
*/

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX {
    USHORT NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageChecksum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

/*
*	NTQSI Modules END
*/

/*
** Virtual Memory START
*/

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped,
    MemoryPhysicalContiguityInformation,
    MemoryBadInformation,
    MemoryBadInformationAllProcesses,
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS {
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation,
    VmPageDirtyStateInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_REGION_INFORMATION {
    PVOID AllocationBase;
    ULONG AllocationProtect;
    union
    {
        ULONG RegionType;
        struct
        {
            ULONG Private : 1;
            ULONG MappedDataFile : 1;
            ULONG MappedImage : 1;
            ULONG MappedPageFile : 1;
            ULONG MappedPhysical : 1;
            ULONG DirectMapped : 1;
            ULONG SoftwareEnclave : 1;
            ULONG PageSize64K : 1;
            ULONG Reserved : 24;
        };
    };
    SIZE_T RegionSize;
    SIZE_T CommitSize;
} MEMORY_REGION_INFORMATION, *PMEMORY_REGION_INFORMATION;

typedef struct _MEMORY_REGION_INFORMATION_V2 {
    PVOID AllocationBase;
    ULONG AllocationProtect;
    union
    {
        ULONG RegionType;
        struct
        {
            ULONG Private : 1;
            ULONG MappedDataFile : 1;
            ULONG MappedImage : 1;
            ULONG MappedPageFile : 1;
            ULONG MappedPhysical : 1;
            ULONG DirectMapped : 1;
            ULONG SoftwareEnclave : 1; // RS3
            ULONG PageSize64K : 1;
            ULONG Reserved : 24;
        };
    };
    SIZE_T RegionSize;
    SIZE_T CommitSize;
    ULONG_PTR PartitionId; // 19H1
} MEMORY_REGION_INFORMATION_V2, * PMEMORY_REGION_INFORMATION_V2;

typedef struct _MEMORY_REGION_INFORMATION_V3 {
    PVOID AllocationBase;
    ULONG AllocationProtect;
    union
    {
        ULONG RegionType;
        struct
        {
            ULONG Private : 1;
            ULONG MappedDataFile : 1;
            ULONG MappedImage : 1;
            ULONG MappedPageFile : 1;
            ULONG MappedPhysical : 1;
            ULONG DirectMapped : 1;
            ULONG SoftwareEnclave : 1; // RS3
            ULONG PageSize64K : 1;
            ULONG PlaceholderReservation : 1; // RS4
            ULONG MappedAwe : 1; // 21H1
            ULONG MappedWriteWatch : 1;
            ULONG PageSizeLarge : 1;
            ULONG PageSizeHuge : 1;
            ULONG Reserved : 19;
        };
    };
    SIZE_T RegionSize;
    SIZE_T CommitSize;
    ULONG_PTR PartitionId; // 19H1
    ULONG_PTR NodePreference; // 20H1
} MEMORY_REGION_INFORMATION_V3, * PMEMORY_REGION_INFORMATION_V3;

typedef struct _MEMORY_RANGE_ENTRY {
    PVOID VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef struct _MEMORY_IMAGE_INFORMATION {
    PVOID ImageBase;
    SIZE_T SizeOfImage;
    union
    {
        ULONG ImageFlags;
        struct
        {
            ULONG ImagePartialMap : 1;
            ULONG ImageNotExecutable : 1;
            ULONG ImageSigningLevel : 4; // RS3
            ULONG Reserved : 26;
        };
    };
} MEMORY_IMAGE_INFORMATION, * PMEMORY_IMAGE_INFORMATION;

typedef struct _MEMORY_ENCLAVE_IMAGE_INFORMATION {
    MEMORY_IMAGE_INFORMATION ImageInfo;
    UCHAR UniqueID[32];
    UCHAR AuthorID[32];
} MEMORY_ENCLAVE_IMAGE_INFORMATION, * PMEMORY_ENCLAVE_IMAGE_INFORMATION;

/*
** Virtual Memory END
*/

/*
** System Firmware START
*/

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION {
    SystemFirmwareTable_Enumerate,
    SystemFirmwareTable_Get,
    SystemFirmwareTableMax
} SYSTEM_FIRMWARE_TABLE_ACTION, *PSYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

/*
** System Firmware END
*/

//
//  PEB/TEB
//
#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

#define GDI_MAX_HANDLE_COUNT 0x4000 //0xFFFF

// 32-bit definitions
typedef struct _STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} STRING32;
typedef STRING32 *PSTRING32;

typedef STRING32 UNICODE_STRING32;

#if (_MSC_VER < 1300) && !defined(_WINDOWS_)
typedef struct LIST_ENTRY32 {
    DWORD Flink;
    DWORD Blink;
} LIST_ENTRY32;
typedef LIST_ENTRY32 *PLIST_ENTRY32;

typedef struct LIST_ENTRY64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
} LIST_ENTRY64;
typedef LIST_ENTRY64 *PLIST_ENTRY64;
#endif

#define WOW64_POINTER(Type) ULONG

typedef struct _PEB_LDR_DATA32 {
    ULONG Length;
    BOOLEAN Initialized;
    WOW64_POINTER(HANDLE) SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    WOW64_POINTER(PVOID) EntryInProgress;
    BOOLEAN ShutdownInProgress;
    WOW64_POINTER(HANDLE) ShutdownThreadId;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

#define LDR_DATA_TABLE_ENTRY_SIZE_WINXP32 FIELD_OFFSET( LDR_DATA_TABLE_ENTRY32, ForwarderLinks )

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    WOW64_POINTER(PVOID) DllBase;
    WOW64_POINTER(PVOID) EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY32 HashLinks;
        struct
        {
            WOW64_POINTER(PVOID) SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        WOW64_POINTER(PVOID) LoadedImports;
    };
    WOW64_POINTER(PVOID) EntryPointActivationContext;
    WOW64_POINTER(PVOID) PatchInformation;
    LIST_ENTRY32 ForwarderLinks;
    LIST_ENTRY32 ServiceTagLinks;
    LIST_ENTRY32 StaticLinks;
    WOW64_POINTER(PVOID) ContextInformation;
    WOW64_POINTER(ULONG_PTR) OriginalBase;
    LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _CURDIR32 {
    UNICODE_STRING32 DosPath;
    WOW64_POINTER(HANDLE) Handle;
} CURDIR32, *PCURDIR32;

typedef struct _RTL_DRIVE_LETTER_CURDIR32 {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, *PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    WOW64_POINTER(HANDLE) ConsoleHandle;
    ULONG ConsoleFlags;
    WOW64_POINTER(HANDLE) StandardInput;
    WOW64_POINTER(HANDLE) StandardOutput;
    WOW64_POINTER(HANDLE) StandardError;

    CURDIR32 CurrentDirectory;
    UNICODE_STRING32 DllPath;
    UNICODE_STRING32 ImagePathName;
    UNICODE_STRING32 CommandLine;
    WOW64_POINTER(PVOID) Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING32 WindowTitle;
    UNICODE_STRING32 DesktopInfo;
    UNICODE_STRING32 ShellInfo;
    UNICODE_STRING32 RuntimeData;
    RTL_DRIVE_LETTER_CURDIR32 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _PEB32 {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    WOW64_POINTER(HANDLE) Mutant;

    WOW64_POINTER(PVOID) ImageBaseAddress;
    WOW64_POINTER(PPEB_LDR_DATA) Ldr;
    WOW64_POINTER(PRTL_USER_PROCESS_PARAMETERS) ProcessParameters;
    WOW64_POINTER(PVOID) SubSystemData;
    WOW64_POINTER(PVOID) ProcessHeap;
    WOW64_POINTER(PRTL_CRITICAL_SECTION) FastPebLock;
    WOW64_POINTER(PVOID) AtlThunkSListPtr;
    WOW64_POINTER(PVOID) IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ReservedBits0 : 25;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        WOW64_POINTER(PVOID) KernelCallbackTable;
        WOW64_POINTER(PVOID) UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    WOW64_POINTER(PVOID) ApiSetMap;
    ULONG TlsExpansionCounter;
    WOW64_POINTER(PVOID) TlsBitmap;
    ULONG TlsBitmapBits[2];
    WOW64_POINTER(PVOID) ReadOnlySharedMemoryBase;
    WOW64_POINTER(PVOID) HotpatchInformation;
    WOW64_POINTER(PPVOID) ReadOnlyStaticServerData;
    WOW64_POINTER(PVOID) AnsiCodePageData;
    WOW64_POINTER(PVOID) OemCodePageData;
    WOW64_POINTER(PVOID) UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    WOW64_POINTER(SIZE_T) HeapSegmentReserve;
    WOW64_POINTER(SIZE_T) HeapSegmentCommit;
    WOW64_POINTER(SIZE_T) HeapDeCommitTotalFreeThreshold;
    WOW64_POINTER(SIZE_T) HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    WOW64_POINTER(PPVOID) ProcessHeaps;

    WOW64_POINTER(PVOID) GdiSharedHandleTable;
    WOW64_POINTER(PVOID) ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    WOW64_POINTER(PRTL_CRITICAL_SECTION) LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    WOW64_POINTER(ULONG_PTR) ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER32 GdiHandleBuffer;
    WOW64_POINTER(PVOID) PostProcessInitRoutine;

    WOW64_POINTER(PVOID) TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    // Rest of structure not included.
} PEB32, *PPEB32;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH32 {
    ULONG Offset;
    WOW64_POINTER(ULONG_PTR) HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH32, *PGDI_TEB_BATCH32;

#if (_MSC_VER < 1300) && !defined(_WINDOWS_)
//
// 32 and 64 bit specific version for wow64 and the debugger
//
typedef struct _NT_TIB32 {
    DWORD ExceptionList;
    DWORD StackBase;
    DWORD StackLimit;
    DWORD SubSystemTib;
    union {
        DWORD FiberData;
        DWORD Version;
    };
    DWORD ArbitraryUserPointer;
    DWORD Self;
} NT_TIB32, *PNT_TIB32;

typedef struct _NT_TIB64 {
    DWORD64 ExceptionList;
    DWORD64 StackBase;
    DWORD64 StackLimit;
    DWORD64 SubSystemTib;
    union {
        DWORD64 FiberData;
        DWORD Version;
    };
    DWORD64 ArbitraryUserPointer;
    DWORD64 Self;
} NT_TIB64, *PNT_TIB64;
#endif

typedef struct _TEB32 {
    NT_TIB32 NtTib;

    WOW64_POINTER(PVOID) EnvironmentPointer;
    CLIENT_ID32 ClientId;
    WOW64_POINTER(PVOID) ActiveRpcHandle;
    WOW64_POINTER(PVOID) ThreadLocalStoragePointer;
    WOW64_POINTER(PPEB) ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    WOW64_POINTER(PVOID) CsrClientThread;
    WOW64_POINTER(PVOID) Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    WOW64_POINTER(PVOID) WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    WOW64_POINTER(PVOID) SystemReserved1[54];
    NTSTATUS ExceptionCode;
    WOW64_POINTER(PVOID) ActivationContextStackPointer;
    BYTE SpareBytes[36];
    ULONG TxFsContext;

    GDI_TEB_BATCH32 GdiTebBatch;
    CLIENT_ID32 RealClientId;
    WOW64_POINTER(HANDLE) GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    WOW64_POINTER(PVOID) GdiThreadLocalInfo;
    WOW64_POINTER(ULONG_PTR) Win32ClientInfo[62];
    WOW64_POINTER(PVOID) glDispatchTable[233];
    WOW64_POINTER(ULONG_PTR) glReserved1[29];
    WOW64_POINTER(PVOID) glReserved2;
    WOW64_POINTER(PVOID) glSectionInfo;
    WOW64_POINTER(PVOID) glSection;
    WOW64_POINTER(PVOID) glTable;
    WOW64_POINTER(PVOID) glCurrentRC;
    WOW64_POINTER(PVOID) glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING32 StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    WOW64_POINTER(PVOID) DeallocationStack;
    WOW64_POINTER(PVOID) TlsSlots[64];
    LIST_ENTRY32 TlsLinks;
} TEB32, *PTEB32;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _GDI_HANDLE_ENTRY {
    union
    {
        PVOID Object;
        PVOID NextFree;
    };
    union
    {
        struct
        {
            USHORT ProcessId;
            USHORT Lock : 1;
            USHORT Count : 15;
        };
        ULONG Value;
    } Owner;
    USHORT Unique;
    UCHAR Type;
    UCHAR Flags;
    PVOID UserPointer;
} GDI_HANDLE_ENTRY, *PGDI_HANDLE_ENTRY;

typedef struct _GDI_SHARED_MEMORY {
    GDI_HANDLE_ENTRY Handles[GDI_MAX_HANDLE_COUNT];
} GDI_SHARED_MEMORY, *PGDI_SHARED_MEMORY;

#ifndef FLS_MAXIMUM_AVAILABLE
#define FLS_MAXIMUM_AVAILABLE 128
#endif

#ifndef TLS_MINIMUM_AVAILABLE
#define TLS_MINIMUM_AVAILABLE 64
#endif

#ifndef TLS_EXPANSION_SLOTS
#define TLS_EXPANSION_SLOTS 1024
#endif

#ifndef DOS_MAX_COMPONENT_LENGTH
#define DOS_MAX_COMPONENT_LENGTH 255
#endif

#ifndef DOS_MAX_PATH_LENGTH
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)
#endif

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    PVOID PackageDependencyData; //8+
    ULONG ProcessGroupId;
    // ULONG LoaderThreads;
    // UNICODE_STRING RedirectionDllName;
    // UNICODE_STRING HeapPartitionName;
    // ULONGLONG* DefaultThreadpoolCpuSetMasks;
    // ULONG DefaultThreadpoolCpuSetMaskCount;
    // ULONG DefaultThreadpoolThreadMaximum;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1;
            ULONG ReservedBits0 : 24;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps;

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;

    SIZE_T MinimumStackCommit;

    PVOID *FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    //ULONGLONG TppWorkerpListLock;
    //LIST_ENTRY TppWorkerpList;
    //PVOID WaitOnAddressHashTable[128];
    //PVOID TelemetryCoverageHeader;
    //ULONG CloudFileFlags;
    //ULONG CloudFileDiagFlags;
    //CHAR PlaceholderCompatibilityMode;
    //CHAR PlaceholderCompatibilityModeReserved[7];
    //struct _LEAP_SECOND_DATA* LeapSecondData;
    //union
    //{
    //  ULONG LeapSecondFlags;
    //  struct 
    //  {
    //      ULONG SixtySecondEnabled : 1;
    //      ULONG Reserved : 31;
    //  }; 
    //};
    //ULONG NtGlobalFlag2;
    //ULONG64 ExtendedFeatureDisableMask;
} PEB, *PPEB;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH {
    ULONG	Offset;
    UCHAR	Alignment[4];
    ULONG_PTR HDC;
    ULONG	Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB {
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    NTSTATUS ExceptionCode;
    PVOID ActivationContextStackPointer;
#if defined(_M_X64)
    UCHAR SpareBytes[24];
#else
    UCHAR SpareBytes[36];
#endif
    ULONG TxFsContext;

    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#if defined(_M_X64)
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID EtwLocalData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR SoftPatchPtr1;
    PVOID ThreadPoolData;
    PVOID *TlsExpansionSlots;
#if defined(_M_X64)
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
    //PVOID ReservedForWdf;
    //ULONGLONG ReservedForCrt;
    //GUID EffectiveContainerId;
    //ULONGLONG LastSleepCounter;
    //ULONG SpinCallCount;
    //UCHAR Padding8[4];
    //ULONGLONG ExtendedFeatureDisableMask;
} TEB, *PTEB;

typedef struct _PROCESS_DEVICEMAP_INFORMATION {
    union {
        struct {
            HANDLE DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            UCHAR DriveType[32];
        } Query;
    };
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

__inline struct _PEB * NtCurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }

/*
** PEB/TEB END
*/

/*
**  MITIGATION POLICY START
*/

//redefine enum

#define ProcessDEPPolicy                    0
#define ProcessASLRPolicy                   1
#define ProcessDynamicCodePolicy            2
#define ProcessStrictHandleCheckPolicy      3
#define ProcessSystemCallDisablePolicy      4
#define ProcessMitigationOptionsMask        5
#define ProcessExtensionPointDisablePolicy  6
#define ProcessControlFlowGuardPolicy       7
#define ProcessSignaturePolicy              8
#define ProcessFontDisablePolicy            9
#define ProcessImageLoadPolicy              10
#define ProcessSystemCallFilterPolicy       11
#define ProcessPayloadRestrictionPolicy     12
#define ProcessChildProcessPolicy           13
#define ProcessSideChannelIsolationPolicy   14
#define ProcessUserShadowStackPolicy        15
#define ProcessRedirectionTrustPolicy       16

typedef struct tagPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD MicrosoftSignedOnly : 1;
            DWORD StoreSignedOnly : 1;
            DWORD MitigationOptIn : 1;
            DWORD AuditMicrosoftSignedOnly : 1;
            DWORD AuditStoreSignedOnly : 1;
            DWORD ReservedFlags : 27;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10, *PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD ProhibitDynamicCode : 1;
            DWORD AllowThreadOptOut : 1;
            DWORD AllowRemoteDowngrade : 1;
            DWORD AuditProhibitDynamicCode : 1;
            DWORD ReservedFlags : 28;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10, *PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD EnableControlFlowGuard : 1;
            DWORD EnableExportSuppression : 1;
            DWORD StrictMode : 1;
            DWORD EnableXfg : 1;
            DWORD EnableXfgAuditMode : 1;
            DWORD ReservedFlags : 27;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_W10, *PPROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_FONT_DISABLE_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD DisableNonSystemFonts : 1;
            DWORD AuditNonSystemFontLoading : 1;
            DWORD ReservedFlags : 30;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_FONT_DISABLE_POLICY_W10, *PPROCESS_MITIGATION_FONT_DISABLE_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD NoRemoteImages : 1;
            DWORD NoLowMandatoryLabelImages : 1;
            DWORD PreferSystem32Images : 1;
            DWORD AuditNoRemoteImages : 1;
            DWORD AuditNoLowMandatoryLabelImages : 1;
            DWORD ReservedFlags : 27;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10, *PPROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10 {
    union {
        ULONG Flags;
        struct {
            ULONG FilterId : 4;
            ULONG ReservedFlags : 28;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10, *PPROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10 {
    union {
        ULONG Flags;
        struct {
            ULONG EnableExportAddressFilter : 1;
            ULONG AuditExportAddressFilter : 1;
            ULONG EnableExportAddressFilterPlus : 1;
            ULONG AuditExportAddressFilterPlus : 1;
            ULONG EnableImportAddressFilter : 1;
            ULONG AuditImportAddressFilter : 1;
            ULONG EnableRopStackPivot : 1;
            ULONG AuditRopStackPivot : 1;
            ULONG EnableRopCallerCheck : 1;
            ULONG AuditRopCallerCheck : 1;
            ULONG EnableRopSimExec : 1;
            ULONG AuditRopSimExec : 1;
            ULONG ReservedFlags : 20;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10, *PPROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_CHILD_PROCESS_POLICY_W10 {
    union {
        ULONG Flags;
        struct {
            ULONG NoChildProcessCreation : 1;
            ULONG AuditNoChildProcessCreation : 1;
            ULONG AllowSecureProcessCreation : 1;
            ULONG ReservedFlags : 29;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_CHILD_PROCESS_POLICY_W10, *PPROCESS_MITIGATION_CHILD_PROCESS_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD SmtBranchTargetIsolation : 1;
            DWORD IsolateSecurityDomain : 1;
            DWORD DisablePageCombine : 1;
            DWORD SpeculativeStoreBypassDisable : 1;
            DWORD ReservedFlags : 28;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY_W10, *PPROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD DisallowWin32kSystemCalls : 1;
            DWORD AuditDisallowWin32kSystemCalls : 1;
            DWORD ReservedFlags : 30;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_W10, *PPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD EnableUserShadowStack : 1;
            DWORD AuditUserShadowStack : 1;
            DWORD SetContextIpValidation : 1;
            DWORD AuditSetContextIpValidation : 1;
            DWORD EnableUserShadowStackStrictMode : 1;
            DWORD BlockNonCetBinaries : 1;
            DWORD BlockNonCetBinariesNonEhcont : 1;
            DWORD AuditBlockNonCetBinaries : 1;
            DWORD CetDynamicApisOutOfProcOnly : 1;
            DWORD ReservedFlags : 23;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_W10, * PPROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_W10;

typedef struct tagPROCESS_MITIGATION_REDIRECTION_TRUST_POLICY_W10 {
    union {
        DWORD Flags;
        struct {
            DWORD EnforceRedirectionTrust : 1;
            DWORD AuditRedirectionTrust : 1;
            DWORD ReservedFlags : 30;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY_W10, * PPROCESS_MITIGATION_REDIRECTION_TRUST_POLICY_W10;

typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION {
    PROCESS_MITIGATION_POLICY Policy;
    union
    {
        PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_W10 SystemCallDisablePolicy;
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10 DynamicCodePolicy;
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_W10 ControlFlowGuardPolicy;
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10 SignaturePolicy;
        PROCESS_MITIGATION_FONT_DISABLE_POLICY_W10 FontDisablePolicy;
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10 ImageLoadPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10 SystemCallFilterPolicy;
        PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10 PayloadRestrictionPolicy;
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY_W10 ChildProcessPolicy;
        PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY_W10 SideChannelIsolationPolicy;
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_W10 UserShadowStackPolicy;
        PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY_W10 RedirectionTrustPolicy;
    };
} PROCESS_MITIGATION_POLICY_INFORMATION, *PPROCESS_MITIGATION_POLICY_INFORMATION;

/*
**  MITIGATION POLICY END
*/

/*
** KUSER_SHARED_DATA START
*/
#define NX_SUPPORT_POLICY_ALWAYSOFF 0
#define NX_SUPPORT_POLICY_ALWAYSON  1
#define NX_SUPPORT_POLICY_OPTIN     2
#define NX_SUPPORT_POLICY_OPTOUT    3

#include <pshpack4.h>
typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;
#include <poppack.h>

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

#define PROCESSOR_FEATURE_MAX 64

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,                 // None == 0 == standard design
    NEC98x86,                       // NEC PC98xx series on X86
    EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

//
// Define Address of User Shared Data
//
#define MM_SHARED_USER_DATA_VA      0x000000007FFE0000

//
// WARNING: this definition is OS version dependent.
// Structure maybe incomplete.
//
#include <pshpack4.h>
typedef struct _KUSER_SHARED_DATA {

    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;

    volatile KSYSTEM_TIME InterruptTime;
    volatile KSYSTEM_TIME SystemTime;
    volatile KSYSTEM_TIME TimeZoneBias;

    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;

    WCHAR NtSystemRoot[260];

    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;

    union {
        ULONG Reserved2[7];
        struct {
            ULONG AitSamplingValue;
            ULONG AppCompatFlag;
            struct {
                ULONG LowPart;
                ULONG HighPart;
            } RNGSeedVersion;
            ULONG GlobalValidationRunlevel;
            LONG TimeZoneBiasStamp;
            ULONG NtBuildNumber;
        };
    };

    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;
    UCHAR Reserved0[1];
    USHORT NativeProcessorArchitecture;

    ULONG NtMajorVersion;
    ULONG NtMinorVersion;

    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG Reserved1;
    ULONG Reserved3;
    volatile ULONG TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG AltArchitecturePad;
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask;
    BOOLEAN KdDebuggerEnabled;

    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };

    UCHAR Reserved6[2];

    volatile ULONG ActiveConsoleId;
    volatile ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    UCHAR VirtualizationFlags;
    UCHAR Reserved12[2];

    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        };
    };
    ULONG DataFlagsPad[1];
    ULONGLONG TestRetInstruction;
    LONGLONG QpcFrequency;

    ULONG SystemCall;
    ULONG SystemCallPad0;

    ULONGLONG SystemCallPad[2];

    union {
        volatile KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        };
    };

    ULONG Cookie;
    ULONG CookiedPad[1];

    LONGLONG ConsoleSessionForegroundProcessId;

    ULONGLONG TimeUpdateLock;
    ULONGLONG BaselineSystemTimeQpc;
    ULONGLONG BaselineInterruptTimeQpc;
    ULONGLONG QpcSystemTimeIncrement;
    ULONGLONG QpcInterruptTimeIncrement;
    UCHAR QpcSystemTimeIncrementShift;
    UCHAR QpcInterruptTimeIncrementShift;
    USHORT UnparkedProcessorCount;

    ULONG EnclaveFeatureMask[4];
    union {
        ULONG Reserved8;
        ULONG TelemetryCoverageRound;
    };

    USHORT UserModeGlobalLogger[16];

    ULONG ImageFileExecutionOptions;
    ULONG LangGenerationCount;
    ULONGLONG Reserved4;

    volatile ULONG64 InterruptTimeBias;
    volatile ULONG64 QpcBias;

    ULONG ActiveProcessorCount;
    volatile UCHAR ActiveGroupCount;
    UCHAR Reserved9;

    union {
        USHORT QpcData;
        struct {
            UCHAR QpcBypassEnabled : 1;
            UCHAR QpcShift : 1;
        };
    };

    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;

    XSTATE_CONFIGURATION XState;

    KSYSTEM_TIME FeatureConfigurationChangeStamp;
    ULONG Spare;

} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#include <poppack.h>

#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)MM_SHARED_USER_DATA_VA)

#if !defined(__midl) && !defined(MIDL_PASS)

//
// The overall size can change, but it must be the same for all architectures.
//

C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountLowDeprecated) == 0x0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountMultiplier) == 0x4);
C_ASSERT(__alignof(KSYSTEM_TIME) == 4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTime) == 0x08);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemTime) == 0x014);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneBias) == 0x020);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageNumberLow) == 0x02c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageNumberHigh) == 0x02e);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtSystemRoot) == 0x030);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, MaxStackTraceDepth) == 0x238);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, CryptoExponent) == 0x23c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneId) == 0x240);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LargePageMinimum) == 0x244);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AitSamplingValue) == 0x248);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AppCompatFlag) == 0x24c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, RNGSeedVersion) == 0x250);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, GlobalValidationRunlevel) == 0x258);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneBiasStamp) == 0x25c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtBuildNumber) == 0x260);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtProductType) == 0x264);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ProductTypeIsValid) == 0x268);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NativeProcessorArchitecture) == 0x26a);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMajorVersion) == 0x26c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMinorVersion) == 0x270);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ProcessorFeatures) == 0x274);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved1) == 0x2b4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved3) == 0x2b8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeSlip) == 0x2bc);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AlternativeArchitecture) == 0x2c0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemExpirationDate) == 0x2c8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SuiteMask) == 0x2d0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, KdDebuggerEnabled) == 0x2d4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, MitigationPolicies) == 0x2d5);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveConsoleId) == 0x2d8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, DismountCount) == 0x2dc);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ComPlusPackage) == 0x2e0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LastSystemRITEventTickCount) == 0x2e4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NumberOfPhysicalPages) == 0x2e8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SafeBootMode) == 0x2ec);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, VirtualizationFlags) == 0x2ed);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved12) == 0x2ee);

#if defined(_MSC_EXTENSIONS)

C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SharedDataFlags) == 0x2f0);

#endif

C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TestRetInstruction) == 0x2f8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcFrequency) == 0x300);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCall) == 0x308);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCallPad0) == 0x30c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCallPad) == 0x310);

#if defined(_MSC_EXTENSIONS)

C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCount) == 0x320);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountQuad) == 0x320);

#endif

C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Cookie) == 0x330);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ConsoleSessionForegroundProcessId) == 0x338);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeUpdateLock) == 0x340);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, BaselineSystemTimeQpc) == 0x348);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, BaselineInterruptTimeQpc) == 0x350);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcSystemTimeIncrement) == 0x358);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcInterruptTimeIncrement) == 0x360);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcSystemTimeIncrementShift) == 0x368);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcInterruptTimeIncrementShift) == 0x369);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, UnparkedProcessorCount) == 0x36a);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, EnclaveFeatureMask) == 0x36c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved8) == 0x37c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, UserModeGlobalLogger) == 0x380);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageFileExecutionOptions) == 0x3a0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LangGenerationCount) == 0x3a4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved4) == 0x3a8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTimeBias) == 0x3b0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcBias) == 0x3b8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveProcessorCount) == 0x3c0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveGroupCount) == 0x3c4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved9) == 0x3c5);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcData) == 0x3c6);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneBiasEffectiveStart) == 0x3c8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneBiasEffectiveEnd) == 0x3d0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, XState) == 0x3d8);

#endif /* __midl | MIDL_PASS */

/*
** KUSER_SHARED_DATA END
*/

/*
** MM UNLOADED DRIVERS START
*/

typedef struct _UNLOADED_DRIVERS {
    UNICODE_STRING Name;
    PVOID StartAddress;
    PVOID EndAddress;
    LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVERS, *PUNLOADED_DRIVERS;

#define MI_UNLOADED_DRIVERS 50

/*
** MM UNLOADED DRIVERS END
*/


/*
** FLT MANAGER START
*/
typedef enum _FLT_FILTER_FLAGS {
    FLTFL_MANDATORY_UNLOAD_IN_PROGRESS = 1,
    FLTFL_FILTERING_INITIATED = 2,
    FLTFL_NAME_PROVIDER = 4,
    FLTFL_SUPPORTS_PIPES_MAILSLOTS = 8,
    FLTFL_BACKED_BY_PAGEFILE = 16,
    FLTFL_SUPPORTS_DAX_VOLUME = 32,
    FLTFL_SUPPORTS_WCOS = 64,
    FLTFL_FILTERS_READ_WRITE = 128,
} FLT_FILTER_FLAGS, *PFLT_FILTER_FLAGS;

typedef enum _FLT_OBJECT_FLAGS {
    FLT_OBFL_DRAINING = 1,
    FLT_OBFL_ZOMBIED = 2,
    FLT_OBFL_TYPE_INSTANCE = 0x1000000,
    FLT_OBFL_TYPE_FILTER = 0x2000000,
    FLT_OBFL_TYPE_VOLUME = 0x4000000,
} FLT_OBJECT_FLAGS, *PFLT_OBJECT_FLAGS;

typedef struct _FLT_OBJECT {
    ULONG Flags;
    ULONG PointerCount;
    EX_RUNDOWN_REF RundownRef;
    LIST_ENTRY PrimaryLink;
} FLT_OBJECT, *PFLT_OBJECT;

// Since w10 th1
typedef struct _FLT_OBJECT_V2 {
    ULONG Flags;
    ULONG PointerCount;
    EX_RUNDOWN_REF RundownRef;
    LIST_ENTRY PrimaryLink;
    GUID UniqueIdentifier;
} FLT_OBJECT_V2, *PFLT_OBJECT_V2; /* size: 0x0030 */

typedef struct _FLT_SERVER_PORT_OBJECT {
    LIST_ENTRY FilterLink;
    PVOID ConnectNotify;
    PVOID DisconnectNotify;
    PVOID MessageNotify;
    PVOID Filter;
    PVOID Cookie;
    ULONG Flags;
    LONG NumberOfConnections;
    LONG MaxConnections;
    LONG __PADDING__[1];
} FLT_SERVER_PORT_OBJECT, *PFLT_SERVER_PORT_OBJECT; /* size: 0x0048 */

typedef struct _FLT_RESOURCE_LIST_HEAD {
    ERESOURCE rLock;
    LIST_ENTRY rList;
    ULONG rCount;
    LONG __PADDING__[1];
} FLT_RESOURCE_LIST_HEAD, *PFLT_RESOURCE_LIST_HEAD; /* size: 0x0080 */

typedef struct _FLT_MUTEX_LIST_HEAD {
    FAST_MUTEX mLock;
    LIST_ENTRY mList;
    union {
        ULONG mCount;
        struct {
            UCHAR mInvalid : 1;
            CHAR __PADDING__[7];
        };
    }; 
} FLT_MUTEX_LIST_HEAD, *PFLT_MUTEX_LIST_HEAD; /* size: 0x0050 */

// Windows 7 version
typedef struct _FLT_FILTER_V1 {
    /* 0x0000 */ FLT_OBJECT Base;
    /* 0x0020 */ struct _FLTP_FRAME* Frame;
    /* 0x0028 */ UNICODE_STRING Name;
    /* 0x0038 */ UNICODE_STRING DefaultAltitude;
    /* 0x0048 */ FLT_FILTER_FLAGS Flags;
    /* 0x004c */ LONG Padding;
    /* 0x0050 */ DRIVER_OBJECT* DriverObject;
    /* 0x0058 */ FLT_RESOURCE_LIST_HEAD InstanceList;
    /* 0x00d8 */ struct FLT_VERIFIER_EXTENSION* VerifierExtension;
    /* 0x00e0 */ LIST_ENTRY VerifiedFiltersLink;
    /* 0x00f0 */ PVOID FilterUnload /* function */;
    /* 0x00f8 */ PVOID InstanceSetup /* function */;
    /* 0x0100 */ PVOID InstanceQueryTeardown /* function */;
    /* 0x0108 */ PVOID InstanceTeardownStart /* function */;
    /* 0x0110 */ PVOID InstanceTeardownComplete /* function */;
    /* 0x0118 */ struct _ALLOCATE_CONTEXT_HEADER* SupportedContextsListHead;
    /* 0x0120 */ struct _ALLOCATE_CONTEXT_HEADER* SupportedContexts[6];
    /* 0x0150 */ PVOID PreVolumeMount /* function */;
    /* 0x0158 */ PVOID PostVolumeMount /* function */;
    /* 0x0160 */ PVOID GenerateFileName /* function */;
    /* 0x0168 */ PVOID NormalizeNameComponent /* function */;
    /* 0x0170 */ PVOID NormalizeNameComponentEx /* function */;
    /* 0x0178 */ PVOID NormalizeContextCleanup /* function */;
    /* 0x0180 */ PVOID KtmNotification /* function */;
    /* 0x0188 */ struct _FLT_OPERATION_REGISTRATION* Operations;
    /* 0x0190 */ PVOID OldDriverUnload /* function */;
    /* 0x0198 */ FLT_MUTEX_LIST_HEAD ActiveOpens;
    /* 0x01e8 */ FLT_MUTEX_LIST_HEAD ConnectionList;
    /* 0x0238 */ FLT_MUTEX_LIST_HEAD PortList;
    /* 0x0288 */ EX_PUSH_LOCK PortLock;
} FLT_FILTER_V1, * PFLT_FILTER_V1; /* size: 0x0290 */

// Windows 8/8.1 version
typedef struct _FLT_FILTER_V2 {
    /* 0x0000 */ FLT_OBJECT Base;
    /* 0x0020 */ struct _FLTP_FRAME* Frame;
    /* 0x0028 */ UNICODE_STRING Name;
    /* 0x0038 */ UNICODE_STRING DefaultAltitude;
    /* 0x0048 */ FLT_FILTER_FLAGS Flags;
    /* 0x004c */ LONG Padding;
    /* 0x0050 */ DRIVER_OBJECT* DriverObject;
    /* 0x0058 */ FLT_RESOURCE_LIST_HEAD InstanceList;
    /* 0x00d8 */ struct _FLT_VERIFIER_EXTENSION* VerifierExtension;
    /* 0x00e0 */ LIST_ENTRY VerifiedFiltersLink;
    /* 0x00f0 */ PVOID FilterUnload /* function */;
    /* 0x00f8 */ PVOID InstanceSetup /* function */;
    /* 0x0100 */ PVOID InstanceQueryTeardown /* function */;
    /* 0x0108 */ PVOID InstanceTeardownStart /* function */;
    /* 0x0110 */ PVOID InstanceTeardownComplete /* function */;
    /* 0x0118 */ struct _ALLOCATE_CONTEXT_HEADER* SupportedContextsListHead;
    /* 0x0120 */ struct _ALLOCATE_CONTEXT_HEADER* SupportedContexts[7];
    /* 0x0158 */ PVOID PreVolumeMount /* function */;
    /* 0x0160 */ PVOID PostVolumeMount /* function */;
    /* 0x0168 */ PVOID GenerateFileName /* function */;
    /* 0x0170 */ PVOID NormalizeNameComponent /* function */;
    /* 0x0178 */ PVOID NormalizeNameComponentEx /* function */;
    /* 0x0180 */ PVOID NormalizeContextCleanup /* function */;
    /* 0x0188 */ PVOID KtmNotification /* function */;
    /* 0x0190 */ PVOID SectionNotification /* function */; //SINCE 8.1
    /* 0x0198 */ struct _FLT_OPERATION_REGISTRATION* Operations;
    /* 0x01a0 */ PVOID OldDriverUnload /* function */;
    /* 0x01a8 */ FLT_MUTEX_LIST_HEAD ActiveOpens;
    /* 0x01f8 */ FLT_MUTEX_LIST_HEAD ConnectionList;
    /* 0x0248 */ FLT_MUTEX_LIST_HEAD PortList;
    /* 0x0298 */ EX_PUSH_LOCK PortLock;
} FLT_FILTER_V2, * PFLT_FILTER_V2; /* size: 0x02a0 */

// Windows 10 version
typedef struct _FLT_FILTER_V3 {
    /* 0x0000 */ FLT_OBJECT_V2 Base;
    /* 0x0030 */ struct _FLTP_FRAME* Frame;
    /* 0x0038 */ UNICODE_STRING Name;
    /* 0x0048 */ UNICODE_STRING DefaultAltitude;
    /* 0x0058 */ FLT_FILTER_FLAGS Flags;
    /* 0x005c */ LONG Padding;
    /* 0x0060 */ DRIVER_OBJECT* DriverObject;
    /* 0x0068 */ FLT_RESOURCE_LIST_HEAD InstanceList;
    /* 0x00e8 */ struct _FLT_VERIFIER_EXTENSION* VerifierExtension;
    /* 0x00f0 */ LIST_ENTRY VerifiedFiltersLink;
    /* 0x0100 */ PVOID FilterUnload /* function */;
    /* 0x0108 */ PVOID InstanceSetup /* function */;
    /* 0x0110 */ PVOID InstanceQueryTeardown /* function */;
    /* 0x0118 */ PVOID InstanceTeardownStart /* function */;
    /* 0x0120 */ PVOID InstanceTeardownComplete /* function */;
    /* 0x0128 */ struct _ALLOCATE_CONTEXT_HEADER* SupportedContextsListHead;
    /* 0x0130 */ struct _ALLOCATE_CONTEXT_HEADER* SupportedContexts[7];
    /* 0x0168 */ PVOID PreVolumeMount /* function */;
    /* 0x0170 */ PVOID PostVolumeMount /* function */;
    /* 0x0178 */ PVOID GenerateFileName /* function */;
    /* 0x0180 */ PVOID NormalizeNameComponent /* function */;
    /* 0x0188 */ PVOID NormalizeNameComponentEx /* function */;
    /* 0x0190 */ PVOID NormalizeContextCleanup /* function */;
    /* 0x0198 */ PVOID KtmNotification /* function */;
    /* 0x01a0 */ PVOID SectionNotification /* function */;
    /* 0x01a8 */ struct _FLT_OPERATION_REGISTRATION* Operations;
    /* 0x01b0 */ PVOID OldDriverUnload /* function */;
    /* 0x01b8 */ FLT_MUTEX_LIST_HEAD ActiveOpens;
    /* 0x0208 */ FLT_MUTEX_LIST_HEAD ConnectionList;
    /* 0x0258 */ FLT_MUTEX_LIST_HEAD PortList;
    /* 0x02a8 */ EX_PUSH_LOCK PortLock;
} FLT_FILTER_V3, *PFLT_FILTER_V3; /* size: 0x02b0 */

// Windows 10/11+ (22000)
typedef struct _FLT_FILTER_V4 {
    /* 0x0000 */ FLT_OBJECT_V2 Base;
    /* 0x0030 */ struct _FLTP_FRAME* Frame;
    /* 0x0038 */ UNICODE_STRING Name;
    /* 0x0048 */ UNICODE_STRING DefaultAltitude;
    /* 0x0058 */ FLT_FILTER_FLAGS Flags;
    /* 0x005c */ LONG Padding;
    /* 0x0060 */ DRIVER_OBJECT* DriverObject;
    /* 0x0068 */ FLT_RESOURCE_LIST_HEAD InstanceList;
    /* 0x00e8 */ struct _FLT_VERIFIER_EXTENSION* VerifierExtension;
    /* 0x00f0 */ LIST_ENTRY VerifiedFiltersLink;
    /* 0x0100 */ PVOID FilterUnload /* function */;
    /* 0x0108 */ PVOID InstanceSetup /* function */;
    /* 0x0110 */ PVOID InstanceQueryTeardown /* function */;
    /* 0x0118 */ PVOID InstanceTeardownStart /* function */;
    /* 0x0120 */ PVOID InstanceTeardownComplete /* function */;
    /* 0x0128 */ struct _ALLOCATE_CONTEXT_HEADER* SupportedContextsListHead;
    /* 0x0130 */ struct _ALLOCATE_CONTEXT_HEADER* SupportedContexts[7];
    /* 0x0168 */ PVOID PreVolumeMount /* function */;
    /* 0x0170 */ PVOID PostVolumeMount /* function */;
    /* 0x0178 */ PVOID GenerateFileName /* function */;
    /* 0x0180 */ PVOID NormalizeNameComponent /* function */;
    /* 0x0188 */ PVOID NormalizeNameComponentEx /* function */;
    /* 0x0190 */ PVOID NormalizeContextCleanup /* function */;
    /* 0x0198 */ PVOID KtmNotification /* function */;
    /* 0x01a0 */ PVOID SectionNotification /* function */;
    /* 0x01a8 */ struct _FLT_OPERATION_REGISTRATION* Operations;
    /* 0x01b0 */ PVOID OldDriverUnload /* function */;
    /* 0x01b8 */ FLT_MUTEX_LIST_HEAD ActiveOpens;
    /* 0x0208 */ FLT_MUTEX_LIST_HEAD ConnectionList;
    /* 0x0258 */ FLT_MUTEX_LIST_HEAD PortList;
    /* 0x02a8 */ EX_PUSH_LOCK_AUTO_EXPAND PortLock;
} FLT_FILTER_V4, * PFLT_FILTER_V4; /* size: 0x02b8 */

typedef FLT_FILTER_V4 FLT_FILTER_COMPATIBLE;
typedef PFLT_FILTER_V4 PFLT_FILTER_COMPATIBLE;

/*
** FLT MANAGER END
*/

/*
** SILO START
*/

typedef struct _SYSTEM_ROOT_SILO_INFORMATION {
    ULONG NumberOfSilos;
    ULONG SiloIdList[1];
} SYSTEM_ROOT_SILO_INFORMATION, *PSYSTEM_ROOT_SILO_INFORMATION;

typedef struct _SILO_USER_SHARED_DATA {
    ULONG64 ServiceSessionId;
    ULONG ActiveConsoleId;
    LONGLONG ConsoleSessionForegroundProcessId;
    NT_PRODUCT_TYPE NtProductType;
    ULONG SuiteMask;
    ULONG SharedUserSessionId;
    BOOLEAN IsMultiSessionSku;
    BOOLEAN IsStateSeparationEnabled;
    WCHAR NtSystemRoot[260];
    USHORT UserModeGlobalLogger[16];
} SILO_USER_SHARED_DATA, *PSILO_USER_SHARED_DATA;

typedef struct _OBP_SYSTEM_DOS_DEVICE_STATE {
    ULONG GlobalDeviceMap;
    ULONG LocalDeviceCount[26];
} OBP_SYSTEM_DOS_DEVICE_STATE, *POBP_SYSTEM_DOS_DEVICE_STATE;

typedef struct _OBP_SILODRIVERSTATE {
    PDEVICE_MAP SystemDeviceMap;
    OBP_SYSTEM_DOS_DEVICE_STATE SystemDosDeviceState;
    EX_PUSH_LOCK DeviceMapLock;
    OBJECT_NAMESPACE_LOOKUPTABLE PrivateNamespaceLookupTable;
} OBP_SILODRIVERSTATE, *POBP_SILODRIVERSTATE;

typedef struct _OBP_SILODRIVERSTATE_V2 {
    EX_FAST_REF SystemDeviceMap;
    OBP_SYSTEM_DOS_DEVICE_STATE SystemDosDeviceState;
    EX_PUSH_LOCK DeviceMapLock;
    OBJECT_NAMESPACE_LOOKUPTABLE PrivateNamespaceLookupTable;
} OBP_SILODRIVERSTATE_V2, * POBP_SILODRIVERSTATE_V2; /* size: 0x02e0 */

//incomplete, values not important, change between versions.
typedef struct _ESERVERSILO_GLOBALS {
    OBP_SILODRIVERSTATE ObSiloState;
    //incomplete
} ESERVERSILO_GLOBALS, *PESERVERSILO_GLOBALS;

/*
** SILO END
*/

/*
** KSE START
*/

typedef enum _KSE_DISABLE_FLAGS {
    DisableNone = 0,
    DisableDriverShims = 1,
    DisableDeviceShims = 2,
    MaxDisableFlags
} KSE_DISABLE_FLAGS;

typedef enum _KSE_STATE {
    KseNotReady = 0,
    KseInProgress = 1,
    KseReady = 2
} KSE_STATE;

#define KseFlagsNone                0x0000
#define KseFlagsGroupPolicyOk       0x0002
#define KseFlagsVerifierEnabled     0x0040
#define KseFlagsNoDb                0x0080   
#define KseFlagsInitSafeMode        0x0100
#define KseFlagsDrvShimActive       0x0800
#define KseFlagsDevShimsActive      0x1000

#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4324) // structure was padded due to __declspec(align())
#endif
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)_KSE_ENGINE {
    KSE_DISABLE_FLAGS DisableFlags;
    KSE_STATE State;
    ULONG Flags; //KseFlags*
    LIST_ENTRY ProvidersListHead;
    LIST_ENTRY ShimmedDriversListHead;
    PVOID KseGetIoCallbacksRoutine;
    PVOID KseSetCompletionHookRoutine;
    PVOID DeviceInfoCache;
    PVOID HardwareIdCache;
    PVOID ShimmedDriverHint;
} KSE_ENGINE, * PKSE_ENGINE;

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

typedef struct _KSE_SHIM {
    ULONG Size;
    GUID* Guid;
    PWCHAR Name;
    PVOID KseCallbackRoutines;
    PVOID RemoveNotificationRoutine;
    PVOID ApplyNotificationRoutine;
    PVOID HookCollectionsArray;
} KSE_SHIM, * PKSE_SHIM;

typedef enum _KSE_HOOK_COLLECTION_TYPE {
    HookNtOsImport = 0,
    HookHalImport = 1,
    HookNamedModuleImports = 2,
    HookCallbacks = 3,
    HookLastCollection = 4
} KSE_HOOK_COLLECTION_TYPE;

typedef struct _KSE_HOOK_COLLECTION {
    KSE_HOOK_COLLECTION_TYPE Type;
    PWCHAR TargetDriverName;
    PVOID HookArray;
} KSE_HOOK_COLLECTION, * PKSE_HOOK_COLLECTION;

typedef enum _KSE_HOOK_TYPE {
    HookFunction = 0,
    HookIrpCallback = 1,
    HookLast = 2
} KSE_HOOK_TYPE, * PKSE_HOOK_TYPE;

typedef struct _KSE_HOOK {
    KSE_HOOK_TYPE Type;
    union {
        PCHAR FunctionName;
        ULONG CallbackId;
    } DUMMYUNION;
    PVOID HookFunction;
    PVOID OriginalFunction;
} KSE_HOOK, * PKSE_HOOK;

typedef struct _KSE_PROVIDER {
    LIST_ENTRY ProviderList;
    PKSE_SHIM Shim;
} KSE_PROVIDER, * PKSE_PROVIDER;

typedef struct _KSE_SHIMMED_DRIVER {
    LIST_ENTRY ListEntry;
    PVOID DriverBaseAddress;
    ULONG RefCount;
    //incomplete
} KSE_SHIMMED_DRIVER, * PKSE_SHIMMED_DRIVER;

/*
** KSE END
*/

/*
** SOFTWARE LICENSING START
*/
#pragma pack(push, 1)
typedef struct _SL_CACHE_VALUE_DESCRIPTOR {
    USHORT Size;
    USHORT NameLength;
    USHORT Type;
    USHORT DataLength;
    ULONG Attributes;
    ULONG Reserved;
    WCHAR Name[ANYSIZE_ARRAY];
} SL_CACHE_VALUE_DESCRIPTOR, *PSL_CACHE_VALUE_DESCRIPTOR;
typedef SL_CACHE_VALUE_DESCRIPTOR SL_KMEM_CACHE_VALUE_DESCRIPTOR;
#pragma pack(pop)

typedef struct _SL_CACHE {
    ULONG TotalSize;
    ULONG SizeOfData;
    ULONG SignatureSize;
    ULONG Flags;
    ULONG Version;
    SL_KMEM_CACHE_VALUE_DESCRIPTOR Descriptors[ANYSIZE_ARRAY];
} SL_CACHE, *PSL_CACHE;
typedef SL_CACHE SL_KMEM_CACHE;

typedef struct _SL_APPX_CACHE_VALUE_DESCRIPTOR {
    UCHAR HashedName[32];
    ULONGLONG Expiration;
    ULONG DataSize;
    WCHAR Name[ANYSIZE_ARRAY];
} SL_APPX_CACHE_VALUE_DESCRIPTOR, *PSL_APPX_CACHE_VALUE_DESCRIPTOR;

typedef struct _SL_APPX_CACHE {
    ULONG Version;
    ULONG Flags;
    ULONG DataSize;
    ULONGLONG DataCheckSum;
    SL_APPX_CACHE_VALUE_DESCRIPTOR Descriptors[ANYSIZE_ARRAY];
} SL_APPX_CACHE, *PSL_APPX_CACHE;


/*
** SOFTWARE LICENSING END
*/

/*
** List Entry macro START (wdm.h)
*/

#if defined (NTOS_ENABLE_LIST_ENTRY_MACRO)

#define InitializeListHead32(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = PtrToUlong((ListHead)))

FORCEINLINE
VOID
InitializeListHead(
    _Out_ PLIST_ENTRY ListHead
)
{
    ListHead->Flink = ListHead->Blink = ListHead;
    return;
}

_Must_inspect_result_
BOOLEAN
CFORCEINLINE
IsListEmpty(
    _In_ const LIST_ENTRY* ListHead
)
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
BOOLEAN
RemoveEntryList(
    _In_ PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(
    _Inout_ PLIST_ENTRY ListHead
)
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
PLIST_ENTRY
RemoveTailList(
    _Inout_ PLIST_ENTRY ListHead
)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}

FORCEINLINE
VOID
InsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
    return;
}

FORCEINLINE
VOID
InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
    return;
}

FORCEINLINE
VOID
AppendTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY ListToAppend
)
{
    PLIST_ENTRY ListEnd = ListHead->Blink;

    ListHead->Blink->Flink = ListToAppend;
    ListHead->Blink = ListToAppend->Blink;
    ListToAppend->Blink->Flink = ListHead;
    ListToAppend->Blink = ListEnd;
    return;
}

FORCEINLINE
PSINGLE_LIST_ENTRY
PopEntryList(
    _Inout_ PSINGLE_LIST_ENTRY ListHead
)
{
    PSINGLE_LIST_ENTRY FirstEntry;

    FirstEntry = ListHead->Next;
    if (FirstEntry != NULL) {
        ListHead->Next = FirstEntry->Next;
    }

    return FirstEntry;
}

FORCEINLINE
VOID
PushEntryList(
    _Inout_ PSINGLE_LIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PSINGLE_LIST_ENTRY Entry
)
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
    return;
}

#define ASSERT_LIST_ENTRY_VALID(ListEntry) {                    \
    if (ListEntry == NULL)                                      \
        return;                                                 \
    if (ListEntry->Flink == NULL || ListEntry->Blink == NULL)   \
        return;                                                 \
}

#define ASSERT_LIST_ENTRY_VALID_ERROR_X(ListEntry, X) {         \
    if (ListEntry == NULL)                                      \
        return X;                                               \
    if (ListEntry->Flink == NULL || ListEntry->Blink == NULL)   \
        return X;                                               \
}

#define ASSERT_LIST_ENTRY_VALID_BOOLEAN(ListEntry) ASSERT_LIST_ENTRY_VALID_ERROR_X(ListEntry, FALSE)

#endif /* NTOS_ENABLE_LIST_ENTRY_MACRO */

/*
** List Entry macro END
*/

/*
**  LDR START
*/

#define LDR_DLL_NOTIFICATION_REASON_LOADED   1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2

typedef enum _LDR_DLL_LOAD_REASON {
    LoadReasonStaticDependency = 0,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary,
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

//
// Dll Characteristics for LdrLoadDll
//
#define LDR_IGNORE_CODE_AUTHZ_LEVEL                 0x00001000

//
// LdrAddRef Flags
//
#define LDR_ADDREF_DLL_PIN                          0x00000001

//
// LdrLockLoaderLock Flags
//
#define LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS   0x00000001
#define LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY          0x00000002

//
// LdrUnlockLoaderLock Flags
//
#define LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001

//
// LdrGetDllHandleEx Flags
//
#define LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT    0x00000001
#define LDR_GET_DLL_HANDLE_EX_PIN                   0x00000002

//
// LdrGetProcedureAddressEx Flags
//
#define LDR_GET_PROCEDURE_ADDRESS_DONT_RECORD_FORWARDER 0x00000001

#define RESOURCE_TYPE_LEVEL     0
#define RESOURCE_NAME_LEVEL     1
#define RESOURCE_LANGUAGE_LEVEL 2
#define RESOURCE_DATA_LEVEL     3

typedef struct _LDR_RESOURCE_INFO {
    ULONG_PTR Type;
    ULONG_PTR Name;
    ULONG Lang;
} LDR_RESOURCE_INFO, * PLDR_RESOURCE_INFO;

typedef struct _LDR_DATA_TABLE_ENTRY_COMPATIBLE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    } DUMMYUNION0;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1; // Size=4 Offset=104 BitOffset=0 BitCount=1
            ULONG MarkedForRemoval : 1; // Size=4 Offset=104 BitOffset=1 BitCount=1
            ULONG ImageDll : 1; // Size=4 Offset=104 BitOffset=2 BitCount=1
            ULONG LoadNotificationsSent : 1; // Size=4 Offset=104 BitOffset=3 BitCount=1
            ULONG TelemetryEntryProcessed : 1; // Size=4 Offset=104 BitOffset=4 BitCount=1
            ULONG ProcessStaticImport : 1; // Size=4 Offset=104 BitOffset=5 BitCount=1
            ULONG InLegacyLists : 1; // Size=4 Offset=104 BitOffset=6 BitCount=1
            ULONG InIndexes : 1; // Size=4 Offset=104 BitOffset=7 BitCount=1
            ULONG ShimDll : 1; // Size=4 Offset=104 BitOffset=8 BitCount=1
            ULONG InExceptionTable : 1; // Size=4 Offset=104 BitOffset=9 BitCount=1
            ULONG ReservedFlags1 : 2; // Size=4 Offset=104 BitOffset=10 BitCount=2
            ULONG LoadInProgress : 1; // Size=4 Offset=104 BitOffset=12 BitCount=1
            ULONG LoadConfigProcessed : 1; // Size=4 Offset=104 BitOffset=13 BitCount=1
            ULONG EntryProcessed : 1; // Size=4 Offset=104 BitOffset=14 BitCount=1
            ULONG ProtectDelayLoad : 1; // Size=4 Offset=104 BitOffset=15 BitCount=1
            ULONG ReservedFlags3 : 2; // Size=4 Offset=104 BitOffset=16 BitCount=2
            ULONG DontCallForThreads : 1; // Size=4 Offset=104 BitOffset=18 BitCount=1
            ULONG ProcessAttachCalled : 1; // Size=4 Offset=104 BitOffset=19 BitCount=1
            ULONG ProcessAttachFailed : 1; // Size=4 Offset=104 BitOffset=20 BitCount=1
            ULONG CorDeferredValidate : 1; // Size=4 Offset=104 BitOffset=21 BitCount=1
            ULONG CorImage : 1; // Size=4 Offset=104 BitOffset=22 BitCount=1
            ULONG DontRelocate : 1; // Size=4 Offset=104 BitOffset=23 BitCount=1
            ULONG CorILOnly : 1; // Size=4 Offset=104 BitOffset=24 BitCount=1
            ULONG ChpeImage : 1; // Size=4 Offset=104 BitOffset=25 BitCount=1
            ULONG ReservedFlags5 : 2; // Size=4 Offset=104 BitOffset=26 BitCount=2
            ULONG Redirected : 1; // Size=4 Offset=104 BitOffset=28 BitCount=1
            ULONG ReservedFlags6 : 2; // Size=4 Offset=104 BitOffset=29 BitCount=2
            ULONG CompatDatabaseProcessed : 1; // Size=4 Offset=104 BitOffset=31 BitCount=1
        };
    } ENTRYFLAGSUNION;
    WORD ObsoleteLoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    } DUMMYUNION1;
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    } DUMMYUNION2;
    //fields below removed for compatibility, if you need them use LDR_DATA_TABLE_ENTRY_FULL
} LDR_DATA_TABLE_ENTRY_COMPATIBLE, * PLDR_DATA_TABLE_ENTRY_COMPATIBLE;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE LDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE* PLDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY* PCLDR_DATA_TABLE_ENTRY;

typedef BOOLEAN(NTAPI* PLDR_INIT_ROUTINE)(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PVOID Context
    );

typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage = 0,
    LdrHotPatchNotApplied = 1,
    LdrHotPatchAppliedReverse = 2,
    LdrHotPatchAppliedForward = 3,
    LdrHotPatchFailedToPatch = 4,
    LdrHotPatchStateMax = 5,
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

//
// Full declaration of LDR_DATA_TABLE_ENTRY
//
typedef struct _LDR_DATA_TABLE_ENTRY_FULL
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ChpeEmulatorImage : 1;
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock;
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel;
    CHAR Padding1[3];
    ULONG CheckSum;
    LONG Padding2;
    PVOID ActivePatchImageBase;
    LDR_HOT_PATCH_STATE HotPatchState;
    LONG __PADDING__[1];
} LDR_DATA_TABLE_ENTRY_FULL, * PLDR_DATA_TABLE_ENTRY_FULL;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;
typedef const LDR_DLL_NOTIFICATION_DATA* PCLDR_DLL_NOTIFICATION_DATA;

typedef VOID(NTAPI *PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION)(
    _In_    PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_    PVOID Context,
    _Inout_ BOOLEAN *StopEnumeration
    );

typedef VOID(CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    _In_ ULONG NotificationReason,
    _In_ PCLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID Context);

#ifndef LDR_IS_DATAFILE
#define LDR_IS_DATAFILE(DllHandle) (((ULONG_PTR)(DllHandle)) & (ULONG_PTR)1)
#endif

#ifndef LDR_IS_IMAGEMAPPING
#define LDR_IS_IMAGEMAPPING(DllHandle) (((ULONG_PTR)(DllHandle)) & (ULONG_PTR)2)
#endif

#ifndef LDR_IS_RESOURCE
#define LDR_IS_RESOURCE(DllHandle) (LDR_IS_IMAGEMAPPING(DllHandle) || LDR_IS_DATAFILE(DllHandle))
#endif

NTSYSAPI
NTSTATUS
NTAPI
LdrAccessResource(
    _In_ PVOID DllHandle,
    _In_ CONST IMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry,
    _Out_opt_ PVOID *Address,
    _Out_opt_ PULONG Size);

NTSYSAPI
NTSTATUS
NTAPI
LdrAddRefDll(
    _In_ ULONG Flags,
    _In_ PVOID DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrEnumerateLoadedModules(
    _In_opt_ ULONG Flags,
    _In_ PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION CallbackFunction,
    _In_opt_ PVOID Context);

NTSYSAPI
NTSTATUS
NTAPI
LdrFindResource_U(
    _In_ PVOID DllHandle,
    _In_ CONST ULONG_PTR* ResourceIdPath,
    _In_ ULONG ResourceIdPathLength,
    _Out_ PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry);

NTSYSAPI
NTSTATUS
NTAPI
LdrFindResourceEx_U(
    _In_ ULONG Flags,
    _In_ PVOID DllHandle,
    _In_ PLDR_RESOURCE_INFO ResourceInfo,
    _In_ ULONG Level,
    _Out_ PIMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry);

NTSYSAPI
NTSTATUS
NTAPI
LdrFindResourceDirectory_U(
    _In_ PVOID DllHandle,
    _In_ PLDR_RESOURCE_INFO ResourceInfo,
    _In_ ULONG Level,
    _Out_ PIMAGE_RESOURCE_DIRECTORY *ResourceDirectory);

NTSYSAPI
NTSTATUS
NTAPI
LdrFindEntryForAddress(
    _In_ PVOID Address,
    _Out_ PLDR_DATA_TABLE_ENTRY *TableEntry);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandle(
    _In_opt_ PCWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PCUNICODE_STRING DllName,
    _Out_ PVOID *DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandleEx(
    _In_ ULONG Flags,
    _In_opt_ PWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_opt_ PVOID *DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandleByMapping(
    _In_ PVOID BaseAddress,
    _Out_ PVOID *DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandleByName(
    _In_opt_ PUNICODE_STRING BaseDllName,
    _In_opt_ PUNICODE_STRING FullDllName,
    _Out_ PVOID *DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllFullName(
    _In_ PVOID DllHandle,
    _Out_ PUNICODE_STRING FullDllName);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllDirectory(
    _Out_ PUNICODE_STRING DllDirectory);

NTSYSAPI
NTSTATUS
NTAPI
LdrSetDllDirectory(
    _In_ PUNICODE_STRING DllDirectory);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress(
    _In_ PVOID DllHandle,
    _In_opt_ CONST ANSI_STRING* ProcedureName,
    _In_opt_ ULONG ProcedureNumber,
    _Out_ PVOID *ProcedureAddress);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddressForCaller(
    _In_ PVOID DllHandle,
    _In_opt_ PANSI_STRING ProcedureName,
    _In_opt_ ULONG ProcedureNumber,
    _Out_ PVOID *ProcedureAddress,
    _In_ ULONG Flags,
    _In_ PVOID *Callback);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddressEx(
    _In_ PVOID DllHandle,
    _In_opt_ PANSI_STRING ProcedureName,
    _In_opt_ ULONG ProcedureNumber,
    _Out_ PVOID* ProcedureAddress,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetKnownDllSectionHandle(
    _In_ PCWSTR DllName,
    _In_ BOOLEAN KnownDlls32,
    _Out_ PHANDLE Section);

NTSYSAPI
NTSTATUS
NTAPI
LdrLoadDll(
    _In_opt_ PCWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_  PCUNICODE_STRING DllName,
    _Out_ PVOID *DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrUnloadDll(
    _In_ PVOID DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrQueryProcessModuleInformation(
    _Out_ PRTL_PROCESS_MODULES ModuleInformation,
    _In_ ULONG ModuleInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
LdrRegisterDllNotification(
    _In_ ULONG Flags,
    _In_ PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    _In_opt_ PVOID Context,
    _Out_ PVOID *Cookie);

NTSYSAPI
NTSTATUS
NTAPI
LdrUnregisterDllNotification(
    _In_ PVOID Cookie);

NTSYSAPI
NTSTATUS
NTAPI
LdrResSearchResource(
    _In_ PVOID File,
    _In_ CONST ULONG_PTR* ResIds,
    _In_ ULONG ResIdCount,
    _In_ ULONG Flags,
    _Out_ LPVOID *Resource,
    _Out_ ULONG_PTR *Size,
    _In_opt_ USHORT *FoundLanguage,
    _In_opt_ ULONG *FoundLanguageLength);

NTSYSAPI
NTSTATUS
NTAPI
LdrOpenImageFileOptionsKey(
    _In_ PCUNICODE_STRING ImagePathName,
    _In_ BOOLEAN Wow64Path,
    _Out_ PHANDLE KeyHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrQueryImageFileExecutionOptions(
    _In_ PCUNICODE_STRING ImagePathName,
    _In_ PCWSTR OptionName,
    _In_ ULONG Type,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG ResultSize);

NTSYSAPI
BOOLEAN
NTAPI
LdrIsModuleSxsRedirected( //LdrEntry->Flags->Redirected
    _In_ PVOID DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrQueryImageFileExecutionOptionsEx(
    _In_ PCUNICODE_STRING ImagePathName,
    _In_ PCWSTR OptionName,
    _In_ ULONG Type,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG ResultSize,
    _In_ BOOLEAN Wow64Path);

NTSYSAPI
NTSTATUS
NTAPI
LdrQueryImageFileKeyOption(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR OptionName,
    _In_ ULONG Type,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG ResultSize);

NTSYSAPI
NTSTATUS
NTAPI
LdrDisableThreadCalloutsForDll(
    _In_ PVOID DllImageBase);

#define LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS           0x00000001
#define LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY                  0x00000002

#define LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID            0x00000000
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED      0x00000001
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED  0x00000002

#define LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS         0x00000001

NTSYSAPI
NTSTATUS
NTAPI
LdrLockLoaderLock(
    _In_ ULONG Flags,
    _Out_opt_ ULONG *Disposition,
    _Out_ PVOID *Cookie);

NTSYSAPI
NTSTATUS
NTAPI
LdrUnlockLoaderLock(
    _In_ ULONG Flags,
    _Inout_ PVOID Cookie);

NTSYSAPI
NTSTATUS
NTAPI
LdrRelocateImage(
    _In_ PVOID NewBase,
    _In_opt_ PSTR LoaderName,
    _In_ NTSTATUS Success,
    _In_ NTSTATUS Conflict,
    _In_ NTSTATUS Invalid);

NTSYSAPI
PIMAGE_BASE_RELOCATION
NTAPI
LdrProcessRelocationBlock(
    _In_ ULONG_PTR VA,
    _In_ ULONG SizeOfBlock,
    _In_ PUSHORT NextOffset,
    _In_ LONG_PTR Diff);

DECLSPEC_NORETURN
NTSYSAPI
VOID
NTAPI
LdrShutdownProcess(
    VOID);

DECLSPEC_NORETURN
NTSYSAPI
VOID
NTAPI
LdrShutdownThread(
    VOID);

NTSYSAPI
BOOLEAN
NTAPI
LdrControlFlowGuardEnforced(
    VOID);

/*
**  LDR END
*/

/*
* WIN32K OBJECTS START
*/

typedef struct _HANDLEENTRY {
    PHEAD   phead;  // Pointer to the Object.
    PVOID   pOwner; // PTI or PPI
    BYTE    bType;  // Object handle type
    BYTE    bFlags; // Flags
    WORD    wUniq;  // Access count.
} HANDLEENTRY, *PHANDLEENTRY;

typedef struct _SERVERINFO {
    WORD            wRIPFlags;
    WORD            wSRVIFlags;
    WORD            wRIPPID;
    WORD            wRIPError;
    ULONG           cHandleEntries;
    // incomplete
} SERVERINFO, *PSERVERINFO;

typedef struct _SHAREDINFO {
    PSERVERINFO		psi;
    PHANDLEENTRY	aheList;
    ULONG			HeEntrySize;
    // incomplete
} SHAREDINFO, *PSHAREDINFO;

typedef struct _USERCONNECT {
    ULONG ulVersion;
    ULONG ulCurrentVersion;
    DWORD dwDispatchCount;
    SHAREDINFO siClient;
} USERCONNECT, *PUSERCONNECT;

/*
* WIN32K OBJECTS END
*/


/*
** Runtime Library API START
*/

/************************************************************************************
*
* CSR API.
*
************************************************************************************/

NTSYSAPI
ULONG
NTAPI
CsrGetProcessId(
    VOID);

NTSYSAPI
NTSTATUS
NTAPI
CsrClientConnectToServer(
    _In_ PWSTR ObjectDirectory,
    _In_ ULONG ServerDllIndex,
    _Inout_ PVOID ConnectionInformation,
    _Inout_ ULONG *ConnectionInformationLength,
    _Out_ PBOOLEAN CalledFromServer);

/************************************************************************************
*
* RTL Strings API.
*
************************************************************************************/

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

#ifndef RtlInitEmptyUnicodeString
#define RtlInitEmptyUnicodeString(_ucStr,_buf,_bufSize) \
    ((_ucStr)->Buffer = (_buf), \
     (_ucStr)->Length = 0, \
     (_ucStr)->MaximumLength = (USHORT)(_bufSize))
#endif

NTSYSAPI
BOOLEAN
NTAPI
RtlCreateUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PCWSTR SourceString);

NTSYSAPI
BOOLEAN
NTAPI
RtlCreateUnicodeStringFromAsciiz(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PSTR SourceString);

NTSYSAPI
VOID
NTAPI
RtlInitString(
    _Out_ PSTRING DestinationString,
    _In_opt_ PCSZ SourceString);

NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString);

NTSYSAPI
NTSTATUS
NTAPI
RtlInitUnicodeStringEx(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString);

NTSYSAPI
BOOLEAN
NTAPI
RtlEqualUnicodeString(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive);

NTSYSAPI
NTSTATUS
NTAPI
RtlDuplicateUnicodeString(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING StringIn,
    _Out_ PUNICODE_STRING StringOut);

NTSYSAPI
WCHAR
NTAPI
RtlUpcaseUnicodeChar(
    _In_ WCHAR SourceCharacter);

NTSYSAPI
WCHAR
NTAPI
RtlDowncaseUnicodeChar(
    _In_ WCHAR SourceCharacter);

NTSYSAPI
BOOLEAN
NTAPI
RtlIsNameInExpression(
    _In_ PUNICODE_STRING Expression,
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN IgnoreCase,
    _In_opt_ PWCH UpcaseTable);

NTSYSAPI
NTSTATUS
NTAPI
RtlStringFromGUID(
    _In_ GUID *Guid,
    _Out_ PUNICODE_STRING GuidString);

NTSYSAPI
NTSTATUS
NTAPI
RtlGUIDFromString(
    _In_ PUNICODE_STRING GuidString,
    _Out_ GUID *Guid);

NTSYSAPI
BOOLEAN
NTAPI
RtlPrefixUnicodeString(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive);

NTSYSAPI
NTSTATUS
NTAPI
RtlFormatCurrentUserKeyPath(
    _Out_ PUNICODE_STRING CurrentUserKeyPath);

NTSYSAPI
VOID
NTAPI
RtlFreeUnicodeString(
    _In_ PUNICODE_STRING UnicodeString);

NTSYSAPI
VOID
NTAPI
RtlEraseUnicodeString(
    _Inout_ PUNICODE_STRING String);

NTSYSAPI
VOID
NTAPI
RtlFreeAnsiString(
    _In_ PANSI_STRING AnsiString);

NTSYSAPI
NTSTATUS
NTAPI
RtlAnsiStringToUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PCANSI_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToAnsiString(
    _Inout_ PANSI_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString);

NTSYSAPI
WCHAR
NTAPI
RtlAnsiCharToUnicodeChar(
    _Inout_ PUCHAR *SourceCharacter);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToMultiByteSize(
    _Out_ PULONG BytesInMultiByteString,
    _In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString);

NTSYSAPI
BOOLEAN
NTAPI
RtlDosPathNameToNtPathName_U(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Reserved_ PVOID Reserved);

NTSYSAPI
LONG
NTAPI
RtlCompareUnicodeStrings(
    _In_reads_(String1Length) PWCHAR String1,
    _In_ SIZE_T String1Length,
    _In_reads_(String2Length) PWCHAR String2,
    _In_ SIZE_T String2Length,
    _In_ BOOLEAN CaseInSensitive);

NTSYSAPI
VOID
NTAPI
RtlCopyString(
    _In_ PSTRING DestinationString,
    _In_opt_ PSTRING SourceString);

NTSYSAPI
CHAR
NTAPI
RtlUpperChar(
    _In_ CHAR Character);

NTSYSAPI
VOID
NTAPI
RtlUpperString(
    _In_ PSTRING DestinationString,
    _In_ PSTRING SourceString);

//
// preallocated heap-growable buffers
//
typedef struct _RTL_BUFFER {
    PUCHAR    Buffer;
    PUCHAR    StaticBuffer;
    SIZE_T    Size;
    SIZE_T    StaticSize;
    SIZE_T    ReservedForAllocatedSize; // for future doubling
    PVOID     ReservedForIMalloc; // for future pluggable growth
} RTL_BUFFER, *PRTL_BUFFER;

typedef struct _RTL_UNICODE_STRING_BUFFER {
    UNICODE_STRING String;
    RTL_BUFFER     ByteBuffer;
    UCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, *PRTL_UNICODE_STRING_BUFFER;

//
// These are OUT Disposition values.
//
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_AMBIGUOUS   (0x00000001)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_UNC         (0x00000002)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_DRIVE       (0x00000003)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_ALREADY_DOS (0x00000004)

NTSYSAPI
NTSTATUS
NTAPI
RtlNtPathNameToDosPathName(
    _In_ ULONG Flags,
    _Inout_ PRTL_UNICODE_STRING_BUFFER Path,
    _Out_opt_ PULONG Disposition,
    _Inout_opt_ PWSTR* FilePart);

NTSYSAPI
ULONG
NTAPI
RtlIsDosDeviceName_U(
    _In_ PCWSTR DosFileName);

NTSYSAPI
ULONG
NTAPI
RtlGetFullPathName_U(
    _In_ PCWSTR lpFileName,
    _In_ ULONG nBufferLength,
    _Out_writes_bytes_(nBufferLength) PWSTR lpBuffer,
    _Out_opt_ PWSTR *lpFilePart);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetSearchPath(
    _Out_ PWSTR *SearchPath);

typedef enum _RTL_PATH_TYPE {
    RtlPathTypeUnknown,         // 0
    RtlPathTypeUncAbsolute,     // 1
    RtlPathTypeDriveAbsolute,   // 2
    RtlPathTypeDriveRelative,   // 3
    RtlPathTypeRooted,          // 4
    RtlPathTypeRelative,        // 5
    RtlPathTypeLocalDevice,     // 6
    RtlPathTypeRootLocalDevice  // 7
} RTL_PATH_TYPE;

NTSYSAPI
RTL_PATH_TYPE
NTAPI
RtlDetermineDosPathNameType_U(
    _In_ PCWSTR DosFileName);

#define HASH_STRING_ALGORITHM_DEFAULT   (0)
#define HASH_STRING_ALGORITHM_X65599    (1)
#define HASH_STRING_ALGORITHM_INVALID   (0xffffffff)

NTSYSAPI
NTSTATUS
NTAPI
RtlHashUnicodeString(
    _In_ const UNICODE_STRING *String,
    _In_ BOOLEAN CaseInSensitive,
    _In_ ULONG HashAlgorithm,
    _Out_ PULONG HashValue);

NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeStringToString(
    _In_ PUNICODE_STRING Destination,
    _In_ PUNICODE_STRING Source);

NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeToString(
    _In_ PUNICODE_STRING Destination,
    _In_opt_ PWSTR Source);

NTSYSAPI
VOID
NTAPI
RtlCopyUnicodeString(
    _In_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString);

NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeString(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString);

NTSYSAPI
NTSTATUS
NTAPI
RtlDowncaseUnicodeString(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString);

NTSYSAPI
VOID
NTAPI
RtlEraseUnicodeString(
    _Inout_ PUNICODE_STRING String);

#define RTL_ENSURE_BUFFER_SIZE_NO_COPY (0x00000001)

NTSYSAPI
NTSTATUS
NTAPI
RtlpEnsureBufferSize(
    _In_ ULONG Flags,
    _Inout_ PRTL_BUFFER Buffer,
    _In_ SIZE_T NewSizeBytes);

#define RtlInitBuffer(Buff, StatBuff, StatSize) \
    do {                                        \
        (Buff)->Buffer       = (StatBuff);      \
        (Buff)->Size         = (StatSize);      \
        (Buff)->StaticBuffer = (StatBuff);      \
        (Buff)->StaticSize   = (StatSize);      \
    } while (0)

#define RtlEnsureBufferSize(Flags, Buff, NewSizeBytes) \
    (   ((Buff) != NULL && (NewSizeBytes) <= (Buff)->Size) \
        ? STATUS_SUCCESS \
        : RtlpEnsureBufferSize((Flags), (Buff), (NewSizeBytes)) \
    )

#define RtlFreeBuffer(Buff)                              \
    do {                                                 \
        if ((Buff) != NULL && (Buff)->Buffer != NULL) {  \
            if (RTLP_BUFFER_IS_HEAP_ALLOCATED(Buff)) {   \
                UNICODE_STRING UnicodeString;            \
                UnicodeString.Buffer = (PWSTR)(PVOID)(Buff)->Buffer; \
                RtlFreeUnicodeString(&UnicodeString);    \
            }                                            \
            (Buff)->Buffer = (Buff)->StaticBuffer;       \
            (Buff)->Size = (Buff)->StaticSize;           \
        }                                                \
    } while (0)


NTSYSAPI
VOID
NTAPI
RtlRunEncodeUnicodeString(
    _Inout_ PUCHAR Seed,
    _Inout_ PUNICODE_STRING String);

NTSYSAPI
VOID
NTAPI
RtlRunDecodeUnicodeString(
    _In_ UCHAR Seed,
    _Inout_ PUNICODE_STRING String);

/************************************************************************************
*
* RTL Integer conversion API.
*
************************************************************************************/

struct in6_addr;

NTSYSAPI
PWSTR
NTAPI
RtlIpv4AddressToStringW(
    _In_ const struct in_addr *Addr,
    _Out_ PWSTR S);

NTSYSAPI
NTSTATUS
NTAPI
RtlIpv4StringToAddressW(
    _In_ PCWSTR AddressString,
    _In_ BOOLEAN Strict,
    _Out_ LPCWSTR *Terminator,
    _Out_ struct in_addr *Address);

NTSYSAPI
PWSTR
NTAPI
RtlIpv6AddressToStringW(
    _In_ struct in6_addr*Address,
    _Out_writes_(46) PWSTR AddressString);

NTSYSAPI
NTSTATUS
NTAPI
RtlIpv6StringToAddressW(
    _In_ PCWSTR AddressString,
    _Out_ PCWSTR * Terminator,
    _Out_ struct in6_addr*Address);

//taken from ph2

NTSYSAPI
NTSTATUS
NTAPI
RtlIntegerToChar(
    _In_ ULONG Value,
    _In_opt_ ULONG Base,
    _In_ LONG OutputLength,
    _Out_ PSTR String);

NTSYSAPI
NTSTATUS
NTAPI
RtlCharToInteger(
    _In_ PSTR String,
    _In_opt_ ULONG Base,
    _Out_ PULONG Value);

NTSYSAPI
NTSTATUS
NTAPI
RtlLargeIntegerToChar(
    _In_ PLARGE_INTEGER Value,
    _In_opt_ ULONG Base,
    _In_ LONG OutputLength,
    _Out_ PSTR String);

NTSYSAPI
NTSTATUS
NTAPI
RtlIntegerToUnicodeString(
    _In_ ULONG Value,
    _In_opt_ ULONG Base,
    _Inout_ PUNICODE_STRING String);

NTSYSAPI
NTSTATUS
NTAPI
RtlInt64ToUnicodeString(
    _In_ ULONGLONG Value,
    _In_opt_ ULONG Base,
    _Inout_ PUNICODE_STRING String);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToInteger(
    _In_ PUNICODE_STRING String,
    _In_opt_ ULONG Base,
    _Out_ PULONG Value);

/************************************************************************************
*
* RTL Process/Thread API.
*
************************************************************************************/

typedef NTSTATUS(*PUSER_PROCESS_START_ROUTINE)(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

typedef NTSTATUS(*PUSER_THREAD_START_ROUTINE)(
    PVOID ThreadParameter
    );

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Length;
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

//
// This structure is used only by Wow64 processes. The offsets
// of structure elements should the same as viewed by a native Win64 application.
//
typedef struct _RTL_USER_PROCESS_INFORMATION64 {
    ULONG Length;
    LONGLONG Process;
    LONGLONG Thread;
    CLIENT_ID64 ClientId;
    SECTION_IMAGE_INFORMATION64 ImageInformation;
} RTL_USER_PROCESS_INFORMATION64, *PRTL_USER_PROCESS_INFORMATION64;

NTSYSAPI
NTSTATUS
STDAPIVCALLTYPE
RtlSetProcessIsCritical(
    _In_ BOOLEAN NewValue,
    _Out_opt_ PBOOLEAN OldValue,
    _In_ BOOLEAN CheckFlag);

NTSYSAPI
NTSTATUS
STDAPIVCALLTYPE
RtlSetThreadIsCritical(
    _In_ BOOLEAN NewValue,
    _Out_opt_ PBOOLEAN OldValue,
    _In_ BOOLEAN CheckFlag);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateEnvironment(
    _In_ BOOLEAN CloneCurrentEnvironment,
    _Out_ PVOID *Environment);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateEnvironmentEx(
    _In_ PVOID SourceEnv,
    _Out_ PVOID *Environment,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
RtlExpandEnvironmentStrings(
    _In_opt_ PVOID Environment,
    _In_reads_(SrcLength) PWSTR Src,
    _In_ SIZE_T SrcLength,
    _Out_writes_opt_(DstLength) PWSTR Dst,
    _In_ SIZE_T DstLength,
    _Out_opt_ PSIZE_T ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlExpandEnvironmentStrings_U(
    _In_opt_ PVOID Environment,
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination,
    _Out_opt_ PULONG ReturnedLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetCurrentEnvironment(
    _In_ PVOID Environment,
    _Out_opt_ PVOID *PreviousEnvironment);

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryEnvironmentVariable_U(
    _In_opt_ PVOID Environment,
    _In_ PUNICODE_STRING Name,
    _Out_ PUNICODE_STRING Value);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentVariable(
    _Inout_opt_ PVOID* Environment,
    _In_ PUNICODE_STRING Name,
    _In_opt_ PUNICODE_STRING Value);

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyEnvironment(
    _In_ PVOID Environment);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParameters(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData);

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyProcessParameters(
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParametersEx(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserProcess(
    _In_ PUNICODE_STRING NtImagePathName,
    _In_ ULONG Attributes,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_opt_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritHandles,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort,
    _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformationn);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
    _In_ HANDLE Process,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_ ULONG StackZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T InitialStackSize,
    _In_ PUSER_THREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE Thread,
    _Out_opt_ PCLIENT_ID ClientId);

NTSYSAPI
VOID
NTAPI
RtlExitUserThread(
    _In_ NTSTATUS ExitStatus);

NTSYSAPI
VOID
NTAPI
RtlExitUserProcess(
    _In_ NTSTATUS ExitStatus);

NTSYSAPI
VOID
NTAPI
RtlFreeUserThreadStack(
    _In_ HANDLE hProcess,
    _In_ HANDLE hThread);

NTSYSAPI
VOID
NTAPI
RtlPushFrame(
    _In_ PTEB_ACTIVE_FRAME Frame);

NTSYSAPI
VOID
NTAPI
RtlPopFrame(
    _In_ PTEB_ACTIVE_FRAME Frame);

NTSYSAPI
PTEB_ACTIVE_FRAME
NTAPI
RtlGetFrame(
    VOID);

NTSYSAPI
PVOID
NTAPI
RtlEncodePointer(
    _In_ PVOID Ptr);

NTSYSAPI
PVOID
NTAPI
RtlDecodePointer(
    _In_ PVOID Ptr);

/************************************************************************************
*
* RTL Memory Buffer API.
*
************************************************************************************/

NTSYSAPI
SIZE_T
NTAPI
RtlCompareMemoryUlong(
    _In_ PVOID Source,
    _In_ SIZE_T Length,
    _In_ ULONG Pattern);

NTSYSAPI
VOID
NTAPI
RtlFillMemoryUlong(
    _Out_ PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONG Pattern);

NTSYSAPI
VOID
NTAPI
RtlFillMemoryUlonglong(
    _Out_ PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONGLONG Pattern);

/************************************************************************************
*
* RTL PEB API.
*
************************************************************************************/

NTSYSAPI
PPEB
NTAPI
RtlGetCurrentPeb(
    VOID);

NTSYSAPI
VOID
NTAPI
RtlAcquirePebLock(
    VOID);

NTSYSAPI
VOID
NTAPI
RtlReleasePebLock(
    VOID);

/************************************************************************************
*
* RTL Exception Handling API.
*
************************************************************************************/

NTSYSAPI
PVOID
NTAPI
RtlAddVectoredExceptionHandler(
    _In_ ULONG First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler);

NTSYSAPI
ULONG
NTAPI
RtlRemoveVectoredExceptionHandler(
    _In_ PVOID Handle);

NTSYSAPI
BOOLEAN
NTAPI
RtlDispatchException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord);

NTSYSAPI
PVOID
NTAPI
RtlAddVectoredContinueHandler(
    _In_ ULONG First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler);

NTSYSAPI
ULONG
NTAPI
RtlRemoveVectoredContinueHandler(
    _In_ PVOID Handle);

NTSYSAPI
VOID
NTAPI
RtlRaiseException(
    _In_ PEXCEPTION_RECORD ExceptionRecord);

NTSYSAPI
DECLSPEC_NORETURN
VOID
NTAPI
RtlRaiseStatus(
    _In_ NTSTATUS Status);

NTSYSAPI
NTSTATUS
NTAPI
NtContinue(
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN TestAlert);

NTSYSAPI
NTSTATUS
NTAPI
NtRaiseException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN FirstChance);

__analysis_noreturn
NTSYSCALLAPI
VOID
NTAPI
RtlAssert(
    _In_ PVOID VoidFailedAssertion,
    _In_ PVOID VoidFileName,
    _In_ ULONG LineNumber,
    _In_opt_ PSTR MutableMessage);

#define RTL_ASSERT(exp) \
    ((!(exp)) ? (RtlAssert((PVOID)#exp, (PVOID)__FILE__, __LINE__, NULL), FALSE) : TRUE)
#define RTL_ASSERTMSG(msg, exp) \
    ((!(exp)) ? (RtlAssert((PVOID)#exp, (PVOID)__FILE__, __LINE__, msg), FALSE) : TRUE)
#define RTL_SOFT_ASSERT(_exp) \
    ((!(_exp)) ? (DbgPrint("%s(%d): Soft assertion failed\n   Expression: %s\n", __FILE__, __LINE__, #_exp), FALSE) : TRUE)
#define RTL_SOFT_ASSERTMSG(_msg, _exp) \
    ((!(_exp)) ? (DbgPrint("%s(%d): Soft assertion failed\n   Expression: %s\n   Message: %s\n", __FILE__, __LINE__, #_exp, (_msg)), FALSE) : TRUE)

/************************************************************************************
*
* RTL Security API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
RtlGetOwnerSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PSID *Owner,
    _Out_ PBOOLEAN OwnerDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetGroupSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PSID *Group,
    _Out_ PBOOLEAN GroupDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Revision);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetOwnerSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ PSID Owner,
    _In_ BOOLEAN OwnerDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlCopySecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR InputSecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR* OutputSecurityDescriptor);

NTSYSAPI
NTSTATUS
NTAPI
RtlMakeSelfRelativeSD(
    _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Out_writes_bytes_(*BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlAbsoluteToSelfRelativeSD(
    _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlSelfRelativeToAbsoluteSD(
    _In_ PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Out_writes_bytes_to_opt_(*AbsoluteSecurityDescriptorSize, *AbsoluteSecurityDescriptorSize) PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Inout_ PULONG AbsoluteSecurityDescriptorSize,
    _Out_writes_bytes_to_opt_(*DaclSize, *DaclSize) PACL Dacl,
    _Inout_ PULONG DaclSize,
    _Out_writes_bytes_to_opt_(*SaclSize, *SaclSize) PACL Sacl,
    _Inout_ PULONG SaclSize,
    _Out_writes_bytes_to_opt_(*OwnerSize, *OwnerSize) PSID Owner,
    _Inout_ PULONG OwnerSize,
    _Out_writes_bytes_to_opt_(*PrimaryGroupSize, *PrimaryGroupSize) PSID PrimaryGroup,
    _Inout_ PULONG PrimaryGroupSize);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN DaclPresent,
    _In_opt_ PACL Dacl,
    _In_ BOOLEAN DaclDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetDaclSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PBOOLEAN DaclPresent,
    _Out_ PACL* Dacl,
    _Out_ PBOOLEAN DaclDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetSaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN SaclPresent,
    _In_opt_ PACL Sacl,
    _In_ BOOLEAN SaclDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetSaclSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PBOOLEAN SaclPresent,
    _Out_ PACL* Sacl,
    _Out_ PBOOLEAN SaclDefaulted);

NTSYSAPI
ULONG
NTAPI
RtlLengthSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

_Check_return_
NTSYSAPI
BOOLEAN
NTAPI
RtlValidSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

_Check_return_
NTSYSAPI
BOOLEAN
NTAPI
RtlValidRelativeSecurityDescriptor(
    _In_reads_bytes_(SecurityDescriptorLength) PSECURITY_DESCRIPTOR SecurityDescriptorInput,
    _In_ ULONG SecurityDescriptorLength,
    _In_ SECURITY_INFORMATION RequiredInformation);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateAcl(
    _Out_writes_bytes_(AclLength) PACL Acl,
    _In_ ULONG AclLength,
    _In_ ULONG AclRevision);

NTSYSAPI
BOOLEAN
NTAPI
RtlValidAcl(
    _In_ PACL Acl);

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryInformationAcl(
    _In_ PACL Acl,
    _Out_writes_bytes_(AclInformationLength) PVOID AclInformation,
    _In_ ULONG AclInformationLength,
    _In_ ACL_INFORMATION_CLASS AclInformationClass);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetInformationAcl(
    _Inout_ PACL Acl,
    _In_reads_bytes_(AclInformationLength) PVOID AclInformation,
    _In_ ULONG AclInformationLength,
    _In_ ACL_INFORMATION_CLASS AclInformationClass);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG StartingAceIndex,
    _In_reads_bytes_(AceListLength) PVOID AceList,
    _In_ ULONG AceListLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceIndex);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetAce(
    _In_ PACL Acl,
    _In_ ULONG AceIndex,
    _Outptr_ PVOID *Ace);

NTSYSAPI
BOOLEAN
NTAPI
RtlFirstFreeAce(
    _In_ PACL Acl,
    _Out_ PVOID *FirstFree);

NTSYSAPI
BOOLEAN
NTAPI
RtlOwnerAcesPresent(
    _In_ PACL pAcl);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAceEx(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessDeniedAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessDeniedAceEx(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAuditAccessAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAuditAccessAceEx(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedObjectAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ GUID *ObjectTypeGuid,
    _In_opt_ GUID *InheritedObjectTypeGuid,
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessDeniedObjectAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ GUID *ObjectTypeGuid,
    _In_opt_ GUID *InheritedObjectTypeGuid,
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAuditAccessObjectAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ GUID *ObjectTypeGuid,
    _In_opt_ GUID *InheritedObjectTypeGuid,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddCompoundAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ UCHAR AceType,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID ServerSid,
    _In_ PSID ClientSid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddMandatoryAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ PSID Sid,
    _In_ UCHAR AceType,
    _In_ ACCESS_MASK AccessMask);

NTSYSAPI
PVOID
NTAPI
RtlFindAceByType(
    _In_ PACL pAcl,
    _In_ UCHAR AceType,
    _Out_opt_ PULONG pIndex);

NTSYSAPI
BOOLEAN
NTAPI
RtlOwnerAcesPresent(
    _In_ PACL pAcl);

NTSYSAPI
NTSTATUS
NTAPI
RtlDefaultNpAcl(
    _Out_ PACL *Acl);

NTSYSAPI
BOOLEAN
NTAPI
RtlValidSid(
    _In_ PSID Sid);

NTSYSAPI
BOOLEAN
NTAPI
RtlEqualSid(
    _In_ PSID Sid1,
    _In_ PSID Sid2);

NTSYSAPI
BOOLEAN
NTAPI
RtlEqualPrefixSid(
    _In_ PSID Sid1,
    _In_ PSID Sid2);

NTSYSAPI
ULONG
NTAPI
RtlLengthRequiredSid(
    _In_ ULONG SubAuthorityCount);

NTSYSAPI
PVOID
NTAPI
RtlFreeSid(
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateAndInitializeSid(
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    _In_ ULONG SubAuthority0,
    _In_ ULONG SubAuthority1,
    _In_ ULONG SubAuthority2,
    _In_ ULONG SubAuthority3,
    _In_ ULONG SubAuthority4,
    _In_ ULONG SubAuthority5,
    _In_ ULONG SubAuthority6,
    _In_ ULONG SubAuthority7,
    _Out_ PSID *Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeSid(
    _Out_ PSID Sid,
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount);

NTSYSAPI
PSID_IDENTIFIER_AUTHORITY
NTAPI
RtlIdentifierAuthoritySid(
    _In_ PSID Sid);

NTSYSAPI
PULONG
NTAPI
RtlSubAuthoritySid(
    _In_ PSID Sid,
    _In_ ULONG SubAuthority);

NTSYSAPI
PUCHAR
NTAPI
RtlSubAuthorityCountSid(
    _In_ PSID Sid);

NTSYSAPI
ULONG
NTAPI
RtlLengthSid(
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlCopySid(
    _In_ ULONG DestinationSidLength,
    _In_ PSID DestinationSid,
    _In_ PSID SourceSid);

NTSYSAPI
NTSTATUS
NTAPI
RtlCopySidAndAttributesArray(
    _In_ ULONG ArrayLength,
    _In_ PSID_AND_ATTRIBUTES Source,
    _In_ ULONG TargetSidBufferSize,
    _Out_ PSID_AND_ATTRIBUTES TargetArrayElement,
    _Out_ PSID TargetSid,
    _Out_ PSID *NextTargetSid,
    _Out_ PULONG RemainingTargetSidBufferSize);

NTSYSAPI
NTSTATUS
NTAPI
RtlLengthSidAsUnicodeString(
    _In_ PSID Sid,
    _Out_ PULONG StringLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlConvertSidToUnicodeString(
    _In_ PUNICODE_STRING UnicodeString,
    _In_ PSID Sid,
    _In_ BOOLEAN AllocateDestinationString);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateServiceSid(
    _In_ PUNICODE_STRING ServiceName,
    _Out_writes_bytes_opt_(*ServiceSidLength) PSID ServiceSid,
    _Inout_ PULONG ServiceSidLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlSidEqualLevel(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN EqualLevel);

NTSYSAPI
NTSTATUS
NTAPI
RtlSidIsHigherLevel(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN HigherLevel);

NTSYSAPI
NTSTATUS
NTAPI
RtlReplaceSidInSd(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ PSID OldSid,
    _In_ PSID NewSid,
    _Out_ ULONG* NumChanges);

NTSYSAPI
BOOLEAN
NTAPI
RtlIsElevatedRid(
    _In_ PSID_AND_ATTRIBUTES SidAttr);

FORCEINLINE 
LUID 
NTAPI 
RtlConvertLongToLuid(
    _In_ LONG Long
)
{
    LUID TempLuid;
    LARGE_INTEGER TempLi;

    TempLi.QuadPart = Long;
    TempLuid.LowPart = TempLi.LowPart;
    TempLuid.HighPart = TempLi.HighPart;
    return(TempLuid);
}

FORCEINLINE 
LUID 
RtlConvertUlongToLuid(
    _In_ ULONG Ulong
)
{
    LUID tempLuid;

    tempLuid.LowPart = Ulong;
    tempLuid.HighPart = 0;

    return tempLuid;
}

NTSYSAPI
ULONG
NTAPI
RtlUniform(
    _Inout_ PULONG Seed);

NTSYSAPI
ULONG
NTAPI
RtlRandomEx(
    _Inout_ PULONG Seed);

NTSYSAPI
ULONG32
NTAPI
RtlComputeCrc32(
    _In_ ULONG32 PartialCrc,
    _In_ PVOID Buffer,
    _In_ ULONG Length);

NTSYSAPI
NTSTATUS
NTAPI
RtlAdjustPrivilege(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled);

NTSYSAPI
BOOLEAN
NTAPI
RtlAreAllAccessesGranted(
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ACCESS_MASK DesiredAccess);

NTSYSAPI
BOOLEAN
NTAPI
RtlAreAnyAccessesGranted(
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ACCESS_MASK DesiredAccess);

NTSYSAPI
VOID
NTAPI
RtlMapGenericMask(
    _In_ PACCESS_MASK AccessMask,
    _In_ PGENERIC_MAPPING GenericMapping);

NTSYSAPI
NTSTATUS
NTAPI
RtlImpersonateSelf(
    _In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

NTSYSAPI
NTSTATUS
NTAPI
RtlImpersonateSelfEx(
    _In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    _In_opt_ ACCESS_MASK AdditionalAccess,
    _Out_opt_ PHANDLE ThreadToken);

/************************************************************************************
*
* RTL Version API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
RtlGetVersion(
    _Inout_	PRTL_OSVERSIONINFOW lpVersionInformation);

NTSYSAPI
VOID
NTAPI
RtlGetNtVersionNumbers(
    _Out_opt_ PULONG MajorVersion,
    _Out_opt_ PULONG MinorVersion,
    _Out_opt_ PULONG BuildNumber);

/************************************************************************************
*
* RTL Error Status API.
*
************************************************************************************/

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
    _In_ NTSTATUS Status);

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32Error(
    _In_ LONG Win32Error);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetLastNtStatus(
    VOID);

NTSYSAPI
LONG
NTAPI
RtlGetLastWin32Error(
    VOID);

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosErrorNoTeb(
    _In_ NTSTATUS Status);

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
    _In_ NTSTATUS Status);

/************************************************************************************
*
* RTL WOW64 Support API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
RtlWow64EnableFsRedirection(
    _In_ BOOLEAN Wow64FsEnableRedirection);

NTSYSAPI
NTSTATUS
NTAPI
RtlWow64EnableFsRedirectionEx(
    _In_ PVOID DisableFsRedirection,
    _Out_ PVOID *OldFsRedirectionLevel);

NTSYSAPI
NTSTATUS
NTAPI
RtlWow64GetThreadContext(
    _In_ HANDLE ThreadHandle,
    _Inout_ PWOW64_CONTEXT ThreadContext);

NTSYSAPI
NTSTATUS
NTAPI
RtlWow64SetThreadContext(
    _In_ HANDLE ThreadHandle,
    _In_ PWOW64_CONTEXT ThreadContext);

/************************************************************************************
*
* RTL Heap Management API.
*
************************************************************************************/

typedef NTSTATUS(NTAPI * PRTL_HEAP_COMMIT_ROUTINE)(
    _In_  PVOID Base,
    _Inout_ PVOID *CommitAddress,
    _Inout_ PSIZE_T CommitSize
    );

typedef struct _RTL_HEAP_PARAMETERS {
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

_Must_inspect_result_
NTSYSAPI
PVOID
NTAPI
RtlCreateHeap(
    _In_ ULONG Flags,
    _In_opt_ PVOID HeapBase,
    _In_ SIZE_T ReserveSize,
    _In_ SIZE_T CommitSize,
    _In_opt_ PVOID Lock,
    _In_opt_ PRTL_HEAP_PARAMETERS Parameters);

NTSYSAPI
PVOID
NTAPI
RtlDestroyHeap(
    _In_ PVOID HeapHandle);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetHeapInformation(
    _In_opt_ PVOID HeapHandle,
    _In_ HEAP_INFORMATION_CLASS HeapInformationClass,
    _In_opt_ PVOID HeapInformation,
    _In_ SIZE_T HeapInformationLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryHeapInformation(
    _In_ PVOID HeapHandle,
    _In_ HEAP_INFORMATION_CLASS HeapInformationClass,
    _Out_opt_ PVOID HeapInformation,
    _In_opt_ SIZE_T HeapInformationLength,
    _Out_opt_ PSIZE_T ReturnLength);

_Must_inspect_result_
NTSYSAPI
PVOID
NTAPI
RtlAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ SIZE_T Size);

NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress);

NTSYSAPI
NTSTATUS
NTAPI
RtlZeroHeap(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags);

NTSYSAPI
SIZE_T
NTAPI
RtlSizeHeap(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress);

NTSYSAPI
VOID
NTAPI
RtlProtectHeap(
    _In_ PVOID HeapHandle,
    _In_ BOOLEAN MakeReadOnly);

NTSYSAPI
PVOID
NTAPI
RtlReAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size);

NTSYSAPI
ULONG
NTAPI
RtlGetProcessHeaps(
    _In_ ULONG NumberOfHeaps,
    _Out_ PVOID *ProcessHeaps);

typedef NTSTATUS(NTAPI *PRTL_ENUM_HEAPS_ROUTINE)(
    _In_ PVOID HeapHandle,
    _In_ PVOID Parameter
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlEnumProcessHeaps(
    _In_ PRTL_ENUM_HEAPS_ROUTINE EnumRoutine,
    _In_ PVOID Parameter);

/************************************************************************************
*
* RTL Compression API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
RtlGetCompressionWorkSpaceSize(
    _In_ USHORT CompressionFormatAndEngine,
    _Out_ PULONG CompressBufferWorkSpaceSize,
    _Out_ PULONG CompressFragmentWorkSpaceSize);

NTSYSAPI
NTSTATUS
NTAPI
RtlCompressBuffer(
    _In_ USHORT CompressionFormatAndEngine,
    _In_reads_bytes_(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _Out_writes_bytes_to_(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_ ULONG UncompressedChunkSize,
    _Out_ PULONG FinalCompressedSize,
    _In_ PVOID WorkSpace);

NTSYSAPI
NTSTATUS
NTAPI
RtlDecompressBuffer(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Out_ PULONG FinalUncompressedSize);

NTSYSAPI
NTSTATUS
NTAPI
RtlDecompressBufferEx(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Out_ PULONG FinalUncompressedSize,
    _In_ PVOID WorkSpace);

/************************************************************************************
*
* RTL Image API.
*
************************************************************************************/

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK (0x00000001)

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID Base);

NTSYSAPI
NTSTATUS
NTAPI
RtlImageNtHeaderEx(
    _In_ ULONG Flags,
    _In_ PVOID Base,
    _In_ ULONG64 Size,
    _Out_ PIMAGE_NT_HEADERS * OutHeaders);

NTSYSAPI
PVOID
NTAPI
RtlAddressInSectionTable(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG VirtualAddress);

NTSYSAPI
PIMAGE_SECTION_HEADER
NTAPI
RtlSectionTableFromVirtualAddress(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG VirtualAddress);

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    _In_ PVOID BaseOfImage,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size);

NTSYSAPI
PIMAGE_SECTION_HEADER
NTAPI
RtlImageRvaToSection(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID Base,
    _In_ ULONG Rva);

NTSYSAPI
PVOID
NTAPI
RtlImageRvaToVa(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID Base,
    _In_ ULONG Rva,
    _Inout_opt_ PIMAGE_SECTION_HEADER *LastRvaSection);

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID BaseOfImage,
    _In_ PSTR RoutineName);

NTSYSAPI
NTSTATUS
NTAPI
RtlGuardCheckLongJumpTarget(
    _In_ PVOID PcValue,
    _In_ BOOL IsFastFail,
    _Out_ PBOOL IsLongJumpTarget);

/************************************************************************************
*
* RTL Time API.
*
************************************************************************************/

NTSYSAPI
VOID
NTAPI
RtlSecondsSince1970ToTime(
    _In_ ULONG ElapsedSeconds,
    _Out_ PLARGE_INTEGER Time);

NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1970(
    _In_ PLARGE_INTEGER Time,
    _Out_ PULONG ElapsedSeconds);


NTSYSAPI
VOID
NTAPI
RtlSecondsSince1980ToTime(
    _In_ ULONG ElapsedSeconds,
    _Out_ PLARGE_INTEGER Time);

NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1980(
    _In_ PLARGE_INTEGER Time,
    _Out_ PULONG ElapsedSeconds);

NTSYSAPI
VOID
NTAPI
RtlTimeToTimeFields(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields);

NTSYSAPI
BOOLEAN
NTAPI
RtlTimeFieldsToTime(
    _In_ PTIME_FIELDS TimeFields,
    _Out_ PLARGE_INTEGER Time);

NTSYSAPI
NTSTATUS
NTAPI
RtlSystemTimeToLocalTime(
    _In_ PLARGE_INTEGER SystemTime,
    _Out_ PLARGE_INTEGER LocalTime);

NTSYSAPI
NTSTATUS
NTAPI
RtlLocalTimeToSystemTime(
    _In_ PLARGE_INTEGER LocalTime,
    _Out_ PLARGE_INTEGER SystemTime);

NTSYSAPI
ULONGLONG
NTAPI
RtlGetSystemTimePrecise(
    VOID);

NTSYSAPI
LARGE_INTEGER
NTAPI
RtlGetInterruptTimePrecise(
    _Out_ PLARGE_INTEGER PerformanceCounter);

NTSYSAPI
BOOLEAN
NTAPI
RtlQueryUnbiasedInterruptTime(
    _Out_ PLARGE_INTEGER InterruptTime);

NTSYSAPI
KSYSTEM_TIME
NTAPI
RtlGetSystemTimeAndBias(
    _Out_ KSYSTEM_TIME TimeZoneBias,
    _Out_opt_ PLARGE_INTEGER TimeZoneBiasEffectiveStart,
    _Out_opt_ PLARGE_INTEGER TimeZoneBiasEffectiveEnd);

/************************************************************************************
*
* RTL Debug Support API.
*
************************************************************************************/

NTSYSAPI
ULONG
STDAPIVCALLTYPE
DbgPrint(
    _In_z_ _Printf_format_string_ PCH Format,
    ...);

NTSYSAPI
ULONG
STDAPIVCALLTYPE
DbgPrintEx(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ _Printf_format_string_ PSTR Format,
    ...);

NTSYSAPI
NTSTATUS
NTAPI
DbgQueryDebugFilterState(
    _In_ ULONG ComponentId,
    _In_ ULONG Level);

NTSYSAPI
NTSTATUS
NTAPI
DbgSetDebugFilterState(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_ BOOLEAN State);

NTSYSAPI
VOID
NTAPI
DbgUserBreakPoint(
    VOID);

NTSYSAPI
VOID
NTAPI
DbgBreakPoint(
    VOID);

NTSYSAPI
NTSTATUS
NTAPI
DbgUiConnectToDbg(
    VOID);

NTSYSAPI
VOID
NTAPI
DbgUiSetThreadDebugObject(
    _In_ HANDLE DebugObject);

NTSYSAPI
NTSTATUS
NTAPI
DbgUiContinue(
    _In_ PCLIENT_ID AppClientId,
    _In_ NTSTATUS ContinueStatus);

NTSYSAPI
NTSTATUS
NTAPI
DbgUiStopDebugging(
    _In_ HANDLE Process);

NTSYSAPI
NTSTATUS
NTAPI
DbgUiDebugActiveProcess(
    _In_ HANDLE Process);

/************************************************************************************
*
* RTL AVL Tree API.
*
************************************************************************************/

typedef enum _TABLE_SEARCH_RESULT {
    TableEmptyTree,
    TableFoundNode,
    TableInsertAsLeft,
    TableInsertAsRight
} TABLE_SEARCH_RESULT;

typedef enum _RTL_GENERIC_COMPARE_RESULTS {
    GenericLessThan,
    GenericGreaterThan,
    GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;

//
// Add an empty typedef so that functions can reference the
// a pointer to the generic table struct before it is declared.
//

#if defined (__cplusplus)
struct _RTL_AVL_TABLE;
#else
typedef struct _RTL_AVL_TABLE RTL_AVL_TABLE;
typedef struct PRTL_AVL_TABLE *_RTL_AVL_TABLE;
#endif

typedef RTL_GENERIC_COMPARE_RESULTS(NTAPI *PRTL_AVL_COMPARE_ROUTINE)(
    _In_  struct _RTL_AVL_TABLE *Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
    );

typedef PVOID(NTAPI *PRTL_AVL_ALLOCATE_ROUTINE)(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ ULONG ByteSize
    );

typedef VOID(NTAPI *PRTL_AVL_FREE_ROUTINE)(
    _In_  struct _RTL_AVL_TABLE *Table,
    _In_ _Post_invalid_ PVOID Buffer
    );

typedef NTSTATUS(NTAPI *PRTL_AVL_MATCH_FUNCTION)(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ PVOID UserData,
    _In_ PVOID MatchData
    );

typedef struct _RTL_BALANCED_LINKS {
    struct _RTL_BALANCED_LINKS *Parent;
    struct _RTL_BALANCED_LINKS *LeftChild;
    struct _RTL_BALANCED_LINKS *RightChild;
    CHAR Balance;
    UCHAR Reserved[3];
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE {
    RTL_BALANCED_LINKS BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    PRTL_BALANCED_LINKS RestartKey;
    ULONG DeleteCount;
    PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
    PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_AVL_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

NTSYSAPI
VOID
NTAPI
RtlInitializeGenericTableAvl(
    _Out_ PRTL_AVL_TABLE Table,
    _In_ PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
    _In_ PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
    _In_ PRTL_AVL_FREE_ROUTINE FreeRoutine,
    _In_opt_ PVOID TableContext);

NTSYSAPI
PVOID
NTAPI
RtlInsertElementGenericTableAvl(
    _In_ PRTL_AVL_TABLE Table,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ CLONG BufferSize,
    _Out_opt_ PBOOLEAN NewElement);

NTSYSAPI
PVOID
NTAPI
RtlInsertElementGenericTableFullAvl(
    _In_ PRTL_AVL_TABLE Table,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ CLONG BufferSize,
    _Out_opt_ PBOOLEAN NewElement,
    _In_ PVOID NodeOrParent,
    _In_ TABLE_SEARCH_RESULT SearchResult);

NTSYSAPI
BOOLEAN
NTAPI
RtlDeleteElementGenericTableAvl(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer);

NTSYSAPI
PVOID
NTAPI
RtlLookupElementGenericTableAvl(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer);

NTSYSAPI
PVOID
NTAPI
RtlLookupElementGenericTableFullAvl(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer,
    _Out_ PVOID *NodeOrParent,
    _Out_ TABLE_SEARCH_RESULT *SearchResult);

NTSYSAPI
PVOID
NTAPI
RtlEnumerateGenericTableAvl(
    _In_ PRTL_AVL_TABLE Table,
    _In_ BOOLEAN Restart);

NTSYSAPI
PVOID
NTAPI
RtlEnumerateGenericTableWithoutSplayingAvl(
    _In_ PRTL_AVL_TABLE Table,
    _Inout_ PVOID *RestartKey);

NTSYSAPI
PVOID
NTAPI
RtlLookupFirstMatchingElementGenericTableAvl(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer,
    _Out_ PVOID *RestartKey);

NTSYSAPI
PVOID
NTAPI
RtlEnumerateGenericTableLikeADirectory(
    _In_ PRTL_AVL_TABLE Table,
    _In_opt_ PRTL_AVL_MATCH_FUNCTION MatchFunction,
    _In_opt_ PVOID MatchData,
    _In_ ULONG NextFlag,
    _Inout_ PVOID *RestartKey,
    _Inout_ PULONG DeleteCount,
    _In_ PVOID Buffer);

NTSYSAPI
PVOID
NTAPI
RtlGetElementGenericTableAvl(
    _In_ PRTL_AVL_TABLE Table,
    _In_ ULONG I);

NTSYSAPI
ULONG
NTAPI
RtlNumberGenericTableElementsAvl(
    _In_ PRTL_AVL_TABLE Table);

NTSYSAPI
BOOLEAN
NTAPI
RtlIsGenericTableEmptyAvl(
    _In_ PRTL_AVL_TABLE Table);

/************************************************************************************
*
* RTL Critical Section Support API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
RtlEnterCriticalSection(
    _In_ PRTL_CRITICAL_SECTION CriticalSection);

NTSYSAPI
NTSTATUS
NTAPI
RtlLeaveCriticalSection(
    _In_ PRTL_CRITICAL_SECTION CriticalSection);

NTSYSAPI
LOGICAL
NTAPI
RtlIsCriticalSectionLocked(
    _In_ PRTL_CRITICAL_SECTION CriticalSection);

NTSYSAPI
LOGICAL
NTAPI
RtlIsCriticalSectionLockedByThread(
    _In_ PRTL_CRITICAL_SECTION CriticalSection);

NTSYSAPI
ULONG
NTAPI
RtlGetCriticalSectionRecursionCount(
    _In_ PRTL_CRITICAL_SECTION CriticalSection);

NTSYSAPI
LOGICAL
NTAPI
RtlTryEnterCriticalSection(
    _In_ PRTL_CRITICAL_SECTION CriticalSection);

NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeCriticalSection(
    _In_ PRTL_CRITICAL_SECTION CriticalSection);

NTSYSAPI
VOID
NTAPI
RtlEnableEarlyCriticalSectionEventCreation(
    VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeCriticalSectionAndSpinCount(
    _In_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount);

NTSYSAPI
ULONG
NTAPI
RtlSetCriticalSectionSpinCount(
    _In_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount);

NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteCriticalSection(
    _In_ PRTL_CRITICAL_SECTION CriticalSection);

/************************************************************************************
*
* RTL SRW Lock Support API.
*
************************************************************************************/

NTSYSAPI
VOID
NTAPI
RtlInitializeSRWLock(
    _Out_ PRTL_SRWLOCK SRWLock);

NTSYSAPI
VOID
NTAPI
RtlAcquireSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock);

NTSYSAPI
VOID
NTAPI
RtlAcquireSRWLockShared(
    _Inout_ PRTL_SRWLOCK SRWLock);

NTSYSAPI
VOID
NTAPI
RtlReleaseSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock);

NTSYSAPI
VOID
NTAPI
RtlReleaseSRWLockShared(
    _Inout_ PRTL_SRWLOCK SRWLock);

NTSYSAPI
BOOLEAN
NTAPI
RtlTryAcquireSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock);

NTSYSAPI
BOOLEAN
NTAPI
RtlTryAcquireSRWLockShared(
    _Inout_ PRTL_SRWLOCK SRWLock);

NTSYSAPI
VOID
NTAPI
RtlAcquireReleaseSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock);

NTSYSAPI
VOID
NTAPI
RtlUpdateClonedSRWLock(
    _Inout_ PRTL_SRWLOCK SRWLock,
    _In_ LOGICAL Shared);

/************************************************************************************
*
* RTL UAC Support API.
*
************************************************************************************/

#define DBG_FLAG_ELEVATION_ENABLED        1
#define DBG_FLAG_VIRTUALIZATION_ENABLED   2
#define DBG_FLAG_INSTALLER_DETECT_ENABLED 3

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryElevationFlags(
    _Inout_ ULONG *ElevationFlags);

/************************************************************************************
*
* RTL Misc Support API.
*
************************************************************************************/

NTSYSAPI
BOOLEAN
NTAPI
RtlDoesFileExists_U(
    _In_ PCWSTR FileName);

NTSYSAPI
ULONG
NTAPI
RtlGetLongestNtPathLength(
    VOID);

NTSYSAPI
BOOLEAN
NTAPI
RtlAreLongPathsEnabled(
    VOID);

/************************************************************************************
*
* RTL Boundary Descriptor API.
*
************************************************************************************/

NTSYSAPI
PVOID
NTAPI
RtlCreateBoundaryDescriptor(
    _In_ PUNICODE_STRING Name,
    _In_ ULONG Flags);

NTSYSAPI
VOID
NTAPI
RtlDeleteBoundaryDescriptor(
    _In_ _Post_invalid_ PVOID BoundaryDescriptor);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddSIDToBoundaryDescriptor(
    _Inout_ PVOID *BoundaryDescriptor,
    _In_ PSID RequiredSid);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddIntegrityLabelToBoundaryDescriptor(
    _Inout_ PVOID *BoundaryDescriptor,
    _In_ PSID IntegrityLabel);

/************************************************************************************
*
* RTL work item/async IO.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
RtlQueueWorkItem(
    _In_ WORKERCALLBACKFUNC Function,
    _In_ PVOID Context,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetIoCompletionCallback(
    _In_ HANDLE FileHandle,
    _In_ APC_CALLBACK_FUNCTION CompletionProc,
    _In_ ULONG Flags);

/************************************************************************************
*
* RTL data exports.
*
************************************************************************************/

#ifndef _M_X64
#define RtlNtdllName L"ntdll.dll"
#define RtlDosPathSeperatorsString ((UNICODE_STRING)RTL_CONSTANT_STRING(L"\\/"))
#define RtlAlternateDosPathSeperatorString ((UNICODE_STRING)RTL_CONSTANT_STRING(L"/"))
#define RtlNtPathSeperatorString ((UNICODE_STRING)RTL_CONSTANT_STRING(L"\\"))
#else
NTSYSAPI PWSTR RtlNtdllName;
NTSYSAPI UNICODE_STRING RtlDosPathSeperatorsString;
NTSYSAPI UNICODE_STRING RtlAlternateDosPathSeperatorString;
NTSYSAPI UNICODE_STRING RtlNtPathSeperatorString;
#endif

/************************************************************************************
*
* ETW API.
*
************************************************************************************/

typedef VOID(NTAPI *PETWENABLECALLBACK)(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ /*EVENT_FILTER_DESCRIPTOR*/ PVOID FilterData,
    _Inout_opt_ PVOID CallbackContext
    );

NTSYSAPI
NTSTATUS
NTAPI
EtwEventRegister(
    _In_ LPCGUID ProviderId,
    _In_opt_ PETWENABLECALLBACK EnableCallback,
    _In_opt_ PVOID CallbackContext,
    _Out_ PREGHANDLE RegHandle);

NTSYSAPI
ULONG
NTAPI
EtwEventWriteNoRegistration(
    _In_ LPCGUID ProviderId,
    _In_ /*PCEVENT_DESCRIPTOR*/ PVOID EventDescriptor,
    _In_ ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) /*PEVENT_DATA_DESCRIPTOR*/PVOID UserData);


/*
** Runtime Library API END
*/

/*
** Native API START
*/

/************************************************************************************
*
* System Information API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
WINAPI
NtQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemInformationEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetSystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_reads_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength);

/************************************************************************************
*
* Event (EventPair) API.
*
************************************************************************************/

typedef enum _EVENT_INFORMATION_CLASS {
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef struct _EVENT_BASIC_INFORMATION {
    EVENT_TYPE EventType;
    LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtSetEvent(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState);

NTSYSAPI
NTSTATUS
NTAPI
NtClearEvent(
    _In_ HANDLE EventHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtResetEvent(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState);

NTSYSAPI
NTSTATUS
NTAPI
NtPulseEvent(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenKeyedEvent(
    _Out_ PHANDLE KeyedEventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryEvent(
    _In_ HANDLE EventHandle,
    _In_ EVENT_INFORMATION_CLASS EventInformationClass,
    _Out_writes_bytes_(EventInformationLength) PVOID EventInformation,
    _In_ ULONG EventInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateEventPair(
    _Out_ PHANDLE EventPairHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenEventPair(
    _Out_ PHANDLE EventPairHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtSetLowEventPair(
    _In_ HANDLE EventPairHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtSetHighEventPair(
    _In_ HANDLE EventPairHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtWaitLowEventPair(
    _In_ HANDLE EventPairHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtWaitHighEventPair(
    _In_ HANDLE EventPairHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtSetLowWaitHighEventPair(
    _In_ HANDLE EventPairHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtSetHighWaitLowEventPair(
    _In_ HANDLE EventPairHandle);

/************************************************************************************
*
* Mutant API.
*
************************************************************************************/

typedef enum _MUTANT_INFORMATION_CLASS {
    MutantBasicInformation,
    MutantOwnerInformation
} MUTANT_INFORMATION_CLASS;

typedef struct _MUTANT_BASIC_INFORMATION {
    LONG CurrentCount;
    BOOLEAN OwnedByCaller;
    BOOLEAN AbandonedState;
} MUTANT_BASIC_INFORMATION, *PMUTANT_BASIC_INFORMATION;

typedef struct _MUTANT_OWNER_INFORMATION {
    CLIENT_ID ClientId;
} MUTANT_OWNER_INFORMATION, *PMUTANT_OWNER_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateMutant(
    _Out_ PHANDLE MutantHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ BOOLEAN InitialOwner);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenMutant(
    _Out_ PHANDLE MutantHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryMutant(
    _In_ HANDLE MutantHandle,
    _In_ MUTANT_INFORMATION_CLASS MutantInformationClass,
    _Out_writes_bytes_(MutantInformationLength) PVOID MutantInformation,
    _In_ ULONG MutantInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtReleaseMutant(
    _In_ HANDLE MutantHandle,
    _Out_opt_ PLONG PreviousCount);

/************************************************************************************
*
* Timer API.
*
************************************************************************************/

typedef VOID(*PTIMER_APC_ROUTINE) (
    _In_ PVOID TimerContext,
    _In_ ULONG TimerLowValue,
    _In_ LONG TimerHighValue
    );

typedef enum _TIMER_TYPE {
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE;

typedef enum _TIMER_INFORMATION_CLASS {
    TimerBasicInformation
} TIMER_INFORMATION_CLASS;

typedef struct _TIMER_BASIC_INFORMATION {
    LARGE_INTEGER RemainingTime;
    BOOLEAN TimerState;
} TIMER_BASIC_INFORMATION, *PTIMER_BASIC_INFORMATION;

typedef enum _TIMER_SET_INFORMATION_CLASS {
    TimerSetCoalescableTimer,
    MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateTimer(
    _In_ PHANDLE TimerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ TIMER_TYPE TimerType);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateTimer2(
    _Out_ PHANDLE TimerHandle,
    _In_opt_ PVOID Reserved1,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Attributes,
    _In_ ACCESS_MASK DesiredAccess);

NTSYSAPI
NTSTATUS
NTAPI
NtSetTimer(
    _In_ HANDLE TimerHandle,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ PTIMER_APC_ROUTINE TimerApcRoutine,
    _In_opt_ PVOID TimerContext,
    _In_ BOOLEAN WakeTimer,
    _In_opt_ LONG Period,
    _Out_opt_ PBOOLEAN PreviousState);

NTSYSAPI
NTSTATUS
NTAPI
NtSetTimer2(
    _In_ HANDLE TimerHandle,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ PLARGE_INTEGER Period,
    _In_ PVOID Parameters);

NTSYSAPI
NTSTATUS
NTAPI
NtSetTimerEx(
    _In_ HANDLE TimerHandle,
    _In_ TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    _Inout_updates_bytes_opt_(TimerSetInformationLength) PVOID TimerSetInformation,
    _In_ ULONG TimerSetInformationLength);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenTimer(
    _In_ PHANDLE TimerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryTimer(
    _In_ HANDLE TimerHandle,
    _In_ TIMER_INFORMATION_CLASS TimerInformationClass,
    _Out_writes_bytes_(TimerInformationLength) PVOID TimerInformation,
    _In_ ULONG TimerInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtCancelTimer(
    _In_ HANDLE TimerHandle,
    _Out_opt_ PBOOLEAN CurrentState);

NTSYSAPI
NTSTATUS
NTAPI
NtCancelTimer2(
    _In_ HANDLE TimerHandle,
    _In_ PVOID Parameters);

//ref from ph2

NTSYSAPI
NTSTATUS
NTAPI
NtCreateIRTimer(
    _Out_ PHANDLE TimerHandle,
    _In_ ACCESS_MASK DesiredAccess);

NTSYSAPI
NTSTATUS
NTAPI
NtSetIRTimer(
    _In_ HANDLE TimerHandle,
    _In_opt_ PLARGE_INTEGER DueTime);


/************************************************************************************
*
* Semaphore API.
*
************************************************************************************/

typedef enum _SEMAPHORE_INFORMATION_CLASS {
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

typedef struct _SEMAPHORE_BASIC_INFORMATION {
    LONG CurrentCount;
    LONG MaximumCount;
} SEMAPHORE_BASIC_INFORMATION, *PSEMAPHORE_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateSemaphore(
    _Out_ PHANDLE SemaphoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ LONG InitialCount,
    _In_ LONG MaximumCount);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSemaphore(
    _Out_ PHANDLE SemaphoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySemaphore(
    _In_ HANDLE SemaphoreHandle,
    _In_ SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    _Out_writes_bytes_(SemaphoreInformationLength) PVOID SemaphoreInformation,
    _In_ ULONG SemaphoreInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtReleaseSemaphore(
    _In_ HANDLE SemaphoreHandle,
    _In_ LONG ReleaseCount,
    _Out_opt_ PLONG PreviousCount);

/************************************************************************************
*
* Object and Handle API.
*
************************************************************************************/
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    ObjectSessionObjectInformation,
    MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG Reserved[3];
    ULONG NameInfoSize;
    ULONG TypeInfoSize;
    ULONG SecurityDescriptorSize;
    LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION_V2 {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION_V2, *POBJECT_TYPE_INFORMATION_V2;

typedef struct _OBJECT_TYPES_INFORMATION {
    ULONG NumberOfTypes;
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

#define OBJECT_TYPES_FIRST_ENTRY(ObjectTypes) (POBJECT_TYPE_INFORMATION)\
    RtlOffsetToPointer(ObjectTypes, ALIGN_UP(sizeof(OBJECT_TYPES_INFORMATION), ULONG_PTR))

#define OBJECT_TYPES_NEXT_ENTRY(ObjectType) (POBJECT_TYPE_INFORMATION)\
    RtlOffsetToPointer(ObjectType, sizeof(OBJECT_TYPE_INFORMATION) + \
    ALIGN_UP(ObjectType->TypeName.MaximumLength, ULONG_PTR))

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, *POBJECT_HANDLE_FLAG_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtClose(
    _In_ _Post_ptr_invalid_ HANDLE Handle);

NTSYSAPI
NTSTATUS
NTAPI
NtDuplicateObject(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options);

NTSYSAPI
NTSTATUS
NTAPI
NtMakePermanentObject(
    _In_ HANDLE Handle);

NTSYSAPI
NTSTATUS
NTAPI
NtMakeTemporaryObject(
    _In_ HANDLE Handle);

NTSYSAPI
NTSTATUS
NTAPI
NtSetSecurityObject(
    _In_ HANDLE Handle,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySecurityObject(
    _In_ HANDLE Handle,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Length,
    _Out_ PULONG LengthNeeded);

NTSYSAPI
NTSTATUS
NTAPI
NtCompareObjects(
    _In_ HANDLE FirstObjectHandle,
    _In_ HANDLE SecondObjectHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationObject(
    _In_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _In_reads_bytes_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength);

typedef enum _WAIT_TYPE {
    WaitAll,
    WaitAny,
    WaitNotification
} WAIT_TYPE;

NTSYSAPI
NTSTATUS
NTAPI
NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

NTSYSAPI
NTSTATUS
NTAPI
NtWaitForMultipleObjects(
    _In_ ULONG Count,
    _In_reads_(Count) HANDLE Handles[],
    _In_ WAIT_TYPE WaitType,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

/************************************************************************************
*
* Time.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemTime(
    _Out_ PLARGE_INTEGER SystemTime);

NTSYSAPI
NTSTATUS
NTAPI
NtSetSystemTime(
    _In_opt_ PLARGE_INTEGER SystemTime,
    _Out_opt_ PLARGE_INTEGER PreviousTime);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryTimerResolution(
    _Out_ PULONG MaximumTime,
    _Out_ PULONG MinimumTime,
    _Out_ PULONG CurrentTime);

NTSYSAPI
NTSTATUS
NTAPI
NtSetTimerResolution(
    _In_ ULONG DesiredTime,
    _In_ BOOLEAN SetResolution,
    _Out_ PULONG ActualTime);

/************************************************************************************
*
* Directory Object API.
*
************************************************************************************/

#define OBJDIR_FLAG_SHADOW_PRESENT 0x4
#define OBJDIR_FLAG_SANDBOX 0x10

NTSYSAPI
NTSTATUS
NTAPI
NtCreateDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateDirectoryObjectEx(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ShadowDirectoryHandle,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength);

/************************************************************************************
*
* Private Namespace API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtCreatePrivateNamespace(
    _Out_ PHANDLE NamespaceHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PVOID BoundaryDescriptor);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenPrivateNamespace(
    _Out_ PHANDLE NamespaceHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PVOID BoundaryDescriptor);

NTSYSAPI
NTSTATUS
NTAPI
NtDeletePrivateNamespace(
    _In_ HANDLE NamespaceHandle);

/************************************************************************************
*
* Symbolic Link API.
*
************************************************************************************/

typedef enum _SYMBOLIC_LINK_INFO_CLASS {
    SymbolicLinkGlobalInformation = 1,
    SymbolicLinkAccessMask,
    MaxnSymbolicLinkInfoClass
} SYMBOLIC_LINK_INFO_CLASS;

typedef struct _OBJECT_SYMBOLIC_LINK_V1 { //pre Win10 TH1
    LARGE_INTEGER CreationTime;
    UNICODE_STRING LinkTarget;
    ULONG DosDeviceDriveIndex;
} OBJECT_SYMBOLIC_LINK_V1, *POBJECT_SYMBOLIC_LINK_V1;

typedef struct _OBJECT_SYMBOLIC_LINK_V2 { //Win10 TH1/TH2
    LARGE_INTEGER CreationTime;
    UNICODE_STRING LinkTarget;
    ULONG DosDeviceDriveIndex;
    ULONG Flags;
} OBJECT_SYMBOLIC_LINK_V2, *POBJECT_SYMBOLIC_LINK_V2;

typedef struct _OBJECT_SYMBOLIC_LINK_V3 { //Win10 RS1
    LARGE_INTEGER CreationTime;
    UNICODE_STRING LinkTarget;
    ULONG DosDeviceDriveIndex;
    ULONG Flags;
    ULONG AccessMask;
} OBJECT_SYMBOLIC_LINK_V3, *POBJECT_SYMBOLIC_LINK_V3;

typedef struct _OBJECT_SYMBOLIC_LINK_V4 { //Win10 RS2+
    LARGE_INTEGER CreationTime;
    union {
        UNICODE_STRING LinkTarget;
        struct {
            PVOID Callback;
            PVOID CallbackContext;
        };
    } u1;
    ULONG DosDeviceDriveIndex;
    ULONG Flags;
    ULONG AccessMask;
    //long __PADDING__[1];
} OBJECT_SYMBOLIC_LINK_V4, *POBJECT_SYMBOLIC_LINK_V4; /* size: 0x0028 */

typedef struct _OBJECT_SYMBOLIC_LINK_V5 { //Win10 21H1+
    LARGE_INTEGER CreationTime;
    union {
        UNICODE_STRING LinkTarget;
        struct {
            PVOID Callback;
            PVOID CallbackContext;
        };
    } u1;
    ULONG DosDeviceDriveIndex;
    ULONG Flags;
    ULONG AccessMask;
    ULONG IntegrityLevel;
} OBJECT_SYMBOLIC_LINK_V5, * POBJECT_SYMBOLIC_LINK_V5; /* size: 0x0028 */

NTSYSAPI
NTSTATUS
NTAPI
NtCreateSymbolicLinkObject(
    _Out_ PHANDLE LinkHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PUNICODE_STRING LinkTarget);

NTSYSAPI
NTSTATUS
WINAPI
NtOpenSymbolicLinkObject(
    _Out_ PHANDLE LinkHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySymbolicLinkObject(
    _In_ HANDLE LinkHandle,
    _Inout_ PUNICODE_STRING LinkTarget,
    _Out_opt_ PULONG  ReturnedLength);

NTSTATUS
NTAPI
NtSetInformationSymbolicLink(
    _In_ HANDLE LinkHandle,
    _In_ SYMBOLIC_LINK_INFO_CLASS SymbolicLinkInformationClass,
    _In_reads_bytes_(SymbolicLinkInformationLength) PVOID SymbolicLinkInformation,
    _In_ ULONG SymbolicLinkInformationLength);

/************************************************************************************
*
* File API (+Driver&HotPatch).
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateNamedPipeFile(
    _Out_ PHANDLE FileHandle,
    _In_ ULONG DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_ ULONG NamedPipeType,
    _In_ ULONG ReadMode,
    _In_ ULONG CompletionMode,
    _In_ ULONG MaximumInstances,
    _In_ ULONG InboundQuota,
    _In_ ULONG OutboundQuota,
    _In_opt_ PLARGE_INTEGER DefaultTimeout);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateMailslotFile(
    _Out_ PHANDLE FileHandle,
    _In_ ULONG DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG CreateOptions,
    _In_ ULONG MailslotQuota,
    _In_ ULONG MaximumMessageSize,
    _In_ PLARGE_INTEGER ReadTimeout);

NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength);

NTSYSAPI
NTSTATUS
NTAPI
NtFsControlFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG FsControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions);

NTSYSAPI
NTSTATUS
NTAPI
NtReadFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key);

NTSYSAPI
NTSTATUS
NTAPI
NtWriteFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key);

NTSYSAPI
NTSTATUS
NTAPI
NtLockFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ PLARGE_INTEGER Length,
    _In_ ULONG Key,
    _In_ BOOLEAN FailImmediately,
    _In_ BOOLEAN ExclusiveLock);

NTSYSAPI
NTSTATUS
NTAPI
NtUnlockFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ PLARGE_INTEGER Length,
    _In_ ULONG Key);

NTSYSAPI
NTSTATUS
NTAPI
NtFlushBuffersFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass);

NTSYSAPI
NTSTATUS
NTAPI
NtDeleteFile(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryFullAttributesFile(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PFILE_NETWORK_OPEN_INFORMATION FileInformation);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryDirectoryFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryDirectoryFileEx(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ ULONG QueryFlags,
    _In_opt_ PUNICODE_STRING FileName);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryEaFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_reads_bytes_opt_(EaListLength) PVOID EaList,
    _In_ ULONG EaListLength,
    _In_opt_ PULONG EaIndex,
    _In_ BOOLEAN RestartScan);

NTSYSAPI
NTSTATUS
NTAPI
NtSetEaFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_bytecount_(Length) PVOID Buffer,
    _In_ ULONG Length);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryVolumeInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FsInformation,
    _In_ ULONG Length,
    _In_ FS_INFORMATION_CLASS FsInformationClass);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryQuotaInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_reads_bytes_opt_(SidListLength) PVOID SidList,
    _In_ ULONG SidListLength,
    _In_opt_ PSID StartSid,
    _In_ BOOLEAN RestartScan);

NTSYSAPI
NTSTATUS
NTAPI
NtSetQuotaInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length);

NTSYSAPI
NTSTATUS
NTAPI
NtReadFileScatter(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PFILE_SEGMENT_ELEMENT SegmentArray,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key);

NTSYSAPI
NTSTATUS
NTAPI
NtWriteFileGather(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PFILE_SEGMENT_ELEMENT SegmentArray,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryDirectoryFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan);

NTSYSAPI
NTSTATUS
NTAPI
NtNotifyChangeDirectoryFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ ULONG CompletionFilter,
    _In_ BOOLEAN WatchTree);

NTSYSAPI
NTSTATUS
NTAPI
NtLoadDriver(
    _In_ PUNICODE_STRING DriverServiceName);

NTSYSAPI
NTSTATUS
NTAPI
NtUnloadDriver(
    _In_ PUNICODE_STRING DriverServiceName);

NTSYSAPI
NTSTATUS
NTAPI
NtLoadHotPatch(
    _In_ PUNICODE_STRING HotPatchName,
    _Reserved_ ULONG LoadFlag);

NTSYSAPI
NTSTATUS
NTAPI
NtManageHotPatch(
    _In_ ULONG HotPatchInformation,
    _In_ PVOID HotPatchData,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength);

/************************************************************************************
*
* Section API (+MemoryPartitions).
*
************************************************************************************/

#define MEM_EXECUTE_OPTION_ENABLE 0x1
#define MEM_EXECUTE_OPTION_DISABLE 0x2
#define MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION 0x4
#define MEM_EXECUTE_OPTION_PERMANENT 0x8
#define MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE 0x10
#define MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE 0x20
#define MEM_EXECUTE_OPTION_VALID_FLAGS 0x3f

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS {
    SystemMemoryPartitionInformation,
    SystemMemoryPartitionMoveMemory,
    SystemMemoryPartitionAddPagefile,
    SystemMemoryPartitionCombineMemory,
    SystemMemoryPartitionInitialAddMemory,
    SystemMemoryPartitionGetMemoryEvents,
    SystemMemoryPartitionSetAttributes,
    SystemMemoryPartitionNodeInformation,
    SystemMemoryPartitionCreateLargePages,
    SystemMemoryPartitionDedicatedMemoryInformation,
    SystemMemoryPartitionOpenDedicatedMemory,
    SystemMemoryPartitionMemoryChargeAttributes,
    SystemMemoryPartitionClearAttributes,
    SystemMemoryPartitionSetMemoryThresholds,
    SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS;

typedef struct _MEMORY_PARTITION_PAGE_RANGE {
    ULONG_PTR StartPage;
    ULONG_PTR NumberOfPages;
} MEMORY_PARTITION_PAGE_RANGE, *PMEMORY_PARTITION_PAGE_RANGE;

typedef struct _MEMORY_PARTITION_INITIAL_ADD_INFORMATION {
    ULONG Flags;
    ULONG NumberOfRanges;
    ULONG_PTR NumberOfPagesAdded;
    MEMORY_PARTITION_PAGE_RANGE PartitionRanges[1];
} MEMORY_PARTITION_INITIAL_ADD_INFORMATION, *PMEMORY_PARTITION_INITIAL_ADD_INFORMATION;

typedef struct _MEMORY_PARTITION_PAGE_COMBINE_INFORMATION {
    PVOID StopHandle;
    ULONG Flags;
    ULONG_PTR TotalNumberOfPages;
} MEMORY_PARTITION_PAGE_COMBINE_INFORMATION, *PMEMORY_PARTITION_PAGE_COMBINE_INFORMATION;

typedef struct _MEMORY_PARTITION_PAGEFILE_INFORMATION {
    UNICODE_STRING PageFileName;
    LARGE_INTEGER MinimumSize;
    LARGE_INTEGER MaximumSize;
    ULONG Flags;
} MEMORY_PARTITION_PAGEFILE_INFORMATION, *PMEMORY_PARTITION_PAGEFILE_INFORMATION;

typedef struct _MEMORY_PARTITION_TRANSFER_INFORMATION {
    ULONG_PTR NumberOfPages;
    ULONG NumaNode;
    ULONG Flags;
} MEMORY_PARTITION_TRANSFER_INFORMATION, *PMEMORY_PARTITION_TRANSFER_INFORMATION;

typedef struct _MEMORY_PARTITION_CONFIGURATION_INFORMATION {
    ULONG Flags;
    ULONG NumaNode;
    ULONG Channel;
    ULONG NumberOfNumaNodes;
    ULONG_PTR ResidentAvailablePages;
    ULONG_PTR CommittedPages;
    ULONG_PTR CommitLimit;
    ULONG_PTR PeakCommitment;
    ULONG_PTR TotalNumberOfPages;
    ULONG_PTR AvailablePages;
    ULONG_PTR ZeroPages;
    ULONG_PTR FreePages;
    ULONG_PTR StandbyPages;

    // Fields added RS1+
    ULONG_PTR StandbyPageCountByPriority[8];
    ULONG_PTR RepurposedPagesByPriority[8];
    ULONG_PTR MaximumCommitLimit;
    ULONG_PTR DonatedPagesToPartitions;
    ULONG PartitionId;
} MEMORY_PARTITION_CONFIGURATION_INFORMATION, * PMEMORY_PARTITION_CONFIGURATION_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle);

//taken from ph2
NTSYSAPI
NTSTATUS
NTAPI
NtCreateSectionEx(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect);

//taken from ph2
NTSYSAPI
NTSTATUS
NTAPI
NtMapViewOfSectionEx(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect,
    _Inout_updates_opt_(ParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount);

NTSYSAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress);

NTSYSAPI
NTSTATUS
NTAPI
NtUnmapViewOfSectionEx(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySection(
    _In_ HANDLE SectionHandle,
    _In_ SECTION_INFORMATION_CLASS SectionInformationClass,
    _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
    _In_ SIZE_T SectionInformationLength,
    _Out_opt_ PSIZE_T ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtExtendSection(
    _In_ HANDLE SectionHandle,
    _Inout_ PLARGE_INTEGER NewSectionSize);

NTSYSAPI
NTSTATUS
NTAPI
NtMapUserPhysicalPages(
    _In_ PVOID VirtualAddress,
    _In_ ULONG_PTR NumberOfPages,
    _In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray);

NTSYSAPI
NTSTATUS
NTAPI
NtMapUserPhysicalPagesScatter(
    _In_reads_(NumberOfPages) PVOID *VirtualAddresses,
    _In_ ULONG_PTR NumberOfPages,
    _In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray);

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateUserPhysicalPages(
    _In_ HANDLE ProcessHandle,
    _Inout_ PULONG_PTR NumberOfPages,
    _Out_writes_(*NumberOfPages) PULONG_PTR UserPfnArray);

NTSYSAPI
NTSTATUS
NTAPI
NtFreeUserPhysicalPages(
    _In_ HANDLE ProcessHandle,
    _Inout_ PULONG_PTR NumberOfPages,
    _In_reads_(*NumberOfPages) PULONG_PTR UserPfnArray);

NTSYSAPI
NTSTATUS
NTAPI
NtAreMappedFilesTheSame(
    _In_ PVOID File1MappedAsAnImage,
    _In_ PVOID File2MappedAsFile);

//
// NtCreatePartition
//

//
// 10248
//
typedef NTSTATUS(NTAPI* pfnNtCreatePartitionV1)(
    _Out_ PHANDLE PartitionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG PreferredNode);

//
// 10586
//
typedef NTSTATUS(NTAPI* pfnNtCreatePartitionV2)(
    _In_ HANDLE ParentPartitionHandle,
    _Out_ HANDLE* PartitionHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Node);

//
// Actual NtCreatePartition definition since Win10 10586
//
NTSYSAPI
NTSTATUS
NTAPI
NtCreatePartition(
    _In_ HANDLE ParentPartitionHandle,
    _Out_ HANDLE* PartitionHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Node);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenPartition(
    _Out_ PHANDLE PartitionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtManagePartition(
    _In_ HANDLE TargetHandle,
    _In_opt_ HANDLE SourceHandle,
    _In_ MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
    _Inout_updates_bytes_(PartitionInformationLength) PVOID PartitionInformation,
    _In_ ULONG PartitionInformationLength);

/************************************************************************************
*
* Token API.
*
************************************************************************************/
//
// This part is taken from PH ntseapi.h.
//

// Types

#define TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID 0x00
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64 0x01
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64 0x02
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING 0x03
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN 0x04
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_SID 0x05
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN 0x06
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING 0x10

// Flags

#define TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE 0x0001
#define TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE 0x0002
#define TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY 0x0004
#define TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT 0x0008
#define TOKEN_SECURITY_ATTRIBUTE_DISABLED 0x0010
#define TOKEN_SECURITY_ATTRIBUTE_MANDATORY 0x0020
#define TOKEN_SECURITY_ATTRIBUTE_COMPARE_IGNORE 0x0040

#define TOKEN_SECURITY_ATTRIBUTE_VALID_FLAGS ( \
    TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE | \
    TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE | \
    TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY | \
    TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT | \
    TOKEN_SECURITY_ATTRIBUTE_DISABLED | \
    TOKEN_SECURITY_ATTRIBUTE_MANDATORY)

#define TOKEN_SECURITY_ATTRIBUTE_CUSTOM_FLAGS 0xffff0000

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
    ULONG64 Version;
    UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
    PVOID pValue;
    ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
    UNICODE_STRING Name;
    USHORT ValueType;
    USHORT Reserved;
    ULONG Flags;
    ULONG ValueCount;
    union
    {
        PLONG64 pInt64;
        PULONG64 pUint64;
        PUNICODE_STRING pString;
        PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    } Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

#define TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1 1
#define TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
    USHORT Version;
    USHORT Reserved;
    ULONG AttributeCount;
    union
    {
        PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
    } Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

//
// endof ntseapi.h
//

NTSYSAPI
NTSTATUS
NTAPI
NtAccessCheck(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus);

NTSYSAPI
NTSTATUS
NTAPI
NtAccessCheckByType(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_reads_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus);

NTSYSAPI
NTSTATUS
NTAPI
NtAccessCheckByTypeResultList(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_reads_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccess,
    _Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatus);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenObjectAuditAlarm(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK GrantedAccess,
    _In_opt_ PPRIVILEGE_SET Privileges,
    _In_ BOOLEAN ObjectCreation,
    _In_ BOOLEAN AccessGranted,
    _Out_ PBOOLEAN GenerateOnClose);

NTSYSAPI
NTSTATUS
NTAPI
NtCloseObjectAuditAlarm(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ BOOLEAN GenerateOnClose);

NTSYSAPI
NTSTATUS
NTAPI
NtDeleteObjectAuditAlarm(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ BOOLEAN GenerateOnClose);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenProcessToken(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenProcessTokenEx(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtDuplicateToken(
    _In_ HANDLE ExistingTokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ BOOLEAN EffectiveOnly,
    _In_ TOKEN_TYPE TokenType,
    _Out_ PHANDLE NewTokenHandle);

#ifndef DISABLE_MAX_PRIVILEGE
#define DISABLE_MAX_PRIVILEGE   0x1 // winnt
#endif

#ifndef SANDBOX_INERT
#define SANDBOX_INERT           0x2 // winnt
#endif

#ifndef LUA_TOKEN
#define LUA_TOKEN               0x4 // winnt
#endif

#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED        0x8 // winnt
#endif

NTSYSAPI
NTSTATUS
NTAPI
NtFilterToken(
    _In_ HANDLE ExistingTokenHandle,
    _In_ ULONG Flags,
    _In_opt_ PTOKEN_GROUPS SidsToDisable,
    _In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
    _In_opt_ PTOKEN_GROUPS RestrictedSids,
    _Out_ PHANDLE NewTokenHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtImpersonateAnonymousToken(
    _In_ HANDLE ThreadHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength,
    _Out_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenThreadToken(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN OpenAsSelf,
    _Out_ PHANDLE TokenHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenThreadTokenEx(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN OpenAsSelf,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtAdjustPrivilegesToken(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES NewState,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtAdjustGroupsToken(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN ResetToDefault,
    _In_opt_ PTOKEN_GROUPS NewState,
    _In_opt_ ULONG BufferLength,
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_GROUPS PreviousState,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtCompareTokens(
    _In_ HANDLE FirstTokenHandle,
    _In_ HANDLE SecondTokenHandle,
    _Out_ PBOOLEAN Equal);

NTSYSAPI
NTSTATUS
NTAPI
NtPrivilegeCheck(
    _In_ HANDLE ClientToken,
    _Inout_ PPRIVILEGE_SET RequiredPrivileges,
    _Out_ PBOOLEAN Result);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateToken(
    _Out_ PHANDLE TokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ TOKEN_TYPE TokenType,
    _In_ PLUID AuthenticationId,
    _In_ PLARGE_INTEGER ExpirationTime,
    _In_ PTOKEN_USER User,
    _In_ PTOKEN_GROUPS Groups,
    _In_ PTOKEN_PRIVILEGES Privileges,
    _In_opt_ PTOKEN_OWNER Owner,
    _In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
    _In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
    _In_ PTOKEN_SOURCE TokenSource);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateTokenEx(
    _Out_ PHANDLE TokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ TOKEN_TYPE TokenType,
    _In_ PLUID AuthenticationId,
    _In_ PLARGE_INTEGER ExpirationTime,
    _In_ PTOKEN_USER User,
    _In_ PTOKEN_GROUPS Groups,
    _In_ PTOKEN_PRIVILEGES Privileges,
    _In_opt_ PVOID UserAttributes, // points to TOKEN_SECURITY_ATTRIBUTES_INFORMATION
    _In_opt_ PVOID DeviceAttributes, // points to PTOKEN_SECURITY_ATTRIBUTES_INFORMATION
    _In_opt_ PTOKEN_GROUPS DeviceGroups,
    _In_opt_ PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy,
    _In_opt_ PTOKEN_OWNER Owner,
    _In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
    _In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
    _In_ PTOKEN_SOURCE TokenSource);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateLowBoxToken(
    _Out_ PHANDLE TokenHandle,
    _In_ HANDLE ExistingTokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PSID PackageSid,
    _In_ ULONG CapabilityCount,
    _In_reads_opt_(CapabilityCount) PSID_AND_ATTRIBUTES Capabilities,
    _In_ ULONG HandleCount,
    _In_reads_opt_(HandleCount) HANDLE *Handles);

/************************************************************************************
*
* Registry API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtCreateKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateKeyTransacted(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _In_ HANDLE TransactionHandle,
    _Out_opt_ PULONG Disposition);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenKeyEx(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG OpenOptions);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenKeyTransacted(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE TransactionHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenKeyTransactedEx(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG OpenOptions,
    _In_ HANDLE TransactionHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryKey(
    _In_ HANDLE KeyHandle,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);

NTSYSAPI
NTSTATUS
NTAPI
NtEnumerateKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);

NTSYSAPI
NTSTATUS
NTAPI
NtEnumerateValueKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryMultipleValueKey(
    _In_ HANDLE KeyHandle,
    _Inout_updates_(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
    _In_ ULONG EntryCount,
    _Out_writes_bytes_(*BufferLength) PVOID ValueBuffer,
    _Inout_ PULONG BufferLength,
    _Out_opt_ PULONG RequiredBufferLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ ULONG TitleIndex,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize);

NTSYSAPI
NTSTATUS
NTAPI
NtDeleteKey(
    _In_ HANDLE KeyHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtDeleteValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName);

NTSYSAPI
NTSTATUS
NTAPI
NtRenameKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING NewName);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationKey(
    _In_ HANDLE KeyHandle,
    _In_ KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    _In_reads_bytes_(KeySetInformationLength) PVOID KeySetInformation,
    _In_ ULONG KeySetInformationLength);

NTSYSAPI
NTSTATUS
NTAPI
NtFlushKey(
    _In_ HANDLE KeyHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtCompressKey(
    _In_ HANDLE Key);

NTSYSAPI
NTSTATUS
NTAPI
NtLoadKey(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile);

NTSYSAPI
NTSTATUS
NTAPI
NtLoadKey2(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags);

//https://gist.github.com/tyranid/1db47869da253a912242c694e921009d#file-ntloadkeyex3-h

typedef enum _KEY_LOAD_HANDLE_TYPE {
    KeyLoadTrustKey = 1,
    KeyLoadEvent,
    KeyLoadToken
} KEY_LOAD_HANDLE_TYPE;

typedef struct _KEY_LOAD_HANDLE {
    KEY_LOAD_HANDLE_TYPE Type;
    HANDLE Handle;
} KEY_LOAD_HANDLE, *PKEY_LOAD_HANDLE;

NTSYSAPI
NTSTATUS
NTAPI
NtLoadKey3(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags,
    _In_ PKEY_LOAD_HANDLE LoadEntries,
    _In_ ULONG LoadEntryCount,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE RootHandle,
    _In_ PVOID Unused);

NTSYSAPI
NTSTATUS
NTAPI
NtLoadKeyEx(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags,
    _In_opt_ HANDLE TrustClassKey,
    _In_opt_ HANDLE Event,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE RootHandle,
    _Out_opt_ PIO_STATUS_BLOCK IoStatus);

NTSYSAPI
NTSTATUS
NTAPI
NtSaveKey(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE FileHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtSaveKeyEx(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE FileHandle,
    _In_ ULONG Format);

NTSYSAPI
NTSTATUS
NTAPI
NtUnloadKey(
    _In_ POBJECT_ATTRIBUTES TargetKey);

NTSYSAPI
NTSTATUS
NTAPI
NtUnloadKey2(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
NtUnloadKeyEx(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_opt_ HANDLE Event);

NTSYSAPI
NTSTATUS
NTAPI
NtNotifyChangeKey(
    _In_ HANDLE KeyHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG CompletionFilter,
    _In_ BOOLEAN WatchTree,
    _Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ BOOLEAN Asynchronous);

NTSYSAPI
NTSTATUS
NTAPI
NtLockRegistryKey(
    _In_ HANDLE KeyHandle);

NTSYSAPI
NTSTATUS
NTAPI 
NtCreateRegistryTransaction(
    _Out_ PHANDLE Handle,
    _In_ ACCESS_MASK DesiredAccess, //generic + TRANSACTION_*
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ DWORD Flags);

NTSYSAPI
NTSTATUS
NTAPI 
NtCommitRegistryTransaction(
    _In_ HANDLE RegistryHandle,
    _In_ BOOL Wait);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenRegistryTransaction(
    _Out_ PHANDLE RegistryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI 
NtRollbackRegistryTransaction(
    _In_ HANDLE RegistryHandle,
    _In_ BOOL Wait);


/************************************************************************************
*
* Job API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtAssignProcessToJobObject(
    _In_ HANDLE JobHandle,
    _In_ HANDLE ProcessHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateJobObject(
    _Out_ PHANDLE JobHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateJobSet(
    _In_ ULONG NumJob,
    _In_reads_(NumJob) PJOB_SET_ARRAY UserJobSet,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
NtIsProcessInJob(
    _In_ HANDLE ProcessHandle,
    _In_opt_ HANDLE JobHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenJobObject(
    _Out_ PHANDLE JobHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationJobObject(
    _In_opt_ HANDLE JobHandle,
    _In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
    _Out_writes_bytes_(JobObjectInformationLength) PVOID JobObjectInformation,
    _In_ ULONG JobObjectInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationJobObject(
    _In_ HANDLE JobHandle,
    _In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
    _In_reads_bytes_(JobObjectInformationLength) PVOID JobObjectInformation,
    _In_ ULONG JobObjectInformationLength);

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateJobObject(
    _In_ HANDLE JobHandle,
    _In_ NTSTATUS ExitStatus);

/************************************************************************************
*
* Session API.
*
************************************************************************************/

typedef struct _SESSION_OBJECT {
    KEVENT Event;
    PVOID SessionGlobal; //MM_SESSION_SPACE ptr
} SESSION_OBJECT, * PSESSION_OBJECT;

//taken from ph2

typedef enum _IO_SESSION_EVENT {
    IoSessionEventIgnore,
    IoSessionEventCreated,
    IoSessionEventTerminated,
    IoSessionEventConnected,
    IoSessionEventDisconnected,
    IoSessionEventLogon,
    IoSessionEventLogoff,
    IoSessionEventMax
} IO_SESSION_EVENT;

typedef enum _IO_SESSION_STATE {
    IoSessionStateCreated = 1,
    IoSessionStateInitialized,
    IoSessionStateConnected,
    IoSessionStateDisconnected,
    IoSessionStateDisconnectedLoggedOn,
    IoSessionStateLoggedOn,
    IoSessionStateLoggedOff,
    IoSessionStateTerminated,
    IoSessionStateMax
} IO_SESSION_STATE;

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSession(
    _Out_ PHANDLE SessionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtNotifyChangeSession(
    _In_ HANDLE SessionHandle,
    _In_ ULONG ChangeSequenceNumber,
    _In_ PLARGE_INTEGER ChangeTimeStamp,
    _In_ IO_SESSION_EVENT Event,
    _In_ IO_SESSION_STATE NewState,
    _In_ IO_SESSION_STATE PreviousState,
    _In_reads_bytes_opt_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize);

/************************************************************************************
*
* IO Completion API.
*
************************************************************************************/

typedef enum _IO_COMPLETION_INFORMATION_CLASS {
    IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

typedef struct _IO_COMPLETION_BASIC_INFORMATION {
    LONG Depth;
} IO_COMPLETION_BASIC_INFORMATION, *PIO_COMPLETION_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateIoCompletion(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Count);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenIoCompletion(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _In_ IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    _Out_writes_bytes_(IoCompletionInformationLength) PVOID IoCompletionInformation,
    _In_ ULONG IoCompletionInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation);

NTSYSAPI
NTSTATUS
NTAPI
NtSetIoCompletionEx(
    _In_ HANDLE IoCompletionHandle,
    _In_ HANDLE IoCompletionPacketHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation);

NTSYSAPI
NTSTATUS
NTAPI
NtRemoveIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _Out_ PVOID *KeyContext,
    _Out_ PVOID *ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER Timeout);

/************************************************************************************
*
* Transactions API.
*
************************************************************************************/

//TmTx
NTSYSAPI
NTSTATUS
NTAPI
NtCreateTransaction(
    _Out_ PHANDLE TransactionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ LPGUID Uow,
    _In_opt_ HANDLE TmHandle,
    _In_ ULONG CreateOptions,
    _In_ ULONG IsolationLevel,
    _In_ ULONG IsolationFlags,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_opt_ PUNICODE_STRING Description);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenTransaction(
    _Out_ PHANDLE TransactionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ LPGUID Uow,
    _In_opt_ HANDLE TmHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtRollbackTransaction(
    _In_ HANDLE TransactionHandle,
    _In_ BOOLEAN Wait);

NTSYSAPI
NTSTATUS
NTAPI
NtCommitTransaction(
    _In_ HANDLE TransactionHandle,
    _In_ BOOLEAN Wait);

NTSYSAPI
NTSTATUS
NTAPI
NtFreezeTransactions(
    _In_ PLARGE_INTEGER FreezeTimeout,
    _In_ PLARGE_INTEGER ThawTimeout);

NTSYSAPI
NTSTATUS
NTAPI
NtThawTransactions(
    VOID);

//TmRm
NTSYSAPI
NTSTATUS
NTAPI
NtCreateResourceManager(
    _Out_ PHANDLE ResourceManagerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE TmHandle,
    _In_opt_ LPGUID ResourceManagerGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG CreateOptions,
    _In_opt_ PUNICODE_STRING Description);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenResourceManager(
    _Out_ PHANDLE ResourceManagerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE TmHandle,
    _In_opt_ LPGUID ResourceManagerGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);

//TmEn
NTSYSAPI
NTSTATUS
NTAPI
NtCreateEnlistment(
    _Out_ PHANDLE EnlistmentHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ResourceManagerHandle,
    _In_ HANDLE TransactionHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG CreateOptions,
    _In_ NOTIFICATION_MASK NotificationMask,
    _In_opt_ PVOID EnlistmentKey);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenEnlistment(
    _Out_ PHANDLE EnlistmentHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ResourceManagerHandle,
    _In_ LPGUID EnlistmentGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);

//TmTm
NTSYSAPI
NTSTATUS
NTAPI
NtCreateTransactionManager(
    _Out_ PHANDLE TmHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PUNICODE_STRING LogFileName,
    _In_ ULONG CreateOptions,
    _In_ ULONG CommitStrength);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenTransactionManager(
    _Out_ PHANDLE TmHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PUNICODE_STRING LogFileName,
    _In_opt_ LPGUID TmIdentity,
    _In_ ULONG OpenOptions);

/************************************************************************************
*
* Performance Counter.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtQueryPerformanceCounter(
    _Out_ PLARGE_INTEGER PerformanceCounter,
    _Out_opt_ PLARGE_INTEGER PerformanceFrequency);

/************************************************************************************
*
* Process and Thread API.
*
************************************************************************************/

typedef struct _INITIAL_TEB
{
    struct
    {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, * PINITIAL_TEB;

#define PROCESS_GET_NEXT_FLAGS_PREVIOUS_PROCESS 0x00000001

#define QUEUE_USER_APC_FLAGS_NONE               0
#define QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC   1

//
// NtCreateProcessEx specific flags.
//
#define PS_REQUEST_BREAKAWAY        1
#define PS_NO_DEBUG_INHERIT         2
#define PS_INHERIT_HANDLES          4
#define PS_LARGE_PAGES              8
#define PS_ALL_FLAGS                (PS_REQUEST_BREAKAWAY | \
                                     PS_NO_DEBUG_INHERIT  | \
                                     PS_INHERIT_HANDLES   | \
                                     PS_LARGE_PAGES)

NTSYSAPI
NTSTATUS
NTAPI
NtGetNextProcess(
    _In_opt_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Flags,
    _Out_ PHANDLE NewProcessHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtGetNextThread(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Flags,
    _Out_ PHANDLE NewThreadHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateProcessEx(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort,
    _In_ BOOLEAN InJob);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_opt_ PVOID ProcessParameters,
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _Out_ PCLIENT_ID ClientId,
    _In_ PCONTEXT ThreadContext,
    _In_ PINITIAL_TEB InitialTeb,
    _In_ BOOLEAN CreateSuspended);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, //THREAD_CREATE_FLAGS_*
    _In_opt_ ULONG_PTR ZeroBits,
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId);

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateProcess(
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus);

NTSYSAPI
NTSTATUS
NTAPI
NtSuspendProcess(
    _In_ HANDLE ProcessHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtResumeProcess(
    _In_ HANDLE ProcessHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateProcessStateChange(
    _Out_ PHANDLE ProcessStateChangeHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_opt_ ULONG64 Reserved);

NTSYSAPI
NTSTATUS
NTAPI
NtChangeProcessState(
    _In_ HANDLE ProcessStateChangeHandle,
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_STATE_CHANGE_TYPE StateChangeType,
    _In_opt_ PVOID ExtendedInformation,
    _In_opt_ SIZE_T ExtendedInformationLength,
    _In_opt_ ULONG64 Reserved);

NTSYSAPI
NTSTATUS
NTAPI
NtSuspendThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount);

NTSYSAPI
NTSTATUS
NTAPI
NtResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateThreadStateChange(
    _Out_ PHANDLE ThreadStateChangeHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ThreadHandle,
    _In_opt_ ULONG64 Reserved);

NTSYSAPI
NTSTATUS
NTAPI
NtChangeThreadState(
    _In_ HANDLE ThreadStateChangeHandle,
    _In_ HANDLE ThreadHandle,
    _In_ THREAD_STATE_CHANGE_TYPE StateChangeType,
    _In_opt_ PVOID ExtendedInformation,
    _In_opt_ SIZE_T ExtendedInformationLength,
    _In_opt_ ULONG64 Reserved);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId);

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateThread(
    _In_opt_ HANDLE ThreadHandle,
    _In_ NTSTATUS ExitStatus);

NTSYSAPI
NTSTATUS
NTAPI
NtImpersonateThread(
    _In_ HANDLE ServerThreadHandle,
    _In_ HANDLE ClientThreadHandle,
    _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos);

NTSYSAPI
NTSTATUS
NTAPI
NtSetContextThread(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext);

NTSYSAPI
NTSTATUS
NTAPI
NtGetContextThread(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength);

typedef VOID(*PPS_APC_ROUTINE) (
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3);

NTSYSAPI
NTSTATUS
NTAPI
NtQueueApcThread(
    _In_ HANDLE ThreadHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3);

NTSYSAPI
NTSTATUS
NTAPI
NtQueueApcThreadEx(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE ReserveHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3);

NTSYSAPI
NTSTATUS
NTAPI
NtQueueApcThreadEx2(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE UserApcReserveHandle,
    _In_ ULONG QueueUserApcFlags, /*QUEUE_USER_APC_FLAGS*/
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_opt_ PVOID SystemArgument3);

NTSYSAPI
NTSTATUS
NTAPI
NtYieldExecution(
    VOID);

NTSYSAPI
NTSTATUS
NTAPI
NtTestAlert(
    VOID);

NTSYSAPI
NTSTATUS
NTAPI
NtAlertThread(
    _In_ HANDLE ThreadHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtAlertResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount);

NTSYSAPI
NTSTATUS
NTAPI
NtAlertThreadByThreadId(
    _In_ HANDLE ThreadId);

NTSYSAPI
NTSTATUS
NTAPI
NtWaitForAlertByThreadId(
    _In_ PVOID Address,
    _In_opt_ PLARGE_INTEGER Timeout);

NTSYSAPI
NTSTATUS
NTAPI
NtDelayExecution(
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER DelayInterval);

NTSYSAPI
ULONG
NTAPI
NtGetCurrentProcessorNumber(
    VOID);

/************************************************************************************
*
* License API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtQueryLicenseValue(
    _In_ PUNICODE_STRING ValueName,
    _Out_opt_ PULONG Type,
    _Out_writes_bytes_to_opt_(DataSize, *ResultDataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PULONG ResultDataSize);

/************************************************************************************
*
* Virtual Memory API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect);

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount);

NTSYSAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    _In_ ULONG_PTR NumberOfEntries,
    _In_reads_(NumberOfEntries) PMEMORY_RANGE_ENTRY VirtualAddresses,
    _In_reads_bytes_(VmInformationLength) PVOID VmInformation,
    _In_ ULONG VmInformationLength);

NTSYSAPI
NTSTATUS
NTAPI
NtReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead);

NTSYSAPI
NTSTATUS
NTAPI
NtReadVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten);

NTSYSAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);

#define MAP_PROCESS 1L
#define MAP_SYSTEM  2L

NTSYSAPI
NTSTATUS
NTAPI
NtLockVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG MapType);

NTSYSAPI
NTSTATUS
NTAPI
NtUnlockVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG MapType);

NTSTATUS
NTAPI
NtFlushVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _Out_ struct _IO_STATUS_BLOCK* IoStatus);

NTSYSAPI
NTSTATUS
NTAPI
NtFlushInstructionCache(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T Length);

NTSYSAPI
NTSTATUS
NTAPI
NtCreatePagingFile(
    _In_ PUNICODE_STRING PageFileName,
    _In_ PLARGE_INTEGER MinimumSize,
    _In_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG Priority);

/************************************************************************************
*
* Port API.
*
************************************************************************************/

typedef struct _PORT_VIEW {

    ULONG  Length;                      // Size of this structure
    HANDLE SectionHandle;               // Handle to section object with
                                        // SECTION_MAP_WRITE and SECTION_MAP_READ
    ULONG  SectionOffset;               // The offset in the section to map a view for
                                        // the port data area. The offset must be aligned 
                                        // with the allocation granularity of the system.
    SIZE_T ViewSize;                    // The size of the view (in bytes)
    PVOID  ViewBase;                    // The base address of the view in the creator
                                        // 
    PVOID  ViewRemoteBase;              // The base address of the view in the process
                                        // connected to the port.
} PORT_VIEW, * PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW {

    ULONG  Length;                      // Size of this structure
    SIZE_T ViewSize;                    // The size of the view (bytes)
    PVOID  ViewBase;                    // Base address of the view

} REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;

typedef struct _PORT_MESSAGE {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;       // Force quadword alignment
    } u3;
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;               // Only valid on LPC_CONNECTION_REQUEST message
        ULONG CallbackId;                   // Only valid on LPC_REQUEST message
    } u4;
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _PORT_MESSAGE32 {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID32 ClientId;
        double DoNotUseThisField;       // Force quadword alignment
    } u3;
    ULONG MessageId;
    union {
        ULONG ClientViewSize;               // Only valid on LPC_CONNECTION_REQUEST message
        ULONG CallbackId;                   // Only valid on LPC_REQUEST message
    } u4;
} PORT_MESSAGE32, * PPORT_MESSAGE32;

typedef struct _PORT_MESSAGE64
{
    union
    {
        struct
        {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        CLIENT_ID64 ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        ULONGLONG ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
        ULONG CallbackId; // only valid for LPC_REQUEST messages
    };
} PORT_MESSAGE64, * PPORT_MESSAGE64;

typedef struct _PORT_DATA_ENTRY {
    PVOID Base;
    ULONG Size;
} PORT_DATA_ENTRY, *PPORT_DATA_ENTRY;

typedef struct _PORT_DATA_INFORMATION {
    ULONG CountDataEntries;
    PORT_DATA_ENTRY DataEntries[1];
} PORT_DATA_INFORMATION, *PPORT_DATA_INFORMATION;

#ifndef InitializeMessageHeader
#define InitializeMessageHeader(ph, l, t)                              \
{                                                                      \
    (ph)->u1.s1.TotalLength      = (USHORT)(l);                        \
    (ph)->u1.s1.DataLength       = (USHORT)(l - sizeof(PORT_MESSAGE)); \
    (ph)->u2.s2.Type             = (USHORT)(t);                        \
    (ph)->u2.s2.DataInfoOffset   = 0;                                  \
    (ph)->ClientId.UniqueProcess = NULL;                               \
    (ph)->ClientId.UniqueThread  = NULL;                               \
    (ph)->MessageId              = 0;                                  \
    (ph)->ClientViewSize         = 0;                                  \
}
#endif

#define LPC_REQUEST                 1
#define LPC_REPLY                   2
#define LPC_DATAGRAM                3
#define LPC_LOST_REPLY              4
#define LPC_PORT_CLOSED             5
#define LPC_CLIENT_DIED             6
#define LPC_EXCEPTION               7
#define LPC_DEBUG_EVENT             8
#define LPC_ERROR_EVENT             9
#define LPC_CONNECTION_REQUEST      10
#define LPC_CONTINUATION_REQUIRED   0x2000


#define PORT_VALID_OBJECT_ATTRIBUTES (OBJ_CASE_INSENSITIVE)
#define PORT_MAXIMUM_MESSAGE_LENGTH 256

typedef struct _LPC_CLIENT_DIED_MSG {
    PORT_MESSAGE PortMsg;
    LARGE_INTEGER CreateTime;
} LPC_CLIENT_DIED_MSG, *PLPC_CLIENT_DIED_MSG;

NTSYSAPI
NTSTATUS
NTAPI
NtCreatePort(
    _Out_ PHANDLE PortHandle,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG MaxConnectionInfoLength,
    _In_ ULONG MaxMessageLength,
    _In_ ULONG MaxPoolUsage);

NTSYSAPI
NTSTATUS
NTAPI
NtCompleteConnectPort(
    _In_ HANDLE PortHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtListenPort(
    _In_ HANDLE PortHandle,
    _Out_ PPORT_MESSAGE ConnectionRequest);

NTSYSAPI
NTSTATUS
NTAPI
NtReplyPort(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE ReplyMessage);

NTSYSAPI
NTSTATUS
NTAPI
NtReplyWaitReplyPort(
    _In_ HANDLE PortHandle,
    _Inout_ PPORT_MESSAGE ReplyMessage);

NTSYSAPI
NTSTATUS
NTAPI
NtRequestPort(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE RequestMessage);

NTSYSAPI
NTSTATUS
NTAPI
NtRequestWaitReplyPort(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE RequestMessage,
    _Out_ PPORT_MESSAGE ReplyMessage);

NTSYSAPI
NTSTATUS
NTAPI
NtClosePort(
    _In_ HANDLE PortHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtReplyWaitReceivePort(
    _In_ HANDLE PortHandle,
    _Out_opt_ PVOID *PortContext,
    _In_opt_ PPORT_MESSAGE ReplyMessage,
    _Out_ PPORT_MESSAGE ReceiveMessage);

NTSYSAPI
NTSTATUS
NTAPI
NtWriteRequestData(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE Message,
    _In_ ULONG DataEntryIndex,
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesWritten);

NTSYSAPI
NTSTATUS
NTAPI
NtReadRequestData(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE Message,
    _In_ ULONG DataEntryIndex,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

NTSYSAPI
NTSTATUS
NTAPI
NtConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    _Inout_opt_ PPORT_VIEW ClientView,
    _Out_opt_ PREMOTE_PORT_VIEW ServerView,
    _Out_opt_ PULONG MaxMessageLength,
    _Inout_opt_	PVOID ConnectionInformation,
    _Inout_opt_	PULONG ConnectionInformationLength);

NTSYSAPI
NTSTATUS
NTAPI
NtAcceptConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_opt_ PVOID PortContext,
    _In_ PPORT_MESSAGE ConnectionRequest,
    _In_ BOOLEAN AcceptConnection,
    _Inout_opt_ PPORT_VIEW ServerView,
    _Out_opt_ PREMOTE_PORT_VIEW ClientView);

NTSYSAPI
NTSTATUS
NTAPI
NtSecureConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    _Inout_opt_ PPORT_VIEW ClientView,
    _In_opt_ PSID RequiredServerSid,
    _Inout_opt_ PREMOTE_PORT_VIEW ServerView,
    _Out_opt_ PULONG MaxMessageLength,
    _Inout_opt_ PVOID ConnectionInformation,
    _Inout_opt_ PULONG ConnectionInformationLength);

/************************************************************************************
*
* Boot Management API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtEnumerateBootEntries(
    _Out_writes_bytes_opt_(*BufferLength) PVOID Buffer,
    _Inout_ PULONG BufferLength);

/************************************************************************************
*
* Reserve Objects API.
*
************************************************************************************/

typedef enum _MEMORY_RESERVE_TYPE {
    MemoryReserveUserApc,
    MemoryReserveIoCompletion,
    MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE;

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateReserveObject(
    _Out_ PHANDLE MemoryReserveHandle,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ MEMORY_RESERVE_TYPE Type);

/************************************************************************************
*
* Debug API.
*
************************************************************************************/

//
// Define the debug object thats used to attatch to processes that are being debugged.
//
#define DEBUG_OBJECT_DELETE_PENDING (0x1) // Debug object is delete pending.
#define DEBUG_OBJECT_KILL_ON_CLOSE  (0x2) // Kill all debugged processes on close

typedef struct _DEBUG_OBJECT {
    //
    // Event thats set when the EventList is populated.
    //
    KEVENT EventsPresent;
    //
    // Mutex to protect the structure
    //
    FAST_MUTEX Mutex;
    //
    // Queue of events waiting for debugger intervention
    //
    LIST_ENTRY EventList;
    //
    // Flags for the object
    //
    ULONG Flags;
} DEBUG_OBJECT, *PDEBUG_OBJECT;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateDebugObject(
    _Out_ PHANDLE DebugObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
NtDebugActiveProcess(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtRemoveProcessDebug(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);

/************************************************************************************
*
* Profile API.
*
************************************************************************************/

typedef enum _KPROFILE_SOURCE {
    ProfileTime,
    ProfileAlignmentFixup,
    ProfileTotalIssues,
    ProfilePipelineDry,
    ProfileLoadInstructions,
    ProfilePipelineFrozen,
    ProfileBranchInstructions,
    ProfileTotalNonissues,
    ProfileDcacheMisses,
    ProfileIcacheMisses,
    ProfileCacheMisses,
    ProfileBranchMispredictions,
    ProfileStoreInstructions,
    ProfileFpInstructions,
    ProfileIntegerInstructions,
    Profile2Issue,
    Profile3Issue,
    Profile4Issue,
    ProfileSpecialInstructions,
    ProfileTotalCycles,
    ProfileIcacheIssues,
    ProfileDcacheAccesses,
    ProfileMemoryBarrierCycles,
    ProfileLoadLinkedIssues,
    ProfileMaximum
} KPROFILE_SOURCE;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateProfile(
    _Out_ PHANDLE ProfileHandle,
    _In_opt_ HANDLE Process,
    _In_ PVOID ProfileBase,
    _In_ SIZE_T ProfileSize,
    _In_ ULONG BucketSize,
    _In_reads_bytes_(BufferSize) PULONG Buffer,
    _In_ ULONG BufferSize,
    _In_ KPROFILE_SOURCE ProfileSource,
    _In_ KAFFINITY Affinity);

NTSYSAPI
NTSTATUS
NTAPI
NtStartProfile(
    _In_ HANDLE ProfileHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtStopProfile(
    _In_ HANDLE ProfileHandle);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryIntervalProfile(
    _In_ KPROFILE_SOURCE ProfileSource,
    _Out_ PULONG Interval);

NTSYSAPI
NTSTATUS
NTAPI
NtSetIntervalProfile(
    _In_ ULONG Interval,
    _In_ KPROFILE_SOURCE Source);

/************************************************************************************
*
* Worker Factory API.
*
************************************************************************************/

typedef enum _WORKERFACTORYINFOCLASS {
    WorkerFactoryTimeout,
    WorkerFactoryRetryTimeout,
    WorkerFactoryIdleTimeout,
    WorkerFactoryBindingCount,
    WorkerFactoryThreadMinimum,
    WorkerFactoryThreadMaximum,
    WorkerFactoryPaused,
    WorkerFactoryBasicInformation,
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation,
    WorkerFactoryThreadBasePriority,
    WorkerFactoryTimeoutWaiters,
    WorkerFactoryFlags,
    WorkerFactoryThreadSoftMaximum,
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

typedef struct _WORKER_FACTORY_BASIC_INFORMATION {
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, *PWORKER_FACTORY_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateWorkerFactory(
    _Out_ PHANDLE WorkerFactoryHandleReturn,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE CompletionPortHandle,
    _In_ HANDLE WorkerProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID StartParameter,
    _In_opt_ ULONG MaxThreadCount,
    _In_opt_ SIZE_T StackReserve,
    _In_opt_ SIZE_T StackCommit);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationWorkerFactory(
    _In_ HANDLE WorkerFactoryHandle,
    _In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _Out_writes_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtShutdownWorkerFactory(
    _In_ HANDLE WorkerFactoryHandle,
    _Inout_ volatile LONG *PendingWorkerCount);

NTSYSAPI
NTSTATUS
NTAPI
NtReleaseWorkerFactoryWorker(
    _In_ HANDLE WorkerFactoryHandle);

/************************************************************************************
*
* Event Tracing API.
*
************************************************************************************/

typedef enum _TRACE_CONTROL_INFORMATION_CLASS {
    TraceControlStartLogger = 1,
    TraceControlStopLogger = 2,
    TraceControlQueryLogger = 3,
    TraceControlUpdateLogger = 4,
    TraceControlFlushLogger = 5,
    TraceControlIncrementLoggerFile = 6,
    TraceControlInvalidClass1 = 7,
    TraceControlInvalidCalss2 = 8,
    TraceControlInvalidClass3 = 9,
    TraceControlInvalidClass4 = 10,
    TraceControlRealtimeConnect = 11,
    TraceControlWdiDispatchControl = 13,
    TraceControlRealtimeDisconnectConsumerByHandle = 14,
    TraceControlReceiveNotification = 16,
    TraceControlEnableGuid = 17,
    TraceControlSendReplyDataBlock = 18,
    TraceControlReceiveReplyDataBlock = 19,
    TraceControlWdiUpdateSem = 20,
    TraceControlGetTraceGuidList = 21,
    TraceControlGetTraceGuidInfo = 22,
    TraceControlEnumerateTraceGuids = 23,
    TraceControlInvalidClass5 = 24,
    TraceControlQueryReferenceTime = 25,
    TraceControlTrackProviderBinary = 26,
    TraceControlAddNotificationEvent = 27,
    TraceControlUpdateDisallowList = 28,
    TraceControlInvalidClass6 = 29,
    TraceControlInvalidClass7 = 30,
    TraceControlUseDescriptorTypeUm = 31,
    TraceControlGetTraceGroupList = 32,
    TraceControlGetTraceGroupInfo = 33,
    TraceControlTraceSetDisallowList = 34,
    TraceControlSetCompressionSettings = 35,
    TraceControlGetCompressionSettings = 36,
    TraceControlUpdatePeriodicCaptureState = 37,
    TraceControlGetPrivateSessionTraceHandle = 38,
    TraceControlRegisterPrivateSession = 39,
    TraceControlQuerySessionDemuxObject = 40,
    TraceControlSetProviderBinaryTracking = 41,
    TraceControlMaxLoggers = 42,
    TraceControlMaxPmcCounter = 43
} TRACE_CONTROL_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS
NTAPI
NtTraceEvent(
    _In_ HANDLE TraceHandle,
    _In_ ULONG Flags,
    _In_ ULONG FieldSize,
    _In_ PVOID Fields);

NTSYSAPI
NTSTATUS
NTAPI
NtTraceControl(
    _In_ TRACE_CONTROL_INFORMATION_CLASS TraceInformationClass,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(TraceInformationLength) PVOID TraceInformation,
    _In_ ULONG TraceInformationLength,
    _Out_ PULONG ReturnLength);

/************************************************************************************
*
* Enclave API.
*
************************************************************************************/

#ifndef _WIN32_WINNT_WIN10
#define _WIN32_WINNT_WIN10 0x0A00
#endif
#if (_WIN32_WINNT < _WIN32_WINNT_WIN10)
typedef LPVOID(WINAPI* PENCLAVE_ROUTINE) (LPVOID lpThreadParameter);
typedef PENCLAVE_ROUTINE LPENCLAVE_ROUTINE;
#endif

NTSYSAPI
NTSTATUS
NTAPI
NtCreateEnclave(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T Size,
    _In_ SIZE_T InitialCommitment,
    _In_ ULONG EnclaveType,
    _In_reads_bytes_(EnclaveInformationLength) PVOID EnclaveInformation,
    _In_ ULONG EnclaveInformationLength,
    _Out_opt_ PULONG EnclaveError);

NTSYSAPI
NTSTATUS
NTAPI
NtLoadEnclaveData(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _In_ ULONG Protect,
    _In_reads_bytes_(PageInformationLength) PVOID PageInformation,
    _In_ ULONG PageInformationLength,
    _Out_opt_ PSIZE_T NumberOfBytesWritten,
    _Out_opt_ PULONG EnclaveError);

NTSYSAPI
NTSTATUS
NTAPI
NtInitializeEnclave(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_reads_bytes_(EnclaveInformationLength) PVOID EnclaveInformation,
    _In_ ULONG EnclaveInformationLength,
    _Out_opt_ PULONG EnclaveError);

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateEnclave(
    _In_ PVOID BaseAddress,
    _In_ BOOLEAN WaitForThread);

NTSYSAPI
NTSTATUS
NTAPI
NtCallEnclave(
    _In_ PENCLAVE_ROUTINE Routine,
    _In_ PVOID Parameter,
    _In_ BOOLEAN WaitForThread,
    _Out_opt_ PVOID* ReturnValue);


/************************************************************************************
*
* LUID/UUID API.
*
************************************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtSetUuidSeed(
    _In_ PCHAR Seed);

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateUuids(
    _Out_ PULARGE_INTEGER Time,
    _Out_ PULONG Range,
    _Out_ PULONG Sequence,
    _Out_ PCHAR Seed);

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateLocallyUniqueId(
    _Out_ PLUID Luid);


/************************************************************************************
*
* Kernel Debugger API.
*
************************************************************************************/

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX {
    BOOLEAN DebuggerAllowed;
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

typedef enum _SYSDBG_COMMAND {
    SysDbgQueryModuleInformation,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall,
    SysDbgClearSpecialCalls,
    SysDbgQuerySpecialCalls,
    SysDbgBreakPoint,
    SysDbgQueryVersion,
    SysDbgReadVirtual,
    SysDbgWriteVirtual,
    SysDbgReadPhysical,
    SysDbgWritePhysical,
    SysDbgReadControlSpace,
    SysDbgWriteControlSpace,
    SysDbgReadIoSpace,
    SysDbgWriteIoSpace,
    SysDbgReadMsr,
    SysDbgWriteMsr,
    SysDbgReadBusData,
    SysDbgWriteBusData,
    SysDbgCheckLowMemory,
    SysDbgEnableKernelDebugger,
    SysDbgDisableKernelDebugger,
    SysDbgGetAutoKdEnable,
    SysDbgSetAutoKdEnable,
    SysDbgGetPrintBufferSize,
    SysDbgSetPrintBufferSize,
    SysDbgGetKdUmExceptionEnable,
    SysDbgSetKdUmExceptionEnable,
    SysDbgGetTriageDump,
    SysDbgGetKdBlockEnable,
    SysDbgSetKdBlockEnable,
    SysDbgRegisterForUmBreakInfo,
    SysDbgGetUmBreakPid,
    SysDbgClearUmBreakPid,
    SysDbgGetUmAttachPid,
    SysDbgClearUmAttachPid,
    SysDbgGetLiveKernelDump,
    SysDbgKdPullRemoteFile,
    SysDbgMaxInfoClass
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef struct _SYSDBG_VIRTUAL {
    PVOID Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

NTSYSAPI
NTSTATUS
NTAPI
NtSystemDebugControl(
    _In_ SYSDBG_COMMAND Command,
    _Inout_updates_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG ReturnLength);

/************************************************************************************
*
* Application Verifier API and definitions.
*
************************************************************************************/

#ifndef DLL_PROCESS_VERIFIER
#define DLL_PROCESS_VERIFIER 4
#endif

typedef VOID(NTAPI *RTL_VERIFIER_DLL_LOAD_CALLBACK)(
    PWSTR DllName,
    PVOID DllBase,
    SIZE_T DllSize,
    PVOID Reserved);

typedef VOID(NTAPI *RTL_VERIFIER_DLL_UNLOAD_CALLBACK)(
    PWSTR DllName,
    PVOID DllBase,
    SIZE_T DllSize,
    PVOID Reserved);

typedef VOID(NTAPI *RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK)(
    PVOID AllocationBase,
    SIZE_T AllocationSize);

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
    PCHAR ThunkName;
    PVOID ThunkOldAddress;
    PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
    PWCHAR DllName;
    DWORD DllFlags;
    PVOID DllAddress;
    PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
    DWORD Length;
    PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
    RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
    RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;
    PWSTR VerifierImage;
    DWORD VerifierFlags;
    DWORD VerifierDebug;
    PVOID RtlpGetStackTraceAddress;
    PVOID RtlpDebugPageHeapCreate;
    PVOID RtlpDebugPageHeapDestroy;
    RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;

//
// Application verifier standard flags.
//
#define RTL_VRF_FLG_FULL_PAGE_HEAP                   0x00000001
#define RTL_VRF_FLG_RESERVED_DONOTUSE                0x00000002
#define RTL_VRF_FLG_HANDLE_CHECKS                    0x00000004
#define RTL_VRF_FLG_STACK_CHECKS                     0x00000008
#define RTL_VRF_FLG_APPCOMPAT_CHECKS                 0x00000010
#define RTL_VRF_FLG_TLS_CHECKS                       0x00000020
#define RTL_VRF_FLG_DIRTY_STACKS                     0x00000040
#define RTL_VRF_FLG_RPC_CHECKS                       0x00000080
#define RTL_VRF_FLG_COM_CHECKS                       0x00000100
#define RTL_VRF_FLG_DANGEROUS_APIS                   0x00000200
#define RTL_VRF_FLG_RACE_CHECKS                      0x00000400
#define RTL_VRF_FLG_DEADLOCK_CHECKS                  0x00000800
#define RTL_VRF_FLG_FIRST_CHANCE_EXCEPTION_CHECKS    0x00001000
#define RTL_VRF_FLG_VIRTUAL_MEM_CHECKS               0x00002000
#define RTL_VRF_FLG_ENABLE_LOGGING                   0x00004000
#define RTL_VRF_FLG_FAST_FILL_HEAP                   0x00008000
#define RTL_VRF_FLG_VIRTUAL_SPACE_TRACKING           0x00010000
#define RTL_VRF_FLG_ENABLED_SYSTEM_WIDE              0x00020000
#define RTL_VRF_FLG_MISCELLANEOUS_CHECKS             0x00020000
#define RTL_VRF_FLG_LOCK_CHECKS                      0x00040000

NTSYSAPI
VOID
NTAPI
RtlApplicationVerifierStop(
    _In_ ULONG_PTR Code,
    _In_ PSTR Message,
    _In_ ULONG_PTR Param1,
    _In_ PSTR Description1,
    _In_ ULONG_PTR Param2,
    _In_ PSTR Description2,
    _In_ ULONG_PTR Param3,
    _In_ PSTR Description3,
    _In_ ULONG_PTR Param4,
    _In_ PSTR Description4);

#ifndef VERIFIER_STOP
#define VERIFIER_STOP(Code, Msg, P1, S1, P2, S2, P3, S3, P4, S4) {  \
        RtlApplicationVerifierStop ((Code),                         \
                                    (Msg),                          \
                                    (ULONG_PTR)(P1),(S1),           \
                                    (ULONG_PTR)(P2),(S2),           \
                                    (ULONG_PTR)(P3),(S3),           \
                                    (ULONG_PTR)(P4),(S4));          \
  }
#endif

//
// NTOS_RTL HEADER END
//

#ifdef __cplusplus
}
#endif

#pragma warning(pop)

#endif NTOS_RTL
