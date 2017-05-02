/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       SIREFEF.H
*
*  VERSION:     2.71
*
*  DATE:        19 Apr 2017
*
*  Prototypes and definitions for Sirefef/ZeroAccess method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef BOOL(NTAPI *pfnSfCopyFileElevated)(
    LPWSTR SourceFileName,
    LPWSTR DestinationDir);

typedef BOOL(NTAPI *pfnCopyFileW)(
    _In_ LPCWSTR lpExistingFileName,
    _In_ LPCWSTR lpNewFileName,
    _In_ BOOL bFailIfExists);

typedef NTSTATUS(NTAPI *pfnNtAllocateVirtualMemory)(
    _In_        HANDLE ProcessHandle,
    _Inout_     PVOID *BaseAddress,
    _In_        ULONG_PTR ZeroBits,
    _Inout_     PSIZE_T RegionSize,
    _In_        ULONG AllocationType,
    _In_        ULONG Protect);

typedef NTSTATUS(NTAPI *pfnNtTerminateProcess)(
    _In_opt_	HANDLE ProcessHandle,
    _In_		NTSTATUS ExitStatus);

typedef NTSTATUS(NTAPI *pfnNtClose)(
    _In_ HANDLE Handle);

typedef HANDLE(NTAPI *pfnCreateRemoteThread)(
    _In_ HANDLE hProcess,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ LPVOID lpParameter,
    _In_ DWORD dwCreationFlags,
    _Out_opt_ LPDWORD lpThreadId);

#pragma warning(suppress: 28301)
typedef DWORD(WINAPI *pfnWaitForSingleObject)(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds);

typedef BOOL(WINAPI *pfnCreateProcessW)(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL(WINAPI *pfnWriteProcessMemory)(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T * lpNumberOfBytesWritten);

typedef HANDLE(NTAPI *pfnRunProcessEx)(
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _Out_opt_ HANDLE *PrimaryThread,
    _Inout_opt_ LPWSTR lpApplicationName);


typedef struct _ZA_CONTROL_CONTEXT {

    //encoded pointers
    pfnSfCopyFileElevated SfCopyFile;

    pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory;
    pfnNtClose pNtClose;
    pfnNtTerminateProcess pNtTerminateProcess;

    pfnCopyFileW pCopyFileW;
    pfnCreateRemoteThread pCreateRemoteThread;
    pfnWaitForSingleObject pWaitForSingleObject;
    pfnWriteProcessMemory pWriteProcessMemory;

    LPVOID ElevatedProcedure;
    pfnRunProcessEx RunProcessEx;

    //parameters
    ELOAD_PARAMETERS_SIREFEF *ElevatedParameters;

    //data buffers
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];

} ZA_CONTROL_CONTEXT, *PZA_CONTROL_CONTEXT;
