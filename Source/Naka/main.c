/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     2.70
*
*  DATE:        22 Mar 2017
*
*  Naka, support payload compressor.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#include <Windows.h>
#include <ntstatus.h>
#include "shared\ntos.h"
#include "shared\minirtl.h"
#include "shared\cmdline.h"
#include "shared\_filename.h"

ULONG g_XorKey = 'naka';

/*
* EncodeBuffer
*
* Purpose:
*
* Decrypt/Encrypt given buffer.
*
*/
VOID EncodeBuffer(
    PVOID Buffer,
    ULONG BufferSize
)
{
    ULONG k, c;
    PUCHAR ptr;

    if ((Buffer == NULL) || (BufferSize == 0))
        return;

    k = g_XorKey;
    c = BufferSize;
    ptr = Buffer;

    do {
        *ptr ^= k;
        k = _rotl(k, 1);
        ptr++;
        --c;
    } while (c != 0);
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
* CompressBufferLZNT1
*
* Purpose:
*
* Compress given buffer with LZ algorithm.
*
* Use VirtualFree to release returned buffer when it no longer needed.
*
*/
PUCHAR CompressBufferLZNT1(
    _In_ PUCHAR SrcBuffer,
    _In_ ULONG SrcSize,
    _Inout_ PULONG FinalCompressedSize
)
{
    BOOL cond = FALSE;
    NTSTATUS status;
    ULONG CompressedSize = 0;
    ULONG CompressBufferWorkSpaceSize = 0;
    ULONG CompressFragmentWorkSpaceSize = 0;
    ULONG CompBufferSize = 0;
    PVOID WorkSpace = NULL;
    PUCHAR CompBuffer = NULL;

    if (FinalCompressedSize == NULL)
        return NULL;

    do {

        status = RtlGetCompressionWorkSpaceSize(
            COMPRESSION_FORMAT_LZNT1,
            &CompressBufferWorkSpaceSize,
            &CompressFragmentWorkSpaceSize
        );

        //accept nothing but STATUS_SUCCESS
        if (status != STATUS_SUCCESS) {
            break;
        }

        WorkSpace = (PVOID)VirtualAlloc(NULL, CompressBufferWorkSpaceSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (WorkSpace == NULL) {
            break;
        }

        //original size + safe buffer + sizeof header
        CompBufferSize = (ULONG)(SrcSize + 0x1000 + sizeof(ULONG));
        CompBuffer = (PUCHAR)VirtualAlloc(NULL, CompBufferSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (CompBuffer == NULL) {
            break;
        }

        CompressedSize = 0;
        status = RtlCompressBuffer(
            COMPRESSION_FORMAT_LZNT1,
            SrcBuffer,
            SrcSize,
            &CompBuffer[4],
            CompBufferSize,
            4096,
            &CompressedSize,
            WorkSpace
        );

        if (status != STATUS_SUCCESS) {
            VirtualFree(CompBuffer, 0, MEM_RELEASE);
            CompBuffer = NULL;
            break;
        }

        *(PULONG)&CompBuffer[0] = SrcSize;//save original size
        CompressedSize += sizeof(ULONG); //add header size
        *FinalCompressedSize = CompressedSize;

    } while (cond);

    if (WorkSpace != NULL) {
        VirtualFree(WorkSpace, 0, MEM_RELEASE);
    }

    return CompBuffer;
}

void CompressPayload(
    LPWSTR lpInputFile
)
{
    BOOL bCond = FALSE;
    PUCHAR Data = NULL, FileData = NULL;
    ULONG FinalCompressedSize = 0, r = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LPWSTR NewName = NULL;
    SIZE_T sz = 0;
    LARGE_INTEGER FileSize;

    do {
        if (lpInputFile == NULL)
            break;

        sz = _strlen(lpInputFile) * sizeof(WCHAR);
        NewName = LocalAlloc(LPTR, sz);
        if (NewName == NULL)
            break;

        hFile = CreateFile(lpInputFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            break;

        FileSize.QuadPart = 0;
        if (!GetFileSizeEx(hFile, &FileSize))
            break;

        if (FileSize.QuadPart == 0)
            break;

        FileData = LocalAlloc(LPTR, (SIZE_T)FileSize.LowPart);
        if (FileData == NULL)
            break;

        if (!ReadFile(hFile, FileData, FileSize.LowPart, (LPDWORD)&r, NULL))
            break;

        Data = CompressBufferLZNT1((PUCHAR)FileData, r, &FinalCompressedSize);
        if (Data) {
            EncodeBuffer(Data, FinalCompressedSize);
            if (_filename_noext(NewName, lpInputFile)) {
                _strcat(NewName, TEXT(".cd"));
                supWriteBufferToFile(NewName, Data, FinalCompressedSize);
            }
            VirtualFree(Data, 0, MEM_RELEASE);
        }

    } while (bCond);

    if (NewName != NULL)
        LocalFree(NewName);
    if (FileData != NULL)
        LocalFree(FileData);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

}

void main()
{
    LPWSTR  lpInputFile = NULL;
    LPWSTR *szArglist;
    INT     nArgs = 0;

    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist) {
        if (nArgs > 1) {
            lpInputFile = szArglist[1];
            if (nArgs > 2) {
                g_XorKey = strtoul(szArglist[2]);
            }
            if (lpInputFile) {
                CompressPayload(lpInputFile);
            }
        }
        else {
            MessageBox(GetDesktopWindow(), TEXT("Input file not specified"), TEXT("Naka"), MB_ICONINFORMATION);
        }

        LocalFree(szArglist);
    }

    ExitProcess(0);
}
