/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       COMPRESS.C
*
*  VERSION:     2.10
*
*  DATE:        16 Apr 2016
*
*  Compression support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#ifndef _DEBUG
#undef GENERATE_COMPRESSED_PAYLOAD
#else
#ifdef _WIN64
#include "modules\hibiki64.h"
#include "modules\fubuki64.h"
#include "modules\kongou64.h"
#else
#include "modules\hibiki32.h"
#include "modules\fubuki32.h"
#include "modules\kongou32.h"
#endif
#endif

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

    k = AKAGI_XOR_KEY;
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
        CompBufferSize = SrcSize + 0x1000 + sizeof(ULONG);
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

/*
* DecompressBufferLZNT1
*
* Purpose:
*
* Decompress buffer compressed with LZ algorithm.
*
* Use VirtualFree to release returned buffer when it no longer needed.
*
*/
PUCHAR DecompressBufferLZNT1(
    _In_ PUCHAR CompBuffer,
    _In_ ULONG CompSize,
    _In_ ULONG UncompressedBufferSize,
    _Inout_ PULONG FinalUncompressedSize
    )
{
    PUCHAR UncompBuffer = NULL;
    NTSTATUS status;

    UncompBuffer = (PUCHAR)VirtualAlloc(NULL, UncompressedBufferSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (UncompBuffer == NULL) {
        return NULL;
    }

    status = RtlDecompressBuffer(
        COMPRESSION_FORMAT_LZNT1,
        UncompBuffer,
        UncompressedBufferSize,
        CompBuffer,
        CompSize,
        FinalUncompressedSize
        );

    if (status != STATUS_SUCCESS) { //accept only success value
        if (UncompBuffer) {
            VirtualFree(UncompBuffer, 0, MEM_RELEASE);
            UncompBuffer = NULL;
        }
    }

    return UncompBuffer;
}

#ifdef GENERATE_COMPRESSED_PAYLOAD

/*
* CompressPayload
*
* Purpose:
*
* Create compressed and encrypted by xor files. Used only during development.
* NOT for usage with release.
*
*/
VOID CompressPayload(
    VOID
    )
{
    PUCHAR Data;
    ULONG FinalCompressedSize = 0;

#ifdef _WIN64
    Data = CompressBufferLZNT1((PUCHAR)Fubuki64, sizeof(Fubuki64), &FinalCompressedSize);
#else
    Data = CompressBufferLZNT1((PUCHAR)Fubuki32, sizeof(Fubuki32), &FinalCompressedSize);
#endif

    if (Data) {

        EncodeBuffer(Data, FinalCompressedSize);

#ifdef _WIN64
        supWriteBufferToFile(TEXT("fubuki64.cd"), Data, FinalCompressedSize);
#else
        supWriteBufferToFile(TEXT("fubuki32.cd"), Data, FinalCompressedSize);
#endif
        VirtualFree(Data, 0, MEM_RELEASE);
    }

    FinalCompressedSize = 0;

#ifdef _WIN64
    Data = CompressBufferLZNT1((PUCHAR)Hibiki64, sizeof(Hibiki64), &FinalCompressedSize);
#else
    Data = CompressBufferLZNT1((PUCHAR)Hibiki32, sizeof(Hibiki32), &FinalCompressedSize);
#endif
    if (Data) {

        EncodeBuffer(Data, FinalCompressedSize);

#ifdef _WIN64
        supWriteBufferToFile(TEXT("hibiki64.cd"), Data, FinalCompressedSize);
#else
        supWriteBufferToFile(TEXT("hibiki32.cd"), Data, FinalCompressedSize);
#endif
        VirtualFree(Data, 0, MEM_RELEASE);
    }

    FinalCompressedSize = 0;

#ifdef _WIN64
    Data = CompressBufferLZNT1((PUCHAR)Kongou64, sizeof(Kongou64), &FinalCompressedSize);
#else
    Data = CompressBufferLZNT1((PUCHAR)Kongou32, sizeof(Kongou32), &FinalCompressedSize);
#endif
    if (Data) {

        EncodeBuffer(Data, FinalCompressedSize);

#ifdef _WIN64
        supWriteBufferToFile(TEXT("kongou64.cd"), Data, FinalCompressedSize);
#else
        supWriteBufferToFile(TEXT("kongou32.cd"), Data, FinalCompressedSize);
#endif
        VirtualFree(Data, 0, MEM_RELEASE);
    }
}

#endif

/*
* DecompressPayload
*
* Purpose:
*
* Decode payload and then decompress it.
*
*/
PVOID DecompressPayload(
    _In_ PVOID CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Inout_ PULONG DecompressedBufferSize
    )
{
    BOOL     cond = FALSE, bResult;
    PUCHAR   Data = NULL, UncompressedData = NULL, Ptr;
    ULONG    FinalDecompressedSize = 0, k, c;

    __try {

        bResult = FALSE;

        do {

            Data = VirtualAlloc(NULL, CompressedBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (Data == NULL)
                break;

            supCopyMemory(Data, CompressedBufferSize, CompressedBuffer, CompressedBufferSize);

            EncodeBuffer(Data, CompressedBufferSize);

            Ptr = Data;
            c = *(PULONG)&Ptr[0]; //query original size
            Ptr += sizeof(ULONG); //skip header
            k = CompressedBufferSize - sizeof(ULONG); //new compressed size without header

            UncompressedData = DecompressBufferLZNT1(Ptr, k, c, &FinalDecompressedSize);
            if (UncompressedData == NULL)
                break;

            //validate uncompressed data
            if (!supVerifyMappedImageMatchesChecksum(UncompressedData, FinalDecompressedSize)) {
                OutputDebugString(TEXT("Invalid file checksum"));
                break;
            }

            bResult = TRUE;

        } while (cond);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    if (Data != NULL) {
        VirtualFree(Data, 0, MEM_RELEASE);
    }

    if (bResult == FALSE) {
        if (UncompressedData != NULL) {
            VirtualFree(UncompressedData, 0, MEM_RELEASE);
            UncompressedData = NULL;
        }
        FinalDecompressedSize = 0;
    }

    if (DecompressedBufferSize) {
        *DecompressedBufferSize = FinalDecompressedSize;
    }

    return UncompressedData;
}
