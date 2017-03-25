/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       COMPRESS.C
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
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

#pragma comment(lib, "msdelta.lib")

pfnCloseDecompressor pCloseDecompressor = NULL;
pfnCreateDecompressor pCreateDecompressor = NULL;
pfnDecompress pDecompress = NULL;

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
* DecompressBufferLZNT1
*
* Purpose:
*
* Decompress buffer compressed with LZ algorithm.
*
* Use NtFreeVirtualMemory to release returned buffer when it no longer needed.
*
*/
PUCHAR DecompressBufferLZNT1(
    _In_ PUCHAR CompBuffer,
    _In_ ULONG CompSize,
    _In_ ULONG UncompressedBufferSize,
    _Inout_ PULONG FinalUncompressedSize
)
{
    SIZE_T      Size;
    PUCHAR      UncompBuffer = NULL;
    NTSTATUS    status;

    if (FinalUncompressedSize)
        *FinalUncompressedSize = 0;

    if (UncompressedBufferSize == 0)
        return NULL;

    Size = (SIZE_T)UncompressedBufferSize;
    status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &UncompBuffer,
        0,
        &Size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if ((!NT_SUCCESS(status)) || (UncompBuffer == NULL))
        return NULL;

    status = RtlDecompressBuffer(
        COMPRESSION_FORMAT_LZNT1,
        UncompBuffer,
        UncompressedBufferSize,
        CompBuffer,
        CompSize,
        FinalUncompressedSize
    );

    if (status != STATUS_SUCCESS) { //accept only success value
        Size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &UncompBuffer, &Size, MEM_RELEASE);       
        UncompBuffer = NULL;
    }

    return UncompBuffer;
}

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
    BOOL        cond = FALSE, bResult;
    ULONG       FinalDecompressedSize = 0, k, c;
    NTSTATUS    status;
    SIZE_T      Size;
    PUCHAR      Data = NULL, UncompressedData = NULL, Ptr;

    __try {

        bResult = FALSE;

        do {

            Size = (SIZE_T)CompressedBufferSize;
            status = NtAllocateVirtualMemory(
                NtCurrentProcess(),
                &Data,
                0,
                &Size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);

            if ( (!NT_SUCCESS(status)) || (Data == NULL) ) 
                break;

            supCopyMemory(Data, (SIZE_T)CompressedBufferSize, CompressedBuffer, (SIZE_T)CompressedBufferSize);

            EncodeBuffer(Data, CompressedBufferSize);

            Ptr = Data;
            c = *(PULONG)&Ptr[0]; //query original size
            Ptr += sizeof(ULONG); //skip header
            k = (ULONG)(CompressedBufferSize - sizeof(ULONG)); //new compressed size without header

            UncompressedData = DecompressBufferLZNT1(Ptr, k, c, &FinalDecompressedSize);
            if (UncompressedData == NULL)
                break;

            //validate uncompressed data
            if (!supVerifyMappedImageMatchesChecksum(UncompressedData, FinalDecompressedSize)) {
                supDebugPrint(TEXT("DecompressPayload"), ERROR_DATA_CHECKSUM_ERROR);
                break;
            }

            bResult = TRUE;

        } while (cond);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    if (Data != NULL) {
        Size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Data, &Size, MEM_RELEASE);
    }

    if (bResult == FALSE) {
        if (UncompressedData != NULL) {
            Size = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &UncompressedData, &Size, MEM_RELEASE);
            UncompressedData = NULL;
        }
        FinalDecompressedSize = 0;
    }

    if (DecompressedBufferSize) {
        *DecompressedBufferSize = FinalDecompressedSize;
    }

    return UncompressedData;
}

/*
* GetTargetFileType
*
* Purpose:
*
* Return container data type.
*
*/
CFILE_TYPE GetTargetFileType(
    VOID *FileBuffer
)
{
    CFILE_TYPE Result = ftUnknown;

    if (FileBuffer == NULL)
        return Result;

    //check if file is in compressed format 
    if (*((BYTE *)FileBuffer) == 'D' &&
        *((BYTE *)FileBuffer + 1) == 'C' &&
        *((BYTE *)FileBuffer + 3) == 1
        )
    {
        switch (*((BYTE *)FileBuffer + 2)) {

        case 'N':
            Result = ftDCN;
            break;

        case 'S':
            Result = ftDCS;
            break;

        default:
            Result = ftUnknown;
            break;

        }
    }
    else {
        //not compressed, check mz header
        if (*((BYTE *)FileBuffer) == 'M' &&
            *((BYTE *)FileBuffer + 1) == 'Z'
            )
        {
            Result = ftMZ;
        }
    }
    return Result;
}

/*
* ProcessFileMZ
*
* Purpose:
*
* Copy Portable Executable to the output buffer, caller must free it with supHeapFree.
*
*/
BOOL ProcessFileMZ(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE;
    PVOID Ptr;

    if ((SourceFile == NULL) ||
        (OutputFileBuffer == NULL) ||
        (OutputFileBufferSize == NULL) ||
        (SourceFileSize == 0)
        )
    {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }

    Ptr = supHeapAlloc(SourceFileSize);
    if (Ptr) {
        *OutputFileBuffer = Ptr;
        *OutputFileBufferSize = SourceFileSize;
        RtlCopyMemory(Ptr, SourceFile, SourceFileSize);
        bResult = TRUE;
    }
    else {
        *OutputFileBuffer = NULL;
        *OutputFileBufferSize = 0;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    return bResult;
}

/*
* ProcessFileDCN
*
* Purpose:
*
* Unpack DCN file to the buffer, caller must free it with supHeapFree.
*
*/
BOOL ProcessFileDCN(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE, bCond = FALSE;

    DELTA_HEADER_INFO   dhi;
    DELTA_INPUT         Source, Delta;
    DELTA_OUTPUT        Target;
    PVOID               Data = NULL;
    SIZE_T              DataSize = 0;

    PDCN_HEADER FileHeader = (PDCN_HEADER)SourceFile;

    if ((SourceFile == NULL) ||
        (OutputFileBuffer == NULL) ||
        (OutputFileBufferSize == NULL) ||
        (SourceFileSize == 0)
        )
    {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }

    do {

        RtlSecureZeroMemory(&dhi, sizeof(DELTA_HEADER_INFO));
        Delta.lpStart = FileHeader->Data;
        Delta.uSize = SourceFileSize - 4;
        Delta.Editable = FALSE;
        if (!GetDeltaInfoB(Delta, &dhi)) {
            SetLastError(ERROR_BAD_FORMAT);
            break;
        }

        RtlSecureZeroMemory(&Source, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&Target, sizeof(DELTA_OUTPUT));

        bResult = ApplyDeltaB(DELTA_DEFAULT_FLAGS_RAW, Source, Delta, &Target);
        if (bResult) {

            Data = supHeapAlloc(Target.uSize);
            if (Data) {
                RtlCopyMemory(Data, Target.lpStart, Target.uSize);
                DataSize = Target.uSize;
            }
            DeltaFree(Target.lpStart);
        }
        else {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }

        *OutputFileBuffer = Data;
        *OutputFileBufferSize = DataSize;

    } while (bCond);

    return bResult;
}

/*
* ProcessFileDCS
*
* Purpose:
*
* Unpack DCS file to the buffer, caller must free it with supHeapFree.
*
*/
BOOL ProcessFileDCS(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE, bCond = FALSE;
    COMPRESSOR_HANDLE hDecompressor = 0;
    BYTE *DataBufferPtr = NULL, *DataBuffer = NULL;

    PDCS_HEADER FileHeader = (PDCS_HEADER)SourceFile;
    PDCS_BLOCK Block;

    DWORD NumberOfBlocks = 0;
    DWORD BytesRead = 0, BytesWritten = 0, NextOffset;

    if ((SourceFile == NULL) ||
        (OutputFileBuffer == NULL) ||
        (OutputFileBufferSize == NULL) ||
        (SourceFileSize == 0)
        )
    {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }

    do {
        SetLastError(0);

        if (!pCreateDecompressor(COMPRESS_RAW | COMPRESS_ALGORITHM_LZMS, NULL, &hDecompressor))
            break;

        if (FileHeader->UncompressedFileSize == 0)
            break;

        if (FileHeader->NumberOfBlocks == 0)
            break;

        DataBuffer = supHeapAlloc(FileHeader->UncompressedFileSize);
        if (DataBuffer == NULL)
            break;

        DataBufferPtr = DataBuffer;
        NumberOfBlocks = FileHeader->NumberOfBlocks;
        Block = (PDCS_BLOCK)FileHeader->FirstBlock;

        do {

            if (BytesRead + Block->CompressedBlockSize > SourceFileSize)
                break;

            if (BytesWritten + Block->DecompressedBlockSize > FileHeader->UncompressedFileSize)
                break;

            bResult = pDecompress(hDecompressor,
                Block->CompressedData, Block->CompressedBlockSize - 4,
                (BYTE *)DataBufferPtr, Block->DecompressedBlockSize,
                NULL);

            if (!bResult)
                break;

            NumberOfBlocks--;
            if (NumberOfBlocks == 0)
                break;

            DataBufferPtr = (BYTE*)DataBufferPtr + Block->DecompressedBlockSize;
            NextOffset = Block->CompressedBlockSize + 4;
            Block = (DCS_BLOCK*)((BYTE *)Block + NextOffset);
            BytesRead += NextOffset;
            BytesWritten += Block->DecompressedBlockSize;

            if (BytesWritten > FileHeader->UncompressedFileSize)
                break;

        } while (NumberOfBlocks > 0);

        *OutputFileBuffer = DataBuffer;
        *OutputFileBufferSize = FileHeader->UncompressedFileSize;

    } while (bCond);

    if (hDecompressor != NULL)
        pCloseDecompressor(hDecompressor);

    return bResult;
}

/*
* InitCabinetDecompressionAPI
*
* Purpose:
*
* Get Cabinet API decompression function addresses.
* Windows 7 lack of their support.
*
*/
BOOL InitCabinetDecompressionAPI(
    VOID
)
{
    HANDLE hCabinetDll;

    hCabinetDll = GetModuleHandle(TEXT("cabinet.dll"));
    if (hCabinetDll == NULL)
        return FALSE;

    pDecompress = (pfnDecompress)GetProcAddress(hCabinetDll, "Decompress");
    if (pDecompress == NULL)
        return FALSE;

    pCreateDecompressor = (pfnCreateDecompressor)GetProcAddress(hCabinetDll, "CreateDecompressor");
    if (pCreateDecompressor == NULL)
        return FALSE;

    pCloseDecompressor = (pfnCloseDecompressor)GetProcAddress(hCabinetDll, "CloseDecompressor");
    if (pCloseDecompressor == NULL)
        return FALSE;

    return TRUE;
}
