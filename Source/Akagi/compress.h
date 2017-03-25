/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       COMPRESS.H
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
*
*  Prototypes and definitions for compression.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <msdelta.h>
#include <compressapi.h>

typedef BOOL(WINAPI *pfnCreateDecompressor)(
    _In_ DWORD Algorithm,
    _In_opt_ PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
    _Out_ PDECOMPRESSOR_HANDLE DecompressorHandle);

typedef BOOL(WINAPI *pfnDecompress)(
    _In_ DECOMPRESSOR_HANDLE DecompressorHandle,
    _In_reads_bytes_opt_(CompressedDataSize) PVOID CompressedData,
    _In_ SIZE_T CompressedDataSize,
    _Out_writes_bytes_opt_(UncompressedBufferSize) PVOID UncompressedBuffer,
    _In_ SIZE_T UncompressedBufferSize,
    _Out_opt_ PSIZE_T UncompressedDataSize);

typedef BOOL(WINAPI *pfnCloseDecompressor)(
    _In_ DECOMPRESSOR_HANDLE DecompressorHandle);

typedef enum _CFILE_TYPE {
    ftDCN,
    ftDCS,
    ftMZ,
    ftUnknown,
    ftMax
} CFILE_TYPE;

typedef struct _DCN_HEADER {
    DWORD Signature; //DCN v1
    BYTE Data[1]; //Intra Package Delta 
} DCN_HEADER, *PDCN_HEADER;

typedef struct _DCS_HEADER {
    DWORD Signature; //DCS v1
    DWORD NumberOfBlocks;
    DWORD UncompressedFileSize;
    BYTE FirstBlock[1];
} DCS_HEADER, *PDCS_HEADER;

typedef struct _DCS_BLOCK {
    DWORD CompressedBlockSize;
    DWORD DecompressedBlockSize;
    BYTE CompressedData[1];
} DCS_BLOCK, *PDCS_BLOCK;

typedef PVOID(*pfnDecompressPayload)(
    _In_ PVOID CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Inout_ PULONG DecompressedBufferSize);

PUCHAR CompressBufferLZNT1(
    _In_ PUCHAR SrcBuffer,
    _In_ ULONG SrcSize,
    _Inout_ PULONG FinalCompressedSize);

PUCHAR DecompressBufferLZNT1(
    _In_ PUCHAR CompBuffer,
    _In_ ULONG CompSize,
    _In_ ULONG UncompressedBufferSize,
    _Inout_ PULONG FinalUncompressedSize);

VOID CompressPayload(
    VOID);

PVOID DecompressPayload(
    _In_ PVOID CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Inout_ PULONG DecompressedBufferSize);

CFILE_TYPE GetTargetFileType(
    VOID *FileBuffer);

BOOL ProcessFileDCN(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize);

BOOL ProcessFileDCS(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize);

BOOL ProcessFileMZ(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize);

BOOL InitCabinetDecompressionAPI(
    VOID);
