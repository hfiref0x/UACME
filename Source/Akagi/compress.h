/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2018
*
*  TITLE:       COMPRESS.H
*
*  VERSION:     3.11
*
*  DATE:        04 Dec 2018
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
#include <bcrypt.h>

#define UACME_CONTAINER_PACKED_UNIT 'UPCU' //Naka handling
#define UACME_CONTAINER_PACKED_DATA 'DPCU' //Naka handling
#define UACME_CONTAINER_PACKED_CODE 'CPCU' //Kuma handling
#define UACME_CONTAINER_PACKED_KEYS 'KPCU' //Kuma handling

//Initialization vector max bytes
#define DCU_IV_MAX_BLOCK_LENGTH 16

typedef struct _DCU_HEADER {
    DWORD Magic;
    DWORD cbData;
    DWORD cbDeltaSize;
    DWORD HeaderCrc;
    BYTE bIV[DCU_IV_MAX_BLOCK_LENGTH];
    //PBYTE pbData[1];     /* not a member of the structure */
} DCU_HEADER, *PDCU_HEADER;

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
    _In_ ULONG PayloadId,
    _In_ PVOID pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbDecompressed);

PVOID DecompressPayload(
    _In_ ULONG PayloadId,
    _In_ PVOID pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbDecompressed);

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

VOID EncodeBuffer(
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ ULONG Key);

BOOL InitCabinetDecompressionAPI(
    VOID);
