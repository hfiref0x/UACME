/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2022
*
*  TITLE:       COMPRESS.H
*
*  VERSION:     3.61
*
*  DATE:        22 Jun 2022
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

VOID EncodeBuffer(
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ ULONG Key);
