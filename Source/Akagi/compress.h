/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       COMPRESS.H
*
*  VERSION:     2.00
*
*  DATE:        15 Nov 2015
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

typedef PVOID (*pfnDecompressPayload)(
	_In_ PVOID CompressedBuffer,
	_In_ ULONG CompressedBufferSize,
	_Inout_ PULONG DecompressedBufferSize
	);

PUCHAR CompressBufferLZNT1(
	_In_ PUCHAR SrcBuffer,
	_In_ ULONG SrcSize,
	_Inout_ PULONG FinalCompressedSize
	);

PUCHAR DecompressBufferLZNT1(
	_In_ PUCHAR CompBuffer,
	_In_ ULONG CompSize,
	_In_ ULONG UncompressedBufferSize,
	_Inout_ PULONG FinalUncompressedSize
	);

VOID CompressPayload(
	VOID
	);

PVOID DecompressPayload(
	_In_ PVOID CompressedBuffer,
	_In_ ULONG CompressedBufferSize,
	_Inout_ PULONG DecompressedBufferSize
	);
