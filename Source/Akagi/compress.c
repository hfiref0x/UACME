/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       COMPRESS.C
*
*  VERSION:     2.40
*
*  DATE:        01 July 2016
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
//#include "modules\hatsuyuki64.h"
#include "modules\kongou64.h"
#else
#include "modules\hibiki32.h"
#include "modules\fubuki32.h"
//#include "modules\hatsuyuki32.h"
#include "modules\kongou32.h"
#endif
#endif

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

    //Process Fubuki

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

    //Process Hatsuyuki
/*
#ifdef _WIN64
    Data = CompressBufferLZNT1((PUCHAR)Hatsuyuki64, sizeof(Hatsuyuki64), &FinalCompressedSize);
#else
    Data = CompressBufferLZNT1((PUCHAR)Hatsuyuki32, sizeof(Hatsuyuki32), &FinalCompressedSize);
#endif

    if (Data) {

        EncodeBuffer(Data, FinalCompressedSize);

#ifdef _WIN64
        supWriteBufferToFile(TEXT("hatsuyuki64.cd"), Data, FinalCompressedSize);
#else
        supWriteBufferToFile(TEXT("hatsuyuki32.cd"), Data, FinalCompressedSize);
#endif
        VirtualFree(Data, 0, MEM_RELEASE);
    }*/

    FinalCompressedSize = 0;

    //Process Hibiki

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

    //Process Kongou

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
* Copy Portable Executable to the output buffer, caller must free it with HeapFree.
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

	Ptr = HeapAlloc(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, SourceFileSize);
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
* Unpack DCN file to the buffer, caller must free it with HeapFree.
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

	if ((SourceFile == NULL) ||
		(OutputFileBuffer == NULL) ||
		(OutputFileBufferSize == NULL) ||
		(SourceFileSize == 0)
		)
	{
		SetLastError(ERROR_BAD_ARGUMENTS);
		return FALSE;
	}

	PDCN_HEADER FileHeader = (PDCN_HEADER)SourceFile;

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

			Data = HeapAlloc(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Target.uSize);
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
* Unpack DCS file to the buffer, caller must free it with HeapFree.
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

		DataBuffer = HeapAlloc(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, FileHeader->UncompressedFileSize);
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
