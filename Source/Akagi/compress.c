/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2018
*
*  TITLE:       COMPRESS.C
*
*  VERSION:     3.10
*
*  DATE:        21 Nov 2018
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
#include "secrets.h"

#pragma comment(lib, "msdelta.lib")
#pragma comment(lib, "Bcrypt.lib")

pfnCloseDecompressor pCloseDecompressor = NULL;
pfnCreateDecompressor pCreateDecompressor = NULL;
pfnDecompress pDecompress = NULL;

typedef struct _DCK_HEADER {
    DWORD Id;
    BYTE Data[UACME_KEY_SIZE];
} DCK_HEADER, *PDCK_HEADER;

/*
* EncodeBuffer
*
* Purpose:
*
* Decrypt/Encrypt given buffer.
*
*/
VOID EncodeBuffer(
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ ULONG Key
)
{
    ULONG k, c;
    PUCHAR ptr;

    if ((Buffer == NULL) || (BufferSize == 0))
        return;

    k = Key;
    c = BufferSize;
    ptr = (PUCHAR)Buffer;

    do {
        *ptr ^= k;
        k = _rotl(k, 1);
        ptr++;
        --c;
    } while (c != 0);
}

/*
* SelectSecretFromBlob
*
* Purpose:
*
* Return key used for decryption by Id from secrets blob.
*
* Use supHeapFree to release allocated result.
*
*/
_Success_(return != NULL)
PVOID SelectSecretFromBlob(
    _In_ ULONG Id,
    _Out_ PDWORD pcbKeyBlob
)
{
    INT i, c;
    PDCK_HEADER P;
    PVOID pbSecret = NULL;

    c = sizeof(g_bSecrets);
    P = (PDCK_HEADER)supHeapAlloc(c);
    if (P == NULL) {
        return NULL;
    }

    RtlCopyMemory(P, g_bSecrets, c);
    EncodeBuffer(P, c, AKAGI_XOR_KEY);

    c = sizeof(g_bSecrets) / sizeof(DCK_HEADER);
    for (i = 0; i < c; i++) {
        if (P[i].Id == Id) {
            pbSecret = supHeapAlloc(UACME_KEY_SIZE);
            if (pbSecret != NULL) {
                RtlCopyMemory(pbSecret, P[i].Data, UACME_KEY_SIZE);
                if (pcbKeyBlob)
                    *pcbKeyBlob = UACME_KEY_SIZE;
            }
            break;
        }
    }

    RtlSecureZeroMemory(P, sizeof(g_bSecrets));
    supHeapFree(P);

    return pbSecret;
}

/*
* IsValidContainerHeader
*
* Purpose:
*
* Basic santity checks over container header.
*
*/
BOOL IsValidContainerHeader(
    _In_ PDCU_HEADER UnitHeader,
    _In_ DWORD FileSize
)
{
    DWORD HeaderCrc;

    __try {
        if ((UnitHeader->Magic != UACME_CONTAINER_PACKED_DATA) &&   //Naka
            (UnitHeader->Magic != UACME_CONTAINER_PACKED_UNIT) &&   //Naka
            (UnitHeader->Magic != UACME_CONTAINER_PACKED_CODE) &&   //Kuma
            (UnitHeader->Magic != UACME_CONTAINER_PACKED_KEYS))     //Kuma
        {
            return FALSE;
        }

        //
        // Note that IV has different meaning in Kuma containers.
        //

        HeaderCrc = UnitHeader->HeaderCrc;
        UnitHeader->HeaderCrc = 0;
        if (RtlComputeCrc32(0, UnitHeader, sizeof(DCU_HEADER)) != HeaderCrc)
            return FALSE;

        if ((UnitHeader->cbData == 0) ||
            (UnitHeader->cbDeltaSize == 0))
            return FALSE;
        if (UnitHeader->cbData > FileSize)
            return FALSE;
        if (UnitHeader->cbDeltaSize > FileSize)
            return FALSE;
        if (UnitHeader->cbDeltaSize > UnitHeader->cbData)
            return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return TRUE;
}

/*
* DecryptBuffer
*
* Purpose:
*
* Decrypt AES encrypted buffer.
*
* Use supVirtualFree to release allocated result.
*
*/
BOOL DecryptBuffer(
    _In_    PBYTE  pbBuffer,
    _In_    DWORD  cbBuffer,
    _In_    PBYTE  pbIV,
    _In_    PBYTE  pbSecret,
    _In_    DWORD  cbSecret,
    _Out_   PBYTE *pbDecryptedBuffer,
    _Out_   PDWORD pcbDecryptedBuffer
)
{
    BOOL                bCond = FALSE, bResult = FALSE;
    BCRYPT_ALG_HANDLE   hAlgAes = NULL;
    BCRYPT_KEY_HANDLE   hKey = NULL;
    HANDLE              heapCNG = NULL;
    DWORD               cbCipherData, cbKeyObject, cbResult, cbBlockLen;
    PBYTE               pbKeyObject = NULL, pbCipherData = NULL;
    SIZE_T              memIO;
    NTSTATUS            status;

    do {

        heapCNG = HeapCreate(0, 0, 0);
        if (heapCNG == NULL)
            break;

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlgAes,
            BCRYPT_AES_ALGORITHM,
            NULL,
            0)))
        {
            break;
        }

        cbKeyObject = 0;
        cbResult = 0;

        if (!NT_SUCCESS(BCryptGetProperty(
            hAlgAes,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&cbKeyObject,
            sizeof(DWORD),
            &cbResult,
            0)))
        {
            break;
        }

        pbKeyObject = (PBYTE)HeapAlloc(heapCNG, HEAP_ZERO_MEMORY, cbKeyObject);
        if (pbKeyObject == NULL)
            break;

        cbBlockLen = 0;

        if (!NT_SUCCESS(BCryptGetProperty(hAlgAes,
            BCRYPT_BLOCK_LENGTH,
            (PUCHAR)&cbBlockLen,
            sizeof(DWORD),
            &cbResult,
            0)))
        {
            break;
        }

        if (cbBlockLen > DCU_IV_MAX_BLOCK_LENGTH)
            break;

        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlgAes,
            &hKey,
            pbKeyObject,
            cbKeyObject,
            pbSecret,
            cbSecret,
            0)))
        {
            break;
        }

        cbCipherData = 0;
        if (!NT_SUCCESS(BCryptDecrypt(
            hKey,
            pbBuffer,
            cbBuffer,
            NULL,
            pbIV,
            cbBlockLen,
            NULL,
            0,
            &cbCipherData,
            BCRYPT_BLOCK_PADDING)))
        {
            break;
        }

        memIO = (SIZE_T)cbCipherData;

        pbCipherData = (PBYTE)supVirtualAlloc(
            &memIO,
            DEFAULT_ALLOCATION_TYPE,
            DEFAULT_PROTECT_TYPE,
            &status);

        if ((!NT_SUCCESS(status)) || (pbCipherData == NULL))
            break;

        cbResult = 0;
        if (!NT_SUCCESS(BCryptDecrypt(
            hKey,
            pbBuffer,
            cbBuffer,
            NULL,
            pbIV,
            cbBlockLen,
            pbCipherData,
            cbCipherData,
            &cbResult,
            BCRYPT_BLOCK_PADDING)))
        {
            break;
        }

        BCryptDestroyKey(hKey);
        hKey = NULL;

        *pbDecryptedBuffer = pbCipherData;
        *pcbDecryptedBuffer = cbCipherData;

        bResult = TRUE;

    } while (bCond);

    if (hKey != NULL)
        BCryptDestroyKey(hKey);

    if (hAlgAes != NULL)
        BCryptCloseAlgorithmProvider(hAlgAes, 0);

    if (heapCNG) HeapDestroy(heapCNG);

    if (bResult == FALSE) {
        if (pbCipherData) supVirtualFree(pbCipherData, NULL);
        *pbDecryptedBuffer = NULL;
        *pcbDecryptedBuffer = 0;
    }

    return bResult;
}

/*
* DecompressContainerUnit
*
* Purpose:
*
* Decompress given container.
*
* Use supVirtualFree to release allocated result.
*
*/
PVOID DecompressContainerUnit(
    _In_ PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _In_ PBYTE pbSecret,
    _In_ DWORD cbSecret,
    _Out_ PULONG pcbDecompressed
)
{
    BOOL            bCond = FALSE;

    PDCU_HEADER     UnitHeader;

    PBYTE           pbDecryptedBuffer = NULL;
    DWORD           cbDecryptedBuffer = 0;

    DELTA_INPUT     diDelta, diSource;
    DELTA_OUTPUT    doOutput;

    PVOID           UncompressedData = NULL;
    SIZE_T          memIO;

    PBYTE           DataPtr;

    NTSTATUS        status;

    if (pcbDecompressed)
        *pcbDecompressed = 0;

    do {

        UnitHeader = (PDCU_HEADER)pbBuffer;

        if (!IsValidContainerHeader(UnitHeader, cbBuffer))
            break;

        DataPtr = (PBYTE)UnitHeader + sizeof(DCU_HEADER);

        if (!DecryptBuffer(
            (PBYTE)DataPtr,
            (DWORD)UnitHeader->cbData,
            (PBYTE)UnitHeader->bIV,
            (PBYTE)pbSecret,
            (DWORD)cbSecret,
            (PBYTE*)&pbDecryptedBuffer,
            (PDWORD)&cbDecryptedBuffer))
        {
            break;
        }

        if (cbDecryptedBuffer > cbBuffer)
            break;

        RtlSecureZeroMemory(&diSource, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&diDelta, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&doOutput, sizeof(DELTA_OUTPUT));

        diDelta.Editable = FALSE;
        diDelta.lpcStart = pbDecryptedBuffer;
        diDelta.uSize = UnitHeader->cbDeltaSize;

        if (ApplyDeltaB(DELTA_FILE_TYPE_RAW, diSource, diDelta, &doOutput)) {

            memIO = doOutput.uSize;
            UncompressedData = supVirtualAlloc(
                &memIO,
                DEFAULT_ALLOCATION_TYPE,
                DEFAULT_PROTECT_TYPE,
                &status);

            if ((NT_SUCCESS(status)) && (UncompressedData != NULL)) {

                RtlCopyMemory(UncompressedData, doOutput.lpStart, doOutput.uSize);
                if (pcbDecompressed)
                    *pcbDecompressed = (ULONG)doOutput.uSize;

            }
            DeltaFree(doOutput.lpStart);
        }

    } while (bCond);

    if (pbDecryptedBuffer != NULL) {
        supVirtualFree(pbDecryptedBuffer, NULL);
    }

    return UncompressedData;
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
    _In_ ULONG PayloadId,
    _In_ PVOID pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbDecompressed
)
{
    BOOL        cond = FALSE, bResult = FALSE;
    ULONG       FinalDecompressedSize = 0;
    SIZE_T      memIO;
    PUCHAR      UncompressedData = NULL;

    PVOID       Data = NULL;

    PBYTE       pbSecret = NULL;
    DWORD       cbSecret = 0, DataSize;

    NTSTATUS    status;

    __try {

        DataSize = cbBuffer;

        do {

            //
            // Make a writeable buffer copy.
            //

            memIO = DataSize;
            Data = supVirtualAlloc(
                (PSIZE_T)&memIO,
                DEFAULT_ALLOCATION_TYPE,
                DEFAULT_PROTECT_TYPE,
                &status);

            if ((!NT_SUCCESS(status)) || (Data == NULL))
                break;

            supCopyMemory(Data, memIO, pbBuffer, DataSize);

            //
            // Get key for decryption.
            //
            pbSecret = (PBYTE)SelectSecretFromBlob(PayloadId, &cbSecret);
            if ((pbSecret == NULL) || (cbSecret == 0))
                break;

            UncompressedData = (PUCHAR)DecompressContainerUnit(
                (PBYTE)Data,
                DataSize,
                pbSecret,
                cbSecret,
                &FinalDecompressedSize);

            if (UncompressedData == NULL)
                break;

            //
            // Validate uncompressed data, skip for dotnet.
            //
            if (!supVerifyMappedImageMatchesChecksum(UncompressedData, FinalDecompressedSize)) {

                if (!supIsCorImageFile(UncompressedData)) {

#ifdef _DEBUG
                    supDebugPrint(
                        TEXT("DecompressPayload"),
                        ERROR_DATA_CHECKSUM_ERROR);
#endif
                    break;
                }
            }

            bResult = TRUE;

        } while (cond);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    if (pbSecret) supHeapFree(pbSecret);

    if (Data) {
        supVirtualFree(Data, NULL);
    }

    if (bResult == FALSE) {
        if (UncompressedData != NULL) {
            supVirtualFree(UncompressedData, NULL);
            UncompressedData = NULL;
        }
        FinalDecompressedSize = 0;
    }

    if (pcbDecompressed)
        *pcbDecompressed = FinalDecompressedSize;

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

    SIZE_T BytesRead;

    DWORD NumberOfBlocks = 0;
    DWORD BytesDecompressed, NextOffset;

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

        DataBuffer = (PBYTE)supHeapAlloc(FileHeader->UncompressedFileSize);
        if (DataBuffer == NULL)
            break;

        DataBufferPtr = DataBuffer;
        NumberOfBlocks = FileHeader->NumberOfBlocks;

        BytesDecompressed = 0;
        BytesRead = 0;

        Block = (PDCS_BLOCK)FileHeader->FirstBlock;

        while (NumberOfBlocks > 0) {

            if (BytesRead + Block->CompressedBlockSize > SourceFileSize)
                break;

            if (BytesDecompressed + Block->DecompressedBlockSize > FileHeader->UncompressedFileSize)
                break;

            BytesDecompressed += Block->DecompressedBlockSize;

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
        }

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
    HMODULE hCabinetDll;

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
