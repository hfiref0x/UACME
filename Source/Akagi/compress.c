/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       COMPRESS.C
*
*  VERSION:     3.58
*
*  DATE:        01 Dec 2020
*
*  Compression and encoding/decoding support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "encresource.h"

#pragma comment(lib, "msdelta.lib")
#pragma comment(lib, "Bcrypt.lib")

#define UACME_KEY_SIZE 32

typedef struct _DCK_HEADER {
    DWORD Id;
    BYTE Data[UACME_KEY_SIZE];
} DCK_HEADER, * PDCK_HEADER;

typedef struct _UCM_STRING_TABLE_ENTRY {
    WORD Id;
    WORD DataLength;//in bytes
    CONST UCHAR* Data;
} UCM_STRING_TABLE_ENTRY, * PUCM_STRING_TABLE_ENTRY;

UCM_STRING_TABLE_ENTRY ucmStringTable[] = {
    { IDSB_USAGE_HELP, sizeof(B_USAGE_HELP), B_USAGE_HELP },
    { IDSB_USAGE_UAC_REQUIRED, sizeof(B_USAGE_UAC_REQUIRED), B_USAGE_UAC_REQUIRED },
    { IDSB_USAGE_ADMIN_REQUIRED, sizeof(B_USAGE_ADMIN_REQUIRED), B_USAGE_ADMIN_REQUIRED },
    { ISDB_USAGE_WOW_DETECTED, sizeof(B_USAGE_WOW64STRING), B_USAGE_WOW64STRING },
    { ISDB_USAGE_WOW64WIN32ONLY, sizeof(B_USAGE_WOW64WIN32STRING), B_USAGE_WOW64WIN32STRING },
    { ISDB_USAGE_UACFIX, sizeof(B_USAGE_UACFIX), B_USAGE_UACFIX },
    { ISDB_PROGRAMNAME, sizeof(B_PROGRAM_NAME), B_PROGRAM_NAME }
};


UINT64 StringCryptGenKey(
    _In_ PWCHAR Key
)
{
    UINT64    k = 0;
    WCHAR     c;

    while (*Key)
    {
        k ^= *Key;

        for (c = 0; c < 8; ++c)
        {
            k = (k << 8) | (k >> 56);
            k += (UINT64)c * 7 + *Key;
        }

        ++Key;
    }

    return k;
}

SIZE_T StringCryptEncrypt(
    _In_ PWCHAR Src,
    _In_ PWCHAR Dst,
    _In_ PWCHAR Key
)
{
    UINT64    k;
    WCHAR     c;
    SIZE_T    len = 0;

    k = StringCryptGenKey(Key);

    c = 0;
    while (*Src)
    {
        c ^= *Src + (wchar_t)k;
        *Dst = c;

        k = (k << 8) | (k >> 56);
        ++Src;
        ++Dst;
        ++len;
    }

    return len;
}

VOID StringCryptDecrypt(
    _In_ PWCHAR Src,
    _In_ PWCHAR Dst,
    _In_ SIZE_T Len,
    _In_ PWCHAR Key)
{
    UINT64    k;
    WCHAR     c, c0;

    k = StringCryptGenKey(Key);

    c = 0;
    while (Len > 0)
    {
        c0 = *Src;
        *Dst = (c0 ^ c) - (wchar_t)k;
        c = c0;

        k = (k << 8) | (k >> 56);
        ++Src;
        ++Dst;
        --Len;
    }
}

/*
* DecodeStringById
*
* Purpose:
*
* Return decrypted string by ID.
*
*/
_Success_(return == TRUE)
BOOLEAN DecodeStringById(
    _In_ ULONG Id,
    _Inout_ LPWSTR lpBuffer,
    _In_ SIZE_T cbBuffer)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(ucmStringTable); i++) {
        if (ucmStringTable[i].Id == Id) {

            if (cbBuffer < ucmStringTable[i].DataLength)
                break;

            StringCryptDecrypt((PWCHAR)ucmStringTable[i].Data,
                (PWCHAR)lpBuffer,
                (SIZE_T)ucmStringTable[i].DataLength / sizeof(WCHAR),
                (PWCHAR)RtlNtdllName);

            return TRUE;
        }
    }
    return FALSE;
}

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
PVOID SelectSecretFromBlob(
    _In_ ULONG Id,
    _Out_ PDWORD pcbKeyBlob
)
{
    ULONG i, c;
    ULONG dataSize = 0;
    PDCK_HEADER secretsBlob;
    PVOID pbSecret = NULL, resourceBlob;

    if (pcbKeyBlob)
        *pcbKeyBlob = 0;

    resourceBlob = supLdrQueryResourceData(SECRETS_ID,
        g_hInstance,
        &dataSize);

    if (resourceBlob) {

        secretsBlob = (PDCK_HEADER)supHeapAlloc(dataSize);
        if (secretsBlob) {

            RtlCopyMemory(secretsBlob, resourceBlob, dataSize);
            EncodeBuffer(secretsBlob, dataSize, AKAGI_XOR_KEY);

            c = dataSize / sizeof(DCK_HEADER);
            for (i = 0; i < c; i++) {
                if (secretsBlob[i].Id == Id) {
                    pbSecret = supHeapAlloc(UACME_KEY_SIZE);
                    if (pbSecret != NULL) {
                        RtlCopyMemory(pbSecret, secretsBlob[i].Data, UACME_KEY_SIZE);
                        if (pcbKeyBlob)
                            *pcbKeyBlob = UACME_KEY_SIZE;
                    }
                    break;
                }
            }

            RtlSecureZeroMemory(secretsBlob, dataSize);
            supHeapFree(secretsBlob);
        }

    }

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
    BOOL                bResult = FALSE;
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

    } while (FALSE);

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

    } while (FALSE);

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
    BOOL        bResult = FALSE;
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

        } while (FALSE);

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
