/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2022
*
*  TITLE:       MAIN.C
*
*  VERSION:     3.59
*
*  DATE:        02 Feb 2022
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

#include "naka.h"

/*
* CreateSha256HashForBuffer
*
* Purpose:
*
* Return SHA256 hash for buffer.
*
*/
BOOL CreateSha256HashForBuffer(
    _In_ PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PBYTE *pbHash,
    _Out_ PDWORD pcbHash
)
{
    BCRYPT_ALG_HANDLE   hAlgSha256 = NULL, hHashSha256 = NULL;
    BOOL                bResult = FALSE;

    DWORD cbKeyObject = 0, cbResult = 0;

    PBYTE pbKeyObject = NULL;
    HANDLE hHeap = GetProcessHeap();

    PBYTE _pbHash = NULL;
    DWORD _cbHash = 0;

    do {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlgSha256,
            BCRYPT_SHA256_ALGORITHM,
            NULL, 0)))
        {
            break;
        }

        //
        // CNG object allocation.
        //

        if (!NT_SUCCESS(BCryptGetProperty(
            hAlgSha256,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&cbKeyObject,
            sizeof(DWORD),
            &cbResult,
            0)))
        {
            break;
        }

        pbKeyObject = (PBYTE)HeapAlloc(
            hHeap,
            HEAP_ZERO_MEMORY,
            cbKeyObject);

        if (pbKeyObject == NULL)
            break;

        //
        // Hash buffer allocation.
        //

        cbResult = 0;
        if (!NT_SUCCESS(BCryptGetProperty(
            hAlgSha256,
            BCRYPT_HASH_LENGTH,
            (PUCHAR)&_cbHash,
            sizeof(DWORD),
            &cbResult, 0)))
        {
            break;
        }

        _pbHash = (PBYTE)HeapAlloc(
            hHeap,
            HEAP_ZERO_MEMORY,
            _cbHash);

        if (_pbHash == NULL)
            break;

        //
        // Create hash from buffer.
        //

        if (!NT_SUCCESS(BCryptCreateHash(
            hAlgSha256,
            &hHashSha256,
            pbKeyObject,
            cbKeyObject,
            NULL,
            0,
            0)))
        {
            break;
        }

        if (!NT_SUCCESS(BCryptHashData(
            hHashSha256,
            (PUCHAR)pbBuffer,
            (ULONG)cbBuffer,
            0)))
        {
            break;
        }

        if (!NT_SUCCESS(BCryptFinishHash(
            hHashSha256,
            _pbHash,
            _cbHash,
            0)))
        {
            break;
        }

        BCryptDestroyHash(hHashSha256);
        hHashSha256 = NULL;

        BCryptCloseAlgorithmProvider(hAlgSha256, 0);
        hAlgSha256 = NULL;

        HeapFree(hHeap, 0, pbKeyObject);
        pbKeyObject = NULL;

        *pbHash = _pbHash;
        *pcbHash = _cbHash;

        bResult = TRUE;

    } while (FALSE);

    if (hHashSha256) BCryptDestroyHash(hHashSha256);
    if (hAlgSha256) BCryptCloseAlgorithmProvider(hAlgSha256, 0);

    if (pbKeyObject) HeapFree(hHeap, 0, pbKeyObject);

    if (bResult == FALSE) {

        *pbHash = NULL;
        *pcbHash = 0;

        if (_pbHash) HeapFree(hHeap, 0, _pbHash);
    }

    return bResult;
}

/*
* GenerateIV
*
* Purpose:
*
* Crypto-random generated initialization vector for AES encryption.
*
*/
BOOL GenerateIV(
    _In_ PBYTE pbIV,
    _In_ DWORD cbIV
)
{
    BOOL bResult = FALSE;
    BCRYPT_ALG_HANDLE hAlgRng = NULL;

    do {

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlgRng,
            BCRYPT_RNG_ALGORITHM,
            NULL,
            0)))
        {
            break;
        }

        bResult = (NT_SUCCESS(BCryptGenRandom(
            hAlgRng,
            pbIV,
            cbIV,
            0)));

    } while (FALSE);

    if (hAlgRng)
        BCryptCloseAlgorithmProvider(hAlgRng, 0);

    return bResult;
}

/*
* DecryptBuffer
*
* Purpose:
*
* Decrypt AES encrypted buffer.
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

        pbCipherData = (PBYTE)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            cbCipherData);

        if (pbCipherData == NULL) {
            break;
        }

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
        if (pbCipherData) {
            HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pbCipherData);
        }
        *pbDecryptedBuffer = NULL;
        *pcbDecryptedBuffer = 0;
    }

    return bResult;
}

/*
* EncryptBuffer
*
* Purpose:
*
* Encrypt given buffer with AES-CBC.
*
*/
BOOL EncryptBuffer(
    _In_    PBYTE   pbBuffer,
    _In_    DWORD   cbBuffer,
    _Inout_ PBYTE   pbIV,
    _In_    PBYTE   pbSecret,
    _In_    DWORD   cbSecret,
    _Out_   PBYTE   *pbEncryptedBuffer,
    _Out_   PDWORD  pcbEncryptedBuffer
)
{
    BOOL                bResult = FALSE;
    BCRYPT_ALG_HANDLE   hAlgAes = NULL;
    BCRYPT_KEY_HANDLE   hKey = NULL;
    HANDLE              heapCNG = NULL;
    DWORD               cbCipherData, cbObject, cbResult, cbBlockLen;
    PBYTE               pbObject, pbCipherData, _pbIV;

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

        cbObject = 0;
        cbResult = 0;

        if (!NT_SUCCESS(BCryptGetProperty(
            hAlgAes,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&cbObject,
            sizeof(DWORD),
            &cbResult,
            0)))
        {
            break;
        }

        pbObject = (PBYTE)HeapAlloc(heapCNG, HEAP_ZERO_MEMORY, cbObject);
        if (pbObject == NULL)
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

        if (!GenerateIV(pbIV, cbBlockLen))
            break;

        _pbIV = (PBYTE)HeapAlloc(heapCNG, HEAP_ZERO_MEMORY, cbBlockLen);
        if (_pbIV == NULL)
            break;

        RtlCopyMemory(_pbIV, pbIV, cbBlockLen);

        if (!NT_SUCCESS(BCryptSetProperty( //-V542
            hAlgAes,
            BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0)))
        {
            break;
        }

        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlgAes,
            &hKey,
            pbObject,
            cbObject,
            pbSecret,
            cbSecret,
            0)))
        {
            break;
        }

        cbCipherData = 0;
        if (!NT_SUCCESS(BCryptEncrypt(
            hKey,
            pbBuffer,
            cbBuffer,
            NULL,
            _pbIV,
            cbBlockLen,
            NULL,
            0,
            &cbCipherData,
            BCRYPT_BLOCK_PADDING)))
        {
            break;
        }

        pbCipherData = (PBYTE)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            cbCipherData);

        if (pbCipherData == NULL) {
            break;
        }

        cbResult = 0;
        if (!NT_SUCCESS(BCryptEncrypt(
            hKey,
            pbBuffer,
            cbBuffer,
            NULL,
            _pbIV,
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

        *pbEncryptedBuffer = pbCipherData;
        *pcbEncryptedBuffer = cbCipherData;
        bResult = TRUE;

    } while (FALSE);

    if (hKey != NULL)
        BCryptDestroyKey(hKey);

    if (hAlgAes != NULL)
        BCryptCloseAlgorithmProvider(hAlgAes, 0);

    if (heapCNG) {
        HeapDestroy(heapCNG);
    }

    if (bResult == FALSE) {
        *pbEncryptedBuffer = NULL;
        *pcbEncryptedBuffer = 0;
    }

    return bResult;
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
* supReadBufferFromFile
*
* Purpose:
*
* Open existing file and read from it to buffer.
*
*/
PVOID supReadBufferFromFile(
    _In_ LPWSTR lpFileName,
    _Out_ PLARGE_INTEGER FileSize
)
{
    BOOL bSuccess = FALSE;
    DWORD r;
    PVOID FileData = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize;

    do {

        hFile = CreateFile(
            lpFileName,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hFile != INVALID_HANDLE_VALUE) {

            fileSize.QuadPart = 0;
            if (!GetFileSizeEx(hFile, &fileSize))
                break;

            if (fileSize.QuadPart == 0)
                break;

            FileData = HeapAlloc(
                GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                (SIZE_T)fileSize.LowPart);

            if (FileData == NULL)
                break;

            if (!ReadFile(
                hFile,
                FileData,
                fileSize.LowPart,
                (LPDWORD)&r, NULL))
            {
                HeapFree(GetProcessHeap(), 0, FileData);
                FileData = NULL;
                break;
            }

            if (FileSize)
                *FileSize = fileSize;

            bSuccess = TRUE;
        }

    } while (FALSE);

    if (!bSuccess) {
        if (FileSize) {
            fileSize.QuadPart = 0;
            *FileSize = fileSize;
        }
    }

    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    return FileData;
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
* DecompressContainerUnit
*
* Purpose:
*
* Decompress given container file.
*
*/
void DecompressContainerUnit(
    _In_ LPWSTR lpInputFile,
    _In_ LPWSTR lpKeyFile
)
{
    PUCHAR FileData = NULL;
    LPWSTR NewName = NULL;
    SIZE_T sz = 0;
    LARGE_INTEGER FileSize, KeyFileSize;

    PDCU_HEADER UnitHeader;

    PBYTE pbDecryptedBuffer = NULL;
    DWORD cbDecryptedBuffer = 0;

    DELTA_INPUT diDelta, diSource;
    DELTA_OUTPUT doOutput;

    HANDLE hHeap = GetProcessHeap();

    PBYTE pbKeyBlob = NULL;

    PBYTE DataPtr;

    do {
        sz = (1 + _strlen(lpInputFile)) * sizeof(WCHAR);
        NewName = (LPWSTR)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sz);
        if (NewName == NULL)
            break;

        FileSize.QuadPart = 0;
        FileData = (PUCHAR)supReadBufferFromFile(lpInputFile, &FileSize);
        if ((FileData == NULL) || (FileSize.QuadPart == 0))
            break;

        KeyFileSize.QuadPart = 0;
        pbKeyBlob = (PBYTE)supReadBufferFromFile(lpKeyFile, &KeyFileSize);
        if ((pbKeyBlob == NULL) || (KeyFileSize.QuadPart == 0))
            break;

        UnitHeader = (PDCU_HEADER)FileData;

        if (!IsValidContainerHeader(UnitHeader, FileSize.LowPart))
            break;

        DataPtr = (PBYTE)UnitHeader + sizeof(DCU_HEADER);

        if (!DecryptBuffer(
            (PBYTE)DataPtr,
            UnitHeader->cbData,
            UnitHeader->bIV,
            (PBYTE)pbKeyBlob,
            KeyFileSize.LowPart,
            &pbDecryptedBuffer,
            &cbDecryptedBuffer))
        {
            break;
        }

        if (cbDecryptedBuffer > FileSize.LowPart)
            break;

        RtlSecureZeroMemory(&diSource, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&diDelta, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&doOutput, sizeof(DELTA_OUTPUT));

        diDelta.Editable = FALSE;
        diDelta.lpcStart = pbDecryptedBuffer;
        diDelta.uSize = UnitHeader->cbDeltaSize;

        if (ApplyDeltaB(DELTA_FILE_TYPE_RAW, diSource, diDelta, &doOutput)) {

            if (_filename_noext(NewName, lpInputFile)) {
                _strcat(NewName, TEXT(".out"));
                supWriteBufferToFile(NewName, doOutput.lpStart, (DWORD)doOutput.uSize);
            }

            DeltaFree(doOutput.lpStart);
        }

    } while (FALSE);

    if (pbDecryptedBuffer != NULL)
        HeapFree(hHeap, 0, pbDecryptedBuffer);
    if (NewName != NULL)
        HeapFree(hHeap, 0, NewName);
    if (FileData != NULL)
        HeapFree(hHeap, 0, FileData);
    if (pbKeyBlob != NULL)
        HeapFree(hHeap, 0, pbKeyBlob);

}

/*
* CreateContainerPackedUnit
*
* Purpose:
*
* Create container with compressed file inside.
*
*/
void CreateContainerPackedUnit(
    _In_ LPWSTR lpInputFile
)
{
    PUCHAR FileData = NULL;
    HANDLE hHeap = GetProcessHeap();
    LPWSTR NewName = NULL;
    SIZE_T sz = 0;
    LARGE_INTEGER FileSize;

    DELTA_INPUT d_in, d_target, s_op, t_op, g_op;
    DELTA_OUTPUT d_out;

    PBYTE pbHash = NULL, pbEncryptedBuffer = NULL;
    DWORD cbHash = 0, cbEncryptedBuffer = 0;

    PDCU_HEADER UnitHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_FILE_HEADER fheader;

    PVOID hashSource;
    DWORD hashSize, Magic;

    PBYTE DataPtr;

#ifdef _DEBUG
    LPWSTR KeyName = NULL;
#endif

    BYTE bIV[DCU_IV_MAX_BLOCK_LENGTH];

    do {
        RtlSecureZeroMemory(&d_out, sizeof(DELTA_OUTPUT));

        sz = (1 + _strlen(lpInputFile)) * sizeof(WCHAR);
        NewName = (LPWSTR)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sz);
        if (NewName == NULL)
            break;

#ifdef _DEBUG
        KeyName = (LPWSTR)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sz);
        if (KeyName == NULL)
            break;
#endif

        FileSize.QuadPart = 0;
        FileData = (PUCHAR)supReadBufferFromFile(lpInputFile, &FileSize);
        if ((FileData == NULL) || (FileSize.QuadPart == 0))
            break;

        NtHeaders = RtlImageNtHeader(FileData);
        if (NtHeaders == NULL) {
            //
            // Not an image file, use whole file SHA256 hash as key.
            //
            hashSource = FileData;
            hashSize = FileSize.LowPart;

            Magic = UACME_CONTAINER_PACKED_DATA;
        }
        else {

            //
            // Image file, create SHA256 hash from IMAGE_FILE_HEADER.
            //
            fheader = &NtHeaders->FileHeader;
            hashSource = fheader;
            hashSize = sizeof(IMAGE_FILE_HEADER);

            Magic = UACME_CONTAINER_PACKED_UNIT;
        }

        if (!CreateSha256HashForBuffer((PBYTE)hashSource, hashSize, &pbHash, &cbHash))
            break;

        if (cbHash > 32)
            break;

        if (_filename_noext(NewName, lpInputFile)) {
            _strcat(NewName, TEXT(".key"));
            supWriteBufferToFile(NewName, pbHash, (DWORD)cbHash);
        }

        //
        // Pack file to buffer.
        //

        RtlSecureZeroMemory(&d_in, sizeof(DELTA_INPUT));
        d_target.lpcStart = FileData;
        d_target.uSize = FileSize.LowPart;
        d_target.Editable = FALSE;

        RtlSecureZeroMemory(&s_op, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&t_op, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&g_op, sizeof(DELTA_INPUT));

        if (!CreateDeltaB(DELTA_FILE_TYPE_RAW,
            DELTA_FLAG_NONE,
            DELTA_FLAG_NONE,
            d_in,
            d_target,
            s_op,
            t_op,
            g_op,
            NULL,
            0,
            &d_out))
        {
            break;
        }

        //
        //  Encrypt buffer with AES-CBC using SHA256 hash as key.
        // 

        RtlSecureZeroMemory(&bIV, sizeof(bIV));

        if (!EncryptBuffer(
            (PBYTE)d_out.lpStart,
            (DWORD)d_out.uSize,
            (PBYTE)&bIV,
            pbHash,
            cbHash,
            &pbEncryptedBuffer,
            &cbEncryptedBuffer))
        {
            break;
        }

        DeltaFree(d_out.lpStart);
        d_out.lpStart = NULL;

        //
        // Build final package and save it to disk.
        //

        sz = sizeof(DCU_HEADER) + cbEncryptedBuffer;
        UnitHeader = (PDCU_HEADER)HeapAlloc(
            hHeap,
            HEAP_ZERO_MEMORY,
            sz);

        if (UnitHeader) {

            UnitHeader->Magic = Magic;
            UnitHeader->cbData = cbEncryptedBuffer;
            UnitHeader->cbDeltaSize = (DWORD)d_out.uSize; //original compressed delta size

            RtlCopyMemory(UnitHeader->bIV, bIV, DCU_IV_MAX_BLOCK_LENGTH);

            UnitHeader->HeaderCrc = RtlComputeCrc32(0, UnitHeader, sizeof(DCU_HEADER));

            DataPtr = (PBYTE)UnitHeader + sizeof(DCU_HEADER);
            RtlCopyMemory(DataPtr, pbEncryptedBuffer, cbEncryptedBuffer);

            if (_filename_noext(NewName, lpInputFile)) {
                _strcat(NewName, TEXT(".cd"));
                supWriteBufferToFile(NewName, UnitHeader, (DWORD)sz);
            }
            HeapFree(GetProcessHeap(), 0, UnitHeader);
        }

    } while (FALSE);

    if (d_out.lpStart)
        DeltaFree(d_out.lpStart);

    if (pbHash)
        HeapFree(hHeap, 0, pbHash);

    if (pbEncryptedBuffer)
        HeapFree(hHeap, 0, pbEncryptedBuffer);

#ifdef _DEBUG
    if (_filename_noext(NewName, lpInputFile)) {
        _strcat(NewName, TEXT(".cd"));
        if (_filename_noext(KeyName, lpInputFile)) {
            _strcat(KeyName, TEXT(".key"));
            DecompressContainerUnit(NewName, KeyName);
        }
    }

    if (KeyName != NULL)
        HeapFree(hHeap, 0, KeyName);
#endif
    if (NewName != NULL)
        HeapFree(hHeap, 0, NewName);

    if (FileData != NULL)
        HeapFree(hHeap, 0, FileData);
}

#define UACME_KEY_SIZE      32
#define UACME_MAX_UNITS     12 //set actual number from github version
#define AKAGI_XOR_KEY       'naka'

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
    ptr = (PUCHAR)Buffer;

    do {
        *ptr ^= k;
        k = _rotl(k, 1);
        ptr++;
        --c;
    } while (c != 0);
}

//
// Keep in sync with Akagi
//
#define IDR_FUBUKI64 100
#define IDR_IKAZUCHI64 102
#define IDR_AKATSUKI64 103
#define IDR_KAMIKAZE64 104

#define IDR_FUBUKI32 200
#define IDR_IKAZUCHI32 202
#define IDR_KAMIKAZE 203

BOOL ProcessUnit(
    _In_ PWSTR UnitKeyName,
    _In_ ULONG UnitID,
    _In_ PDCK_HEADER UnitHeader)
{
    PWCHAR pBuffer;
    LARGE_INTEGER fs;

    pBuffer = (PWCHAR)supReadBufferFromFile(UnitKeyName, &fs);
    if (pBuffer) {
        if (fs.LowPart != UACME_KEY_SIZE) {

            MessageBox(
                GetDesktopWindow(),
                L"Unexpected key size.",
                NULL,
                MB_ICONERROR);

            return FALSE;
        }

        UnitHeader->Id = UnitID;
        RtlCopyMemory(UnitHeader->Data, pBuffer, fs.LowPart);
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }
    else {

        MessageBox(
            GetDesktopWindow(),
            L"File read error, memory not allocated.",
            NULL,
            MB_ICONERROR);

        return FALSE;
    }
    return TRUE;
}

VOID CreateSecretTables(VOID)
{
    INT c = 0;
    SIZE_T l = 0;
    DCK_HEADER S[UACME_MAX_UNITS];

    WCHAR szFileName[MAX_PATH * 2];

    RtlSecureZeroMemory(szFileName, sizeof(szFileName));

#ifdef _DEBUG
    _strcpy(szFileName, L"Z:\\HE\\UACME\\Compress");
#else
    GetCurrentDirectory(MAX_PATH, szFileName);
#endif

    _strcat(szFileName, L"\\");

    l = _strlen(szFileName);
    szFileName[l] = 0;

    //
    // Build secrets64
    //
    c = 0;
    RtlSecureZeroMemory(S, sizeof(S));

    _strcat(&szFileName[l], L"Akatsuki64.key");
    if (ProcessUnit(szFileName, IDR_AKATSUKI64, &S[c]))
        c++;

    szFileName[l] = 0;
    _strcat(&szFileName[l], L"Fubuki64.key");
    if (ProcessUnit(szFileName, IDR_FUBUKI64, &S[c]))
        c++;

    szFileName[l] = 0;
    _strcat(&szFileName[l], L"Fubuki32.key");
    if (ProcessUnit(szFileName, IDR_FUBUKI32, &S[c]))
        c++;

    szFileName[l] = 0;
    _strcat(&szFileName[l], L"Kamikaze.key");
    if (ProcessUnit(szFileName, IDR_KAMIKAZE64, &S[c]))
        c++;

    EncodeBuffer(S, c * sizeof(DCK_HEADER));
    szFileName[l] = 0;
    _strcat(&szFileName[l], L"secrets64.bin");
    supWriteBufferToFile(szFileName, S, c * sizeof(DCK_HEADER));

    //
    // Build secrets32
    //
    c = 0;
    RtlSecureZeroMemory(S, sizeof(S));
    szFileName[l] = 0;
    _strcat(&szFileName[l], L"Fubuki32.key");
    if (ProcessUnit(szFileName, IDR_FUBUKI32, &S[c]))
        c++;

    szFileName[l] = 0;
    _strcat(&szFileName[l], L"Kamikaze.key");
    if (ProcessUnit(szFileName, IDR_KAMIKAZE, &S[c]))
        c++;

    EncodeBuffer(S, c * sizeof(DCK_HEADER));
    szFileName[l] = 0;
    _strcat(&szFileName[l], L"secrets32.bin");
    supWriteBufferToFile(szFileName, S, c * sizeof(DCK_HEADER));
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
void main()
{
    LPWSTR  FirstParam = NULL;
    LPWSTR *szArglist;
    INT     nArgs = 0;

    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist) {

        if (nArgs > 1) {
            FirstParam = szArglist[1];
            if (FirstParam) {
                if (_strcmpi(FirstParam, L"--stable") == 0) {
                    CreateSecretTables();
                }
                else {
                    CreateContainerPackedUnit(FirstParam);
                }
            }
        }
        else {
            MessageBox(
                GetDesktopWindow(), 
                TEXT("Input file not specified"), 
                TEXT("Naka"), 
                MB_ICONINFORMATION);
        }

        LocalFree(szArglist);
    }

    ExitProcess(0);
}
