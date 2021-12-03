/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       FUSUTIL.C
*
*  VERSION:     3.58
*
*  DATE:        01 Dec 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* fusUtilInitFusion
*
* Purpose:
*
* Load .NET Assembly Manager dll and remember function pointers.
*
*/
BOOLEAN fusUtilInitFusion(
    _In_ DWORD dwVersion
)
{
    HMODULE hFusion;
    LPCWSTR lpFusionDir;
    pfnCreateAssemblyCache CreateAssemblyCache;
    pfnCreateAssemblyEnum CreateAssemblyEnum;

    WCHAR szBuffer[MAX_PATH * 2];

    if (g_ctx->FusionContext.Initialized)
        return TRUE;

    if (dwVersion != 2 && dwVersion != 4)
        return FALSE;

    //
    // Build path to assembly manager dll
    //
    _strcpy(szBuffer, g_ctx->szSystemRoot);
    _strcat(szBuffer, MSNETFRAMEWORK_DIR);

#ifdef _WIN64
    _strcat(szBuffer, TEXT("64"));
#endif

    if (dwVersion == 2)
        lpFusionDir = NET2_DIR;
    else
        lpFusionDir = NET4_DIR;

    supConcatenatePaths(szBuffer, lpFusionDir, ARRAYSIZE(szBuffer));
    supConcatenatePaths(szBuffer, TEXT("fusion.dll"), ARRAYSIZE(szBuffer));

    hFusion = LoadLibraryEx(szBuffer, NULL, 0);
    if (hFusion == NULL)
        return FALSE;

    CreateAssemblyCache = (pfnCreateAssemblyCache)GetProcAddress(hFusion, "CreateAssemblyCache");
    CreateAssemblyEnum = (pfnCreateAssemblyEnum)GetProcAddress(hFusion, "CreateAssemblyEnum");
    if (CreateAssemblyCache == NULL ||
        CreateAssemblyEnum == NULL)
    {
        FreeLibrary(hFusion);
        return FALSE;
    }

    g_ctx->FusionContext.hFusion = hFusion;
    g_ctx->FusionContext.CreateAssemblyCache = CreateAssemblyCache;
    g_ctx->FusionContext.CreateAssemblyEnum = CreateAssemblyEnum;
    g_ctx->FusionContext.Initialized = TRUE;

    return TRUE;
}

/*
* fusUtilBinToUnicodeHex
*
* Purpose:
*
* Bin to Hex special edition.
*
*/
VOID fusUtilBinToUnicodeHex(
    _In_ const BYTE* pSrc,
    _In_ UINT cSrc,
    _Out_cap_(2 * cSrc + 1) LPWSTR pDst)
{
    UINT x;
    UINT y;

#define TOHEX(a) (WCHAR)((a)>=10 ? L'a'+(a)-10 : L'0'+(a))

    for (x = 0, y = 0; x < cSrc; ++x)
    {
        UINT v;
        v = pSrc[x] >> 4;
        pDst[y++] = TOHEX(v);
        v = pSrc[x] & 0x0f;
        pDst[y++] = TOHEX(v);
    }
    pDst[y] = L'\0';
}

/*
* fusUtilGetAssemblyName
*
* Purpose:
*
* Return assembly name.
*
* Note: Use supHeapFree to release lpAssemblyName allocated memory.
*
*/
HRESULT fusUtilGetAssemblyName(
    _In_ IAssemblyName* pInterface,
    _Inout_ LPWSTR* lpName,
    _Out_opt_ PSIZE_T pcchName,
    _Inout_opt_ LPWSTR* lpDisplayName,
    _Out_opt_ PSIZE_T pcchDisplayName
)
{
    DWORD cchName = 0;
    HRESULT hr;
    LPWSTR assemblyName = NULL, displayName = NULL;

    do {

        if (pcchName) *pcchName = 0;
        if (pcchDisplayName) *pcchDisplayName = 0;

        hr = pInterface->lpVtbl->GetName(pInterface, &cchName, NULL);
        if (hr != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
            break;

        assemblyName = (LPWSTR)supHeapAlloc((cchName * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
        if (assemblyName)
            hr = pInterface->lpVtbl->GetName(pInterface, &cchName, (LPOLESTR)assemblyName);
        else
            hr = E_OUTOFMEMORY;

        if (pcchName) {
            if (SUCCEEDED(hr))
                *pcchName = cchName;
        }

        cchName = 0;
        hr = pInterface->lpVtbl->GetDisplayName(pInterface, NULL, &cchName, 0);
        if (hr != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
            break;

        displayName = (LPWSTR)supHeapAlloc((cchName * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
        if (displayName)
            hr = pInterface->lpVtbl->GetDisplayName(pInterface, (LPOLESTR)displayName, &cchName, 0);
        else
            hr = E_OUTOFMEMORY;

        if (pcchDisplayName) {
            if (SUCCEEDED(hr))
                *pcchDisplayName = cchName;
        }

    } while (FALSE);

    *lpName = assemblyName;
    if (lpDisplayName)
        *lpDisplayName = displayName;

    return hr;
}

/*
* fusUtilGetAssemblyMVIDFromZapCache
*
* Purpose:
*
* Query cache zap assembly mvid.
*
*/
BOOL fusUtilGetAssemblyMVIDFromZapCache(
    _In_ LPCWSTR AssemblyName,
    _Inout_ GUID* ModuleVersionId
)
{
    BOOL bFound = FALSE, bResult = FALSE;
    HRESULT hr;
    IAssemblyEnum* asmEnum = NULL;
    IAssemblyName* asmName = NULL;
    LPWSTR lpAssemblyName = NULL;
    DWORD dwSize;

    do {

        hr = g_ctx->FusionContext.CreateAssemblyEnum(&asmEnum, NULL, NULL, ASM_CACHE_ZAP, NULL);
        if ((FAILED(hr)) || (asmEnum == NULL))
            break;

        //
        // Locate assembly and remember it name/display name.
        //
        while ((hr = asmEnum->lpVtbl->GetNextAssembly(asmEnum, NULL, &asmName, 0)) == S_OK) {

            if (SUCCEEDED(fusUtilGetAssemblyName(asmName,
                &lpAssemblyName,
                NULL,
                NULL,
                NULL)))
            {

                if (_strcmpi(AssemblyName, lpAssemblyName) == 0) {
                    bFound = TRUE;
                    break;
                }
                else {
                    supHeapFree(lpAssemblyName);
                    lpAssemblyName = NULL;
                }

            }

            asmName->lpVtbl->Finalize(asmName);
            asmName->lpVtbl->Release(asmName);
        }

        if (FAILED(hr) || bFound == FALSE)
            break;

        dwSize = 0;
        hr = asmName->lpVtbl->GetProperty(asmName, ASM_NAME_MVID, NULL, &dwSize);
        if (hr != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
            break;

        if (dwSize != sizeof(GUID))
            break;

        hr = asmName->lpVtbl->GetProperty(asmName, ASM_NAME_MVID, ModuleVersionId, &dwSize);
        bResult = SUCCEEDED(hr);

    } while (FALSE);

    if (asmName) {
        asmName->lpVtbl->Finalize(asmName);
        asmName->lpVtbl->Release(asmName);
    }

    if (asmEnum)
        asmEnum->lpVtbl->Release(asmEnum);

    if (lpAssemblyName)
        supHeapFree(lpAssemblyName);

    return bResult;
}

/*
* fusUtilGetAssemblyPath
*
* Purpose:
*
* Return given assembly file path.
*
* Note: Use supHeapFree to release lpAssemblyPath allocated memory.
*
*/
HRESULT fusUtilGetAssemblyPath(
    _In_ IAssemblyCache* pInterface,
    _In_ LPCWSTR lpAssemblyName,
    _Inout_ LPCWSTR* lpAssemblyPath
)
{
    HRESULT hr = E_FAIL;
    ASSEMBLY_INFO asmInfo;
    LPWSTR assemblyPath;

    *lpAssemblyPath = NULL;

    RtlSecureZeroMemory(&asmInfo, sizeof(asmInfo));

    pInterface->lpVtbl->QueryAssemblyInfo(pInterface,
        QUERYASMINFO_FLAG_GETSIZE,
        lpAssemblyName,
        &asmInfo);

    if (asmInfo.cchBuf == 0) //empty pszCurrentAssemblyPathBuf
        return E_FAIL;

    assemblyPath = (LPWSTR)supHeapAlloc(asmInfo.cchBuf * sizeof(WCHAR));
    if (assemblyPath == NULL)
        return E_FAIL;

    asmInfo.pszCurrentAssemblyPathBuf = assemblyPath;

    hr = pInterface->lpVtbl->QueryAssemblyInfo(pInterface,
        QUERYASMINFO_FLAG_VALIDATE,
        lpAssemblyName,
        &asmInfo);

    if (!SUCCEEDED(hr)) {
        supHeapFree(asmInfo.pszCurrentAssemblyPathBuf);
    }
    else {
        *lpAssemblyPath = assemblyPath;
    }

    return hr;
}

/*
* fusUtilGetAssemblyPathByName
*
* Purpose:
*
* Return given assembly file path.
*
* Note: Use supHeapFree to release lpAssemblyPath allocated memory.
*
*/
BOOLEAN fusUtilGetAssemblyPathByName(
    _In_ LPWSTR lpAssemblyName,
    _Inout_ LPWSTR* lpAssemblyPath
)
{
    HRESULT hr;
    IAssemblyCache* asmCache = NULL;

    do {

        hr = g_ctx->FusionContext.CreateAssemblyCache(&asmCache, 0);
        if ((FAILED(hr)) || (asmCache == NULL))
            break;

        hr = fusUtilGetAssemblyPath(asmCache,
            lpAssemblyName,
            lpAssemblyPath);

        asmCache->lpVtbl->Release(asmCache);

    } while (FALSE);

    return SUCCEEDED(hr);
}

/*
* fusUtilReferenceStreamByName
*
* Purpose:
*
* Query stream pointer by stream name.
*
*/
BOOL fusUtilReferenceStreamByName(
    _In_ STORAGEHEADER* StorageHeader,
    _In_ LPCSTR StreamName,
    _Out_ PSTORAGESTREAM* StreamRef
)
{
    WORD i;
    PBYTE streamPtr;
    STORAGESTREAM* pStorStream;
    ULONG offset;
    SIZE_T nameLen;

    *StreamRef = NULL;

    streamPtr = (PBYTE)RtlOffsetToPointer(StorageHeader, sizeof(STORAGEHEADER));

    i = 0;

    do {
        pStorStream = (STORAGESTREAM*)streamPtr;
        if (_strcmpi_a(pStorStream->rcName, StreamName) == 0) {
            *StreamRef = pStorStream;
            return TRUE;
        }

        nameLen = _strlen_a(pStorStream->rcName) + 1;
        offset = ALIGN_UP(FIELD_OFFSET(STORAGESTREAM, rcName) + nameLen, ULONG);
        streamPtr = (PBYTE)RtlOffsetToPointer(streamPtr, offset);
        i++;

    } while (i < StorageHeader->iStreams);

    return FALSE;
}

/*
* fusUtilGetImageMVID
*
* Purpose:
*
* Query MVID value from image metadata.
*
* Ref: https://www.ntcore.com/files/dotnetformat.htm
*
*/
BOOL fusUtilGetImageMVID(
    _In_ LPCWSTR lpImageName,
    _Out_ GUID* ModuleVersionId
)
{
    BOOL bResult = FALSE;
    HMODULE hModule;
    PVOID baseAddress;
    IMAGE_COR20_HEADER* cliHeader;
    ULONG sz, offset, mvidIndex, i;

    STORAGESIGNATURE* pStorSign;
    STORAGEHEADER* pStorHeader;
    STORAGESTREAM* pStreamGuid;
    STORAGESTREAM* pStreamTables;
    STORAGETABLESHEADER* pTablesHeader;

    PBYTE tablesPtr;
    LPGUID guidsPtr;

    RPC_STATUS st;

    st = UuidCreateNil(ModuleVersionId);
    if (st != S_OK)
        return FALSE;

    hModule = LoadLibraryEx(lpImageName, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (hModule) {

        baseAddress = (PBYTE)(((ULONG_PTR)hModule) & ~3);

        cliHeader = (IMAGE_COR20_HEADER*)RtlImageDirectoryEntryToData(baseAddress, TRUE,
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &sz);

        pStorSign = (STORAGESIGNATURE*)RtlOffsetToPointer(baseAddress, cliHeader->MetaData.VirtualAddress);
        if (pStorSign->lSignature == STORAGE_MAGIC_SIG) {

            offset = FIELD_OFFSET(STORAGESIGNATURE, pVersion) + pStorSign->iVersionString;
            pStorHeader = (STORAGEHEADER*)RtlOffsetToPointer(pStorSign, offset);

            pStreamTables = NULL;
            if (!fusUtilReferenceStreamByName(pStorHeader, "#~", &pStreamTables)) {
                FreeLibrary(hModule);
                return FALSE;
            }

            pStreamGuid = NULL;
            if (!fusUtilReferenceStreamByName(pStorHeader, "#GUID", &pStreamGuid)) {
                FreeLibrary(hModule);
                return FALSE;
            }

            pTablesHeader = (STORAGETABLESHEADER*)RtlOffsetToPointer(pStorSign, pStreamTables->iOffset);
            sz = 0;

            //
            // __popcnt64 or the garbage code below
            //
            for (i = 0; i < MAX_CLR_TABLES; i++)
                if ((i < 32 && (pTablesHeader->Valid.u.LowPart >> i) & 1) ||
                    (i >= 32 && (pTablesHeader->Valid.u.HighPart >> i) & 1))
                {
                    sz++;
                }

            offset = FIELD_OFFSET(STORAGETABLESHEADER, Rows) + (sz * sizeof(ULONG));

            tablesPtr = (PBYTE)RtlOffsetToPointer(pTablesHeader, offset);
            tablesPtr += sizeof(WORD);

            if (pTablesHeader->HeapOffsetSizes & MD_STRINGS_BIT)
                tablesPtr += sizeof(DWORD);
            else
                tablesPtr += sizeof(WORD);

            if (pTablesHeader->HeapOffsetSizes & MD_GUIDS_BIT)
                mvidIndex = *(PULONG)tablesPtr;
            else
                mvidIndex = *(PUSHORT)tablesPtr;

            if (mvidIndex) {
                guidsPtr = (LPGUID)RtlOffsetToPointer(pStorSign, pStreamGuid->iOffset);
                RtlCopyMemory(ModuleVersionId, &guidsPtr[mvidIndex - 1], sizeof(GUID));
                bResult = TRUE;
            }
        }

        FreeLibrary(hModule);
    }

    return bResult;
}


/*
* fusUtilpFusionScanFiles
*
* Purpose:
*
* Scan directory for files of given type.
*
* Note:
* Return TRUE to abort further scan, FALSE otherwise.
*
*/
BOOL fusUtilpFusionScanFiles(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpExtension,
    _In_ pfnFusionScanFilesCallback pfnCallback,
    _In_opt_ PVOID pvUserContext
)
{
    BOOL bResult = FALSE;
    HANDLE hFile;
    LPWSTR lpLookupDirectory = NULL;
    SIZE_T cchBuffer;
    WIN32_FIND_DATA fdata;

    //
    // Allocate buffer for path to the file including backslash and terminating null.
    //
    cchBuffer = (2 + _strlen(lpDirectory) + _strlen(lpExtension));
    lpLookupDirectory = (LPWSTR)supHeapAlloc(cchBuffer * sizeof(WCHAR));
    if (lpLookupDirectory) {

        _strcpy(lpLookupDirectory, lpDirectory);
        supConcatenatePaths(lpLookupDirectory, lpExtension, cchBuffer);

        hFile = FindFirstFile(lpLookupDirectory, &fdata);
        if (hFile != INVALID_HANDLE_VALUE) {
            do {

                if (pfnCallback(lpDirectory, &fdata, pvUserContext)) {
                    bResult = TRUE;
                    break;
                }

            } while (FindNextFile(hFile, &fdata));
            FindClose(hFile);
        }
        supHeapFree(lpLookupDirectory);
    }

    return bResult;
}

/*
* fusUtilScanDirectory
*
* Purpose:
*
* Recursively scan directories looking for files with given extension.
*
*/
BOOL fusUtilScanDirectory(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpExtension,
    _In_ pfnFusionScanFilesCallback pfnCallback,
    _In_opt_ PVOID pvUserContext
)
{
    BOOL                bResult = FALSE;
    SIZE_T              cchBuffer;
    HANDLE              hDirectory;
    LPWSTR              lpFilePath;
    WIN32_FIND_DATA     fdata;

    if (fusUtilpFusionScanFiles(lpDirectory, lpExtension, pfnCallback, pvUserContext))
        return TRUE;

    //
    // Allocate buffer for path including backslash, search mask, terminating null and space for filename.
    //
    cchBuffer = 4 + MAX_PATH + _strlen(lpDirectory);
    lpFilePath = (LPWSTR)supHeapAlloc(cchBuffer * sizeof(WCHAR));
    if (lpFilePath == NULL)
        return FALSE;

    _strcpy(lpFilePath, lpDirectory);
    supConcatenatePaths(lpFilePath, TEXT("*"), cchBuffer);

    hDirectory = FindFirstFile(lpFilePath, &fdata);
    if (hDirectory != INVALID_HANDLE_VALUE) {
        do {
            if ((fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                (fdata.cFileName[0] != L'.')
                )
            {
                _strcpy(lpFilePath, lpDirectory);
                _strcat(lpFilePath, fdata.cFileName);

                bResult = fusUtilScanDirectory(lpFilePath,
                    lpExtension,
                    pfnCallback,
                    pvUserContext);

                if (bResult)
                    break;

            }
        } while (FindNextFile(hDirectory, &fdata));
        FindClose(hDirectory);
    }

    supHeapFree(lpFilePath);

    return bResult;
}

/*
* fusUtilFindFileByMVIDCallback
*
* Purpose:
*
* supFusionScanDirectory callback for MVID comparison.
*
*/
BOOL fusUtilFindFileByMVIDCallback(
    _In_ LPWSTR CurrentDirectory,
    _In_ WIN32_FIND_DATA* FindData,
    _In_ PVOID UserContext
)
{
    FUSION_SCAN_PARAM* ScanParam = (FUSION_SCAN_PARAM*)UserContext;
    LPWSTR lpFileName;
    SIZE_T cchBuffer;
    GUID mVid;
    RPC_STATUS rpcStatus;

    cchBuffer = 2 + MAX_PATH + _strlen(CurrentDirectory);
    lpFileName = (LPWSTR)supHeapAlloc(cchBuffer * sizeof(WCHAR));
    if (lpFileName) {

        _strcpy(lpFileName, CurrentDirectory);
        supConcatenatePaths(lpFileName, FindData->cFileName, cchBuffer);

        if (fusUtilGetImageMVID(lpFileName, &mVid)) {

            if (0 == UuidCompare(ScanParam->ReferenceMVID,
                &mVid,
                &rpcStatus))
            {
                ScanParam->lpFileName = lpFileName;
                return TRUE;
            }
        }

        supHeapFree(lpFileName);
    }
    return FALSE;
}

#define NI_DLL_EXT L".ni.dll"
#define NI_DLL_EXT_SIZE (sizeof(NI_DLL_EXT) - sizeof(UNICODE_NULL))
#define NI_DLL_AUX_EXT L".ni.dll.aux"
#define NI_DLL_AUX_EXT_SIZE (sizeof(NI_DLL_EXT) - sizeof(UNICODE_NULL))

/*
* fusUtilCombineNativeImageCacheName
*
* Purpose:
*
* Build cache image name from assembly name.
*
*/
VOID fusUtilCombineNativeImageCacheName(
    _In_ LPCWSTR lpAssemblyName,
    _Inout_ LPWSTR lpNativeImageName,
    _In_ DWORD cchNativeName,
    _In_ BOOLEAN fIsAux
)
{
    supConcatenatePaths(lpNativeImageName, lpAssemblyName, cchNativeName);

    if (fIsAux) {
        _strcat(lpNativeImageName, NI_DLL_AUX_EXT);
    }
    else {
        _strcat(lpNativeImageName, NI_DLL_EXT);
    }

}
