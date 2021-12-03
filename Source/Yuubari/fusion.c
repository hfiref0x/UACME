/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       FUSION.C
*
*  VERSION:     1.52
*
*  DATE:        23 Nov 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

ptrWTGetSignatureInfo WTGetSignatureInfo = NULL;

/*
* IsExemptedAutoApproveEXE
*
* Purpose:
*
* Check if the given file is Exempted AutoApprove EXE.
*
*/
BOOLEAN IsExemptedAutoApproveEXE(
    _In_ LPWSTR lpFileName,
    _In_ HANDLE hFile)
{
    SIGNATURE_INFO sigData;
    NTSTATUS status;

    LPWSTR lpName = _filename(lpFileName);

    if ((_strcmpi(lpName, L"sysprep.exe") == 0) ||
        (_strcmpi(lpName, L"inetmgr.exe") == 0))
    {
        RtlSecureZeroMemory(&sigData, sizeof(sigData));
        sigData.cbSize = sizeof(sigData);
        status = WTGetSignatureInfo(lpFileName, hFile,
            SIF_BASE_VERIFICATION | SIF_CHECK_OS_BINARY | SIF_CATALOG_SIGNED,
            &sigData,
            NULL, NULL);
        if (NT_SUCCESS(status))
            return ((sigData.SignatureState == SIGNATURE_STATE_VALID) && (sigData.fOSBinary != FALSE));
    }

    return FALSE;
}

/*
* SxsGetTocHeaderFromActivationContext
*
* Purpose:
*
* Locate and return pointer to Toc header in activation context.
*
*/
NTSTATUS SxsGetTocHeaderFromActivationContext(
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _Out_ PACTIVATION_CONTEXT_DATA_TOC_HEADER *TocHeader,
    _Out_opt_ PACTIVATION_CONTEXT_DATA *ActivationContextData
)
{
    NTSTATUS result = STATUS_UNSUCCESSFUL;
    ACTIVATION_CONTEXT_DATA *ContextData = NULL;
    ACTIVATION_CONTEXT_DATA_TOC_HEADER *Header;
    WCHAR szLog[0x100];

    if (ActivationContext == NULL)
        return STATUS_INVALID_PARAMETER_1;
    if (TocHeader == NULL)
        return STATUS_INVALID_PARAMETER_2;

    __try {

        do {

            RtlSecureZeroMemory(szLog, sizeof(szLog));

            ContextData = ActivationContext->ActivationContextData;

            if (ContextData->Magic != ACTIVATION_CONTEXT_DATA_MAGIC) {
                wsprintf(szLog, TEXT("ActivationContext Magic = %lx invalid"), ContextData->Magic);
                break;
            }

            if (
                (ContextData->HeaderSize != sizeof(ACTIVATION_CONTEXT_DATA)) ||
                (ContextData->HeaderSize > ContextData->TotalSize)
                )
            {
                wsprintf(szLog, TEXT("Unexpected data HeaderSize = %lu"), ContextData->HeaderSize);
                break;
            }

            if (ContextData->DefaultTocOffset > ContextData->TotalSize) {
                wsprintf(szLog, TEXT("Unexpected Toc offset %lx"), ContextData->DefaultTocOffset);
                break;
            }

            Header = (ACTIVATION_CONTEXT_DATA_TOC_HEADER *)(((LPBYTE)ContextData) + ContextData->DefaultTocOffset);
            if (Header->HeaderSize != sizeof(ACTIVATION_CONTEXT_DATA_TOC_HEADER)) {
                wsprintf(szLog, TEXT("Unexpected Toc HeaderSize %lu"), Header->HeaderSize);
                break;
            }

            if ((Header->FirstEntryOffset != 0) && (Header->EntryCount == 0)) {
                wsprintf(szLog, TEXT("Unexpected EntryCount %lu"), Header->EntryCount);
                break;
            }

            if ((Header->EntryCount > 0) && (Header->FirstEntryOffset == 0)) {
                wsprintf(szLog, TEXT("Unexpected Toc FirstEntryOffset %lu"), Header->FirstEntryOffset);
                break;
            }

            if (Header->FirstEntryOffset > ContextData->TotalSize) {
                wsprintf(szLog, TEXT("Toc FirstEntry offset = %lu invalid"), Header->FirstEntryOffset);
                break;
            }

            *TocHeader = Header;
            if (ActivationContextData != NULL)
                *ActivationContextData = ContextData;

            result = STATUS_SUCCESS;

        } while (FALSE);

        if (!NT_SUCCESS(result)) {
            OutputDebugString(szLog);
            return STATUS_SXS_CORRUPTION;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_SXS_CORRUPTION;
    }
    return result;
}

/*
* SxsGetStringSectionRedirectionDlls
*
* Purpose:
*
* Extract redirection dlls from string section entry.
*
*/
NTSTATUS SxsGetStringSectionRedirectionDlls(
    _In_ ACTIVATION_CONTEXT_STRING_SECTION_HEADER *SectionHeader,
    _In_ ACTIVATION_CONTEXT_STRING_SECTION_ENTRY *StringEntry,
    _Inout_ PDLL_REDIRECTION_LIST DllList
)
{
    ULONG SegmentIndex;
    NTSTATUS result = STATUS_SXS_KEY_NOT_FOUND;
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION *DataDll = NULL;
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT *DllPathSegment = NULL;
    DLL_REDIRECTION_LIST_ENTRY *DllListEntry = NULL;
    WCHAR *wszDllName = NULL;

    if (DllList == NULL)
        return STATUS_INVALID_PARAMETER;

    __try {

        DataDll = (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION*)(((LPBYTE)SectionHeader) + StringEntry->Offset);
        if (DataDll->PathSegmentOffset) {
            DllPathSegment = (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT*)(((LPBYTE)SectionHeader) + DataDll->PathSegmentOffset);
            if (DllPathSegment) {
                for (SegmentIndex = 0; SegmentIndex < DataDll->PathSegmentCount; SegmentIndex++) {
                    if ((DllPathSegment->Length) && (DllPathSegment->Offset)) {
                        DllListEntry = (DLL_REDIRECTION_LIST_ENTRY*)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(DLL_REDIRECTION_LIST_ENTRY));
                        if (DllListEntry) {
                            wszDllName = (WCHAR*)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, DllPathSegment->Length);
                            if (wszDllName) {
                                RtlCopyMemory(wszDllName, (((PBYTE)SectionHeader) + DllPathSegment->Offset), DllPathSegment->Length);
                                RtlInitUnicodeString(&DllListEntry->DllName, wszDllName);
                            }
                            RtlInterlockedPushEntrySList(&DllList->Header, &DllListEntry->ListEntry);
                        }
                    }
                    DllPathSegment = (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT*)(((LPBYTE)SectionHeader) + DataDll->Size);
                }
            }
            result = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_SXS_CORRUPTION;
    }

    return result;
}

/*
* SxsGetDllRedirectionFromActivationContext
*
* Purpose:
*
* Query redirection dll list from activation context data.
*
*/
NTSTATUS SxsGetDllRedirectionFromActivationContext(
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _In_ PDLL_REDIRECTION_LIST DllList
)
{
    ULONG i, j;
    NTSTATUS result = STATUS_UNSUCCESSFUL, status;
    ACTIVATION_CONTEXT_DATA *ContextData = NULL;
    ACTIVATION_CONTEXT_DATA_TOC_HEADER *TocHeader = NULL;
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY *TocEntry = NULL;
    ACTIVATION_CONTEXT_STRING_SECTION_HEADER *SectionHeader = NULL;
    ACTIVATION_CONTEXT_STRING_SECTION_ENTRY *StringEntry = NULL;

    WCHAR szLog[0x100];

    __try {

        if (ActivationContext == NULL)
            return STATUS_INVALID_PARAMETER_1;
        if (DllList == NULL)
            return STATUS_INVALID_PARAMETER_2;

        do {

            if (!NT_SUCCESS(SxsGetTocHeaderFromActivationContext(ActivationContext, &TocHeader, &ContextData)))
                break;

            TocEntry = (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(((LPBYTE)ContextData) + TocHeader->FirstEntryOffset);

            RtlInitializeSListHead(&DllList->Header);

            i = 1;
            while (i < TocHeader->EntryCount) {
                if (TocEntry->Format == ACTIVATION_CONTEXT_SECTION_FORMAT_STRING) {
                    SectionHeader = (ACTIVATION_CONTEXT_STRING_SECTION_HEADER*)(((LPBYTE)ContextData) + TocEntry->Offset);
                    if (SectionHeader->Magic != ACTIVATION_CONTEXT_STRING_SECTION_MAGIC) {
                        wsprintf(szLog, TEXT("Section Magic = %lx invalid"), SectionHeader->Magic);
                        OutputDebugString(szLog);
                        break;
                    }
                    if (SectionHeader->HeaderSize != sizeof(ACTIVATION_CONTEXT_STRING_SECTION_HEADER)) {
                        wsprintf(szLog, TEXT("Unexpected Section HeaderSize = %lu"), SectionHeader->HeaderSize);
                        OutputDebugString(szLog);
                        break;
                    }

                    if (TocEntry->Id == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) {
                        StringEntry = (ACTIVATION_CONTEXT_STRING_SECTION_ENTRY*)(((LPBYTE)SectionHeader) + SectionHeader->ElementListOffset);
                        status = SxsGetStringSectionRedirectionDlls(SectionHeader, StringEntry, DllList);
                        if (status == STATUS_SXS_CORRUPTION)
                            continue;

                        for (j = 1; j < SectionHeader->ElementCount; j++) {
                            StringEntry = (ACTIVATION_CONTEXT_STRING_SECTION_ENTRY*)(((LPBYTE)StringEntry) + sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY));
                            status = SxsGetStringSectionRedirectionDlls(SectionHeader, StringEntry, DllList);
                            if (status == STATUS_SXS_CORRUPTION)
                                continue;
                        }
                    }
                }
                TocEntry = (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(((LPBYTE)TocEntry) + sizeof(ACTIVATION_CONTEXT_DATA_TOC_ENTRY));
                i += 1;
            } //while (i < TocHeader->EntryCount)

            DllList->Depth = RtlQueryDepthSList(&DllList->Header);
            if (DllList->Depth == 0)
                result = STATUS_SXS_SECTION_NOT_FOUND;
            else
                result = STATUS_SUCCESS;

        } while (FALSE);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_SXS_CORRUPTION;
    }

    return result;
}

/*
* FusionProbeForRedirectedDlls
*
* Purpose:
*
* Probe activation context for redirection dlls and output them if found.
*
*/
NTSTATUS FusionProbeForRedirectedDlls(
    _In_ LPWSTR lpFileName,
    _In_ ACTIVATION_CONTEXT *ActivationContext,
    _In_ OUTPUTCALLBACK OutputCallback
)
{
    NTSTATUS status;
    SLIST_ENTRY *ListEntry = NULL;
    DLL_REDIRECTION_LIST_ENTRY *DllData = NULL;
    UAC_FUSION_DATA_DLL FusionRedirectedDll;
    DLL_REDIRECTION_LIST DllList;

    __try {
        RtlSecureZeroMemory(&DllList, sizeof(DllList));
        status = SxsGetDllRedirectionFromActivationContext(ActivationContext, &DllList);
        if (NT_SUCCESS(status)) {
            while (DllList.Depth) {
                ListEntry = RtlInterlockedPopEntrySList(&DllList.Header);
                if (ListEntry) {
                    DllData = (PDLL_REDIRECTION_ENTRY)ListEntry;
                    RtlSecureZeroMemory(&FusionRedirectedDll, sizeof(FusionRedirectedDll));

                    FusionRedirectedDll.DataType = UacFusionDataRedirectedDllType;
                    FusionRedirectedDll.FileName = lpFileName;
                    FusionRedirectedDll.DllName = DllData->DllName.Buffer;
                    OutputCallback((PVOID)&FusionRedirectedDll);

                    RtlFreeUnicodeString(&DllData->DllName);
                    RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, DllData);
                }
                DllList.Depth--;
            }
            RtlInterlockedFlushSList(&DllList.Header);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_SXS_CORRUPTION;
    }
    return status;
}

/*
* FusionCheckFile
*
* Purpose:
*
* Query file manifest data related to security.
*
*/
VOID FusionCheckFile(
    _In_ LPWSTR lpDirectory,
    _In_ WIN32_FIND_DATA *fdata,
    _In_ OUTPUTCALLBACK OutputCallback
)
{
    DWORD               lastError;
    NTSTATUS            status;
    HANDLE              hFile = NULL, hSection = NULL, hActCtx = NULL;
    LPWSTR              FileName = NULL, pt = NULL;
    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize, sz, l;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usFileName;
    IO_STATUS_BLOCK     iosb;
    ULONG_PTR           ResourceSize = 0;
    ULONG_PTR           IdPath[3];

    ACTCTX      ctx;

    SIGNATURE_INFO sigData;
    UAC_FUSION_DATA FusionCommonData;
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ctxrl;
    WCHAR           szValue[100];

    usFileName.Buffer = NULL;

    do {

        if ((lpDirectory == NULL) || (fdata == NULL))
            break;

        if (fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            break;

        sz = (_strlen(lpDirectory) + _strlen(fdata->cFileName)) * sizeof(WCHAR) + sizeof(UNICODE_NULL);
        sz = ALIGN_UP_BY(sz, PAGE_SIZE);
        FileName = (LPWSTR)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (FileName == NULL)
            break;

        pt = FileName;

        _strcpy(FileName, lpDirectory);
        l = _strlen(FileName);
        if (pt[l - 1] != L'\\') {
            pt[l] = L'\\';
            pt[l + 1] = 0;
        }
        _strcat(FileName, fdata->cFileName);

        if (RtlDosPathNameToNtPathName_U(FileName, &usFileName, NULL, NULL) == FALSE)
            break;

        InitializeObjectAttributes(&attr, &usFileName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);
        RtlSecureZeroMemory(&iosb, sizeof(iosb));

        //
        // Open file and map it.
        //
        status = NtCreateFile(&hFile, SYNCHRONIZE | FILE_READ_DATA,
            &attr, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status))
            break;

        status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
            NULL, PAGE_READONLY, SEC_IMAGE, hFile);
        if (!NT_SUCCESS(status))
            break;

        DllBase = NULL;
        DllVirtualSize = 0;
        status = NtMapViewOfSection(hSection, NtCurrentProcess(), (PVOID*)&DllBase,
            0, 0, NULL, &DllVirtualSize, ViewUnmap, 0, PAGE_READONLY);
        if (!NT_SUCCESS(status))
            break;

        RtlSecureZeroMemory(&FusionCommonData, sizeof(FusionCommonData));
        FusionCommonData.Name = FileName;

        //
        // Look for embedded manifest resource
        //
        IdPath[0] = (ULONG_PTR)RT_MANIFEST;
        IdPath[1] = (ULONG_PTR)CREATEPROCESS_MANIFEST_RESOURCE_ID;
        IdPath[2] = 0;
        status = LdrResSearchResource(DllBase, (ULONG_PTR*)&IdPath, 3, 0,
            (LPVOID*)&pt, (ULONG_PTR*)&ResourceSize, NULL, NULL);

        FusionCommonData.IsFusion = NT_SUCCESS(status);

        //
        // File has no manifest embedded.
        //
        if (FusionCommonData.IsFusion == FALSE) {
            switch (status) {
            case STATUS_RESOURCE_TYPE_NOT_FOUND:
                OutputDebugString(TEXT("LdrResSearchResource: resource type not found\r\n"));
                break;
            case STATUS_RESOURCE_DATA_NOT_FOUND:
                OutputDebugString(TEXT("LdrResSearchResource: resource data not found\r\n"));
                break;
            case STATUS_RESOURCE_NAME_NOT_FOUND:
                OutputDebugString(TEXT("LdrResSearchResource: resource name not found\r\n"));
                break;
            default:
                break;
            }

            //
            // No embedded manifest, possible manifest hijacking for versions below RS1
            //
            if (
                (status == STATUS_RESOURCE_TYPE_NOT_FOUND) ||
                (status == STATUS_RESOURCE_DATA_NOT_FOUND) ||
                (status == STATUS_RESOURCE_NAME_NOT_FOUND)
                ) {
                if (WTGetSignatureInfo != NULL) {
                    //
                    // Check if file is signed as part of an operation system
                    //
                    RtlSecureZeroMemory(&sigData, sizeof(sigData));
                    sigData.cbSize = sizeof(sigData);
                    status = WTGetSignatureInfo(FileName, hFile,
                        SIF_BASE_VERIFICATION | SIF_CHECK_OS_BINARY | SIF_CATALOG_SIGNED,
                        &sigData,
                        NULL, NULL);
                    if (NT_SUCCESS(status)) {
                        if (sigData.fOSBinary != FALSE) {

                            RtlSecureZeroMemory(&FusionCommonData, sizeof(FusionCommonData));
                            FusionCommonData.Name = FileName;
                            FusionCommonData.IsOSBinary = TRUE;

                            //
                            // Check if signature valid or trusted
                            //
                            FusionCommonData.IsSignatureValidOrTrusted = ((sigData.SignatureState == SIGNATURE_STATE_TRUSTED) ||
                                (sigData.SignatureState == SIGNATURE_STATE_VALID));

                            OutputCallback((PVOID)&FusionCommonData);
                        }
                    }
                }
                else { //WTGetSignatureInfo != NULL

                    //
                    // On Windows 7 this API is not available, just output result.
                    //
                    RtlSecureZeroMemory(&FusionCommonData, sizeof(FusionCommonData));
                    FusionCommonData.Name = FileName;
                    OutputCallback((PVOID)&FusionCommonData);
                }
            }

            //break the global loop
            break;
        }

        //
        // File has manifest, create activation context for it.
        //
        RtlSecureZeroMemory(&ctx, sizeof(ctx));
        ctx.cbSize = sizeof(ACTCTX);
        ctx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
        ctx.lpResourceName = CREATEPROCESS_MANIFEST_RESOURCE_ID;
        ctx.lpSource = FileName;
        ctx.hModule = (HMODULE)DllBase;

        hActCtx = CreateActCtx(&ctx);
        if (hActCtx == INVALID_HANDLE_VALUE) {
            lastError = GetLastError();
            RtlSecureZeroMemory(szValue, sizeof(szValue));
            _strcpy(szValue, TEXT("Unexpected activation context failure ="));
            ultostr(lastError, _strend(szValue));
            _strcat(szValue, TEXT("\r\n"));
            OutputDebugString(szValue);
            break;
        }

        //
        // Query run level and uiAccess information.
        //
        RtlSecureZeroMemory(&ctxrl, sizeof(ctxrl));
        status = RtlQueryInformationActivationContext(RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_NO_ADDREF,
            (PCACTIVATION_CONTEXT)hActCtx,
            NULL,
            RunlevelInformationInActivationContext,
            (PVOID)&ctxrl,
            sizeof(ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION),
            NULL);

        if (NT_SUCCESS(status)) {
            RtlCopyMemory(&FusionCommonData.RunLevel, &ctxrl, sizeof(ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION));
        }

        //
        // DotNet application highly vulnerable for Dll Hijacking attacks.
        // Always check if file is DotNet origin.
        //
        FusionCommonData.IsDotNet = supIsCorImageFile(DllBase);

        //
        // Query autoelevate setting.
        //
        l = 0;
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        status = RtlQueryActivationContextApplicationSettings(0, hActCtx, NULL, TEXT("autoElevate"), (PWSTR)&szValue, sizeof(szValue), &l);
        if (NT_SUCCESS(status)) {

            //
            // Actually appinfo only looks for 'T' or 't' symbol 
            // for performance reasons perhaps
            //
            if (_strcmpi(szValue, TEXT("true")) == 0)
                FusionCommonData.AutoElevateState = AutoElevateEnabled;
            else
                //
                // Several former autoelevate applications has autoelevated strictly 
                // disabled in manifest as part of their UAC fixes.
                //
                if (_strcmpi(szValue, TEXT("false")) == 0)
                    FusionCommonData.AutoElevateState = AutoElevateDisabled;
        }
        else {

            //
            // Check specific "exempted" autoelevated files, they may not have "autoelevate" in manifest.
            //
            if (IsExemptedAutoApproveEXE(FileName, hFile)) {
                FusionCommonData.AutoElevateState = AutoElevateExempted;
            }

            //
            // Query settings failed, check if it known error like sxs key not exist.         
            //
            if (status != STATUS_SXS_KEY_NOT_FOUND) {
                RtlSecureZeroMemory(szValue, sizeof(szValue));
                _strcpy(szValue, TEXT("QueryActivationContext error ="));
                ultostr(status, _strend(szValue));
                _strcat(szValue, TEXT("\r\n"));
                OutputDebugString(szValue);

                //
                // Don't output anything, just break, it is unexpected situation.
                //
                break;
            }
        }

        //
        // Even if autoElevate key could be not found, application still can be in whitelist.
        // As in case of inetmgr.exe on RS1+, so check if it has redirection dlls.
        //
        OutputCallback((PVOID)&FusionCommonData);

        //
        // Print redirection dlls from activation context
        //
        FusionProbeForRedirectedDlls(FileName, (PACTIVATION_CONTEXT)hActCtx, OutputCallback);


    } while (FALSE);

    if (hActCtx != NULL)
        ReleaseActCtx(hActCtx);

    if (usFileName.Buffer != NULL)
        RtlFreeUnicodeString(&usFileName);

    if (DllBase != NULL)
        NtUnmapViewOfSection(NtCurrentProcess(), DllBase);

    if (hSection != NULL)
        NtClose(hSection);

    if (hFile != NULL)
        NtClose(hFile);

    if (FileName != NULL)
        VirtualFree(FileName, 0, MEM_RELEASE);
}

/*
* FusionScanFiles
*
* Purpose:
*
* Scan directory for files of given type.
*
*/
VOID FusionScanFiles(
    _In_ LPWSTR lpDirectory,
    _In_ OUTPUTCALLBACK OutputCallback
)
{
    HANDLE hFile;
    LPWSTR lpLookupDirectory = NULL;
    SIZE_T sz;
    WIN32_FIND_DATA fdata;

    sz = (_strlen(lpDirectory) + MAX_PATH) * sizeof(WCHAR);
    lpLookupDirectory = (LPWSTR)supHeapAlloc(sz);
    if (lpLookupDirectory) {
        _strncpy(lpLookupDirectory, MAX_PATH, lpDirectory, MAX_PATH);
        _strcat(lpLookupDirectory, TEXT("\\*.exe"));

        hFile = FindFirstFile(lpLookupDirectory, &fdata);
        if (hFile != INVALID_HANDLE_VALUE) {
            do {
                FusionCheckFile(lpDirectory, &fdata, OutputCallback);
            } while (FindNextFile(hFile, &fdata));
            FindClose(hFile);
        }
        supHeapFree(lpLookupDirectory);
    }
}

/*
* FusionScanDirectory
*
* Purpose:
*
* Recursively scan directories.
*
*/
VOID FusionScanDirectory(
    _In_ LPWSTR lpDirectory,
    _In_ OUTPUTCALLBACK OutputCallback
)
{
    SIZE_T              cchBuffer;
    HANDLE              hDirectory;
    LPWSTR              lpFilePath;
    WIN32_FIND_DATA     fdata;

    FusionScanFiles(lpDirectory, OutputCallback);

    cchBuffer = 4 + MAX_PATH + _strlen(lpDirectory);
    lpFilePath = (LPWSTR)supHeapAlloc(cchBuffer * sizeof(WCHAR));
    if (lpFilePath) {

        _strcpy(lpFilePath, lpDirectory);
        supConcatenatePaths(lpFilePath, L"*", cchBuffer);

        hDirectory = FindFirstFile(lpFilePath, &fdata);
        if (hDirectory != INVALID_HANDLE_VALUE) {
            do {
                if ((fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    (fdata.cFileName[0] != L'.')
                    )
                {
                    _strcpy(lpFilePath, lpDirectory);
                    supConcatenatePaths(lpFilePath, fdata.cFileName, cchBuffer);
                    FusionScanDirectory(lpFilePath, OutputCallback);
                }
            } while (FindNextFile(hDirectory, &fdata));
            FindClose(hDirectory);
        }

        supHeapFree(lpFilePath);
    }
}
