/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       FUSION.C
*
*  VERSION:     1.0F
*
*  DATE:        18 Feb 2017
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
* CheckFile
*
* Purpose:
*
* Query file manifest data related to security.
*
*/
VOID CheckFile(
    LPWSTR lpDirectory,
    WIN32_FIND_DATA *fdata,
    FUSIONCALLBACK OutputCallback
    )
{
    BOOL                bCond = FALSE;
    DWORD               lastError;
    NTSTATUS            status;
    HANDLE              hFile = NULL, hSection = NULL, hActCtx = NULL;
    LPWSTR              FileName = NULL, pt;
    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize, sz, l;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usFileName;
    IO_STATUS_BLOCK     iosb;

    ULONG_PTR   IdPath[3], ResourceSize = 0;
    WCHAR       szValue[100];
    ACTCTX      ctx;

    SIGNATURE_INFO sigData;
    UAC_FUSION_DATA CallbackData;
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ctxrl;

    usFileName.Buffer = NULL;

    do {

        if ((lpDirectory == NULL) || (fdata == NULL) || (OutputCallback == NULL))
            break;

        if (fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            break;

        sz = (_strlen(lpDirectory) + _strlen(fdata->cFileName)) * sizeof(WCHAR) + sizeof(UNICODE_NULL);
        sz = ALIGN_UP(sz, 0x1000);
        FileName = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
        // Open file and map it
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
        status = NtMapViewOfSection(hSection, NtCurrentProcess(), &DllBase,
            0, 0, NULL, &DllVirtualSize, ViewUnmap, 0, PAGE_READONLY);
        if (!NT_SUCCESS(status))
            break;

        //
        //Look for embedded manifest resource
        //
        IdPath[0] = (ULONG_PTR)RT_MANIFEST;
        IdPath[1] = 1;
        IdPath[2] = 0;
        pt = NULL;
        ResourceSize = 0;
        status = LdrResSearchResource(DllBase, (ULONG_PTR*)&IdPath, 3, 0, &pt, &ResourceSize, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            lastError = RtlNtStatusToDosError(status);
            switch (lastError) {
            case ERROR_RESOURCE_TYPE_NOT_FOUND:
                OutputDebugString(TEXT("GetLastError(LdrResSearchResource): resource type not found\r\n"));
                break;
            case ERROR_RESOURCE_DATA_NOT_FOUND:
                OutputDebugString(TEXT("GetLastError(LdrResSearchResource): resource data not found\r\n"));
                break;
            case ERROR_RESOURCE_NAME_NOT_FOUND:
                OutputDebugString(TEXT("GetLastError(LdrResSearchResource): resource name not found\r\n"));
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

                            RtlSecureZeroMemory(&CallbackData, sizeof(CallbackData));
                            CallbackData.Name = FileName;
                            CallbackData.IsOSBinary = TRUE;

                            //
                            // Check if signature valid or trusted
                            //
                            CallbackData.IsSignatureValidOrTrusted = ((sigData.SignatureState == SIGNATURE_STATE_TRUSTED) ||
                                (sigData.SignatureState == SIGNATURE_STATE_VALID));

                            OutputCallback(&CallbackData);
                        }
                    }
                }
                else { //WTGetSignatureInfo != NULL
                    //
                    // On Windows 7 this API is not available, just output result
                    //
                    RtlSecureZeroMemory(&CallbackData, sizeof(CallbackData));
                    CallbackData.Name = FileName;
                    OutputCallback(&CallbackData);
                }
            }
            break;
        }

        //
        // Create activation context for current file
        //
        RtlSecureZeroMemory(&ctx, sizeof(ctx));
        ctx.cbSize = sizeof(ACTCTX);
        ctx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
        ctx.lpResourceName = MAKEINTRESOURCE(1);
        ctx.lpSource = FileName;
        ctx.hModule = (HMODULE)DllBase;

        hActCtx = CreateActCtx(&ctx);
        if (hActCtx == INVALID_HANDLE_VALUE)
            break;

        //
        // Query autoelevate setting and run level information
        //
        l = 0;
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        status = RtlQueryActivationContextApplicationSettings(0, hActCtx, NULL, TEXT("autoElevate"), (PWSTR)&szValue, sizeof(szValue), &l);
        if (NT_SUCCESS(status)) {
            RtlSecureZeroMemory(&CallbackData, sizeof(CallbackData));
            CallbackData.Name = FileName;
            CallbackData.IsFusion = TRUE;
            CallbackData.AutoElevate = (_strcmpi(szValue, TEXT("true")) == 0); //actually appinfo only looks for 'T' or 't' symbol for performance reasons perhaps
            
            //
            //Query run level information
            //
            RtlSecureZeroMemory(&ctxrl, sizeof(ctxrl));        
            status = RtlQueryInformationActivationContext(
                RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_NO_ADDREF,
                hActCtx, NULL, RunlevelInformationInActivationContext, (PVOID)&ctxrl, sizeof(ctxrl), NULL);

            if (NT_SUCCESS(status)) {
                switch (ctxrl.RunLevel) {
                case ACTCTX_RUN_LEVEL_AS_INVOKER:
                    CallbackData.RequestedExecutionLevel = TEXT("asInvoker");
                    break;
                case ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE:
                    CallbackData.RequestedExecutionLevel = TEXT("highestAvailable");
                    break;
                case ACTCTX_RUN_LEVEL_REQUIRE_ADMIN:
                    CallbackData.RequestedExecutionLevel = TEXT("requireAdministrator");
                    break;
                case ACTCTX_RUN_LEVEL_UNSPECIFIED:
                default:
                    CallbackData.RequestedExecutionLevel = TEXT("unspecified");
                    break;
                }
            }
            CallbackData.IsDotNet = supIsCorImageFile(DllBase);
            OutputCallback(&CallbackData);
        }
        else {
            //some shit happened, if not expected - debug print it
            lastError = RtlNtStatusToDosError(status);
            if (lastError != ERROR_SXS_KEY_NOT_FOUND) {
                RtlSecureZeroMemory(szValue, sizeof(szValue));
                _strcpy(szValue, TEXT("GetLastError(QueryActivationContext)="));
                ultostr(lastError, _strend(szValue));
                _strcat(szValue, TEXT("\r\n"));
                OutputDebugString(szValue);
            }
        }

    } while (bCond);

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
* ScanFiles
*
* Purpose:
*
* Scan directory for files of given type.
*
*/
VOID ScanFiles(
    LPWSTR lpDirectory,
    FUSIONCALLBACK OutputCallback
    )
{
    HANDLE hFile;
    LPWSTR lpLookupDirectory = NULL;
    SIZE_T sz;
    WIN32_FIND_DATA fdata;

    sz = (_strlen(lpDirectory) + MAX_PATH) * sizeof(WCHAR);
    lpLookupDirectory = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    if (lpLookupDirectory) {
        _strncpy(lpLookupDirectory, MAX_PATH, lpDirectory, MAX_PATH);
        _strcat(lpLookupDirectory, TEXT("\\*.exe"));

        RtlSecureZeroMemory(&fdata, sizeof(fdata));
        hFile = FindFirstFile(lpLookupDirectory, &fdata);
        if (hFile != INVALID_HANDLE_VALUE) {
            do {
                CheckFile(lpDirectory, &fdata, OutputCallback);
            } while (FindNextFile(hFile, &fdata));
            FindClose(hFile);
        }
        HeapFree(GetProcessHeap(), 0, lpLookupDirectory);
    }
}

/*
* ScanDirectory
*
* Purpose:
*
* Recursively scan directories.
*
*/
VOID ScanDirectory(
    LPWSTR lpDirectory,
    FUSIONCALLBACK OutputCallback
    )
{
    SIZE_T              l;
    HANDLE              hDirectory;
    WCHAR               dirbuf[MAX_PATH * 2];
    WCHAR               textbuf[MAX_PATH * 2];
    WIN32_FIND_DATA     fdata;

    if ((lpDirectory == NULL) || (OutputCallback == NULL))
        return;

    ScanFiles(lpDirectory, OutputCallback);

    RtlSecureZeroMemory(dirbuf, sizeof(dirbuf));
    RtlSecureZeroMemory(textbuf, sizeof(textbuf));

    _strncpy(dirbuf, MAX_PATH, lpDirectory, MAX_PATH);

    l = _strlen(dirbuf);
    if (dirbuf[l - 1] != L'\\') {
        dirbuf[l] = L'\\';
        dirbuf[l + 1] = 0;
        l++;
    }

    _strcpy(textbuf, dirbuf);
    textbuf[l] = L'*';
    textbuf[l + 1] = 0;
    l++;

    RtlSecureZeroMemory(&fdata, sizeof(fdata));
    hDirectory = FindFirstFile(textbuf, &fdata);
    if (hDirectory != INVALID_HANDLE_VALUE) {
        do {
            if ((fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                (fdata.cFileName[0] != L'.')
                )
            {
                _strcpy(textbuf, dirbuf);
                _strcat(textbuf, fdata.cFileName);
                ScanDirectory(textbuf, OutputCallback);
            }
        } while (FindNextFile(hDirectory, &fdata));
        FindClose(hDirectory);
    }
}
