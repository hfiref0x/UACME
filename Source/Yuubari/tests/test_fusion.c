/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       TEST_FUSION.C
*
*  VERSION:     1.10
*
*  DATE:        20 Feb 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "..\global.h"
#include "..\fusion.h"

BYTE TestArray[1024 * 32] = { 0 };

VOID TestActivationContext(
    VOID
)
{
    ULONG               i;
    NTSTATUS            status;
    HANDLE              hFile = NULL, hSection = NULL, hActCtx = NULL;
    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usStr;
    IO_STATUS_BLOCK     iosb;

    ACTCTX ctx;
    WCHAR szLog[MAX_PATH];

    DLL_REDIRECTION_LIST DllList;
    PSLIST_ENTRY ListEntry;
    DLL_REDIRECTION_LIST_ENTRY *DllData = NULL;

    RtlSecureZeroMemory(szLog, sizeof(szLog));

    __try {

        RtlSecureZeroMemory(&usStr, sizeof(usStr));
        RtlInitUnicodeString(&usStr, L"\\??\\C:\\malware\\sysprep_15019.exe");

        InitializeObjectAttributes(&attr, &usStr,
            OBJ_CASE_INSENSITIVE, NULL, NULL);
        RtlSecureZeroMemory(&iosb, sizeof(iosb));

        //
        // Open file and map it
        //
        status = NtCreateFile(&hFile, SYNCHRONIZE | FILE_READ_DATA,
            &attr, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status))
            __leave;

        status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
            NULL, PAGE_READONLY, SEC_IMAGE, hFile);
        if (!NT_SUCCESS(status))
            __leave;

        DllBase = NULL;
        DllVirtualSize = 0;
        status = NtMapViewOfSection(hSection, NtCurrentProcess(), &DllBase,
            0, 0, NULL, &DllVirtualSize, ViewUnmap, 0, PAGE_READONLY);
        if (!NT_SUCCESS(status))
            __leave;

        //
        // Create activation context for current file
        //
        RtlSecureZeroMemory(&ctx, sizeof(ctx));
        ctx.cbSize = sizeof(ACTCTX);
        ctx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
        ctx.lpResourceName = MAKEINTRESOURCE(1);
        ctx.lpSource = &usStr.Buffer[4];
        ctx.hModule = (HMODULE)DllBase;

        hActCtx = CreateActCtx(&ctx);
        if (hActCtx == INVALID_HANDLE_VALUE)
            __leave;

        RtlSecureZeroMemory(&DllList, sizeof(DllList));
        status = SxsGetDllRedirectionFromActivationContext(hActCtx, &DllList);
        if (NT_SUCCESS(status)) {
            for (i = 0; i < DllList.Depth; i++) {
                ListEntry = RtlInterlockedPopEntrySList(&DllList.Header);
                if (ListEntry) {
                    DllData = (PDLL_REDIRECTION_ENTRY)ListEntry;
                    if (DllData) {

                        RtlFreeUnicodeString(&DllData->DllName);
                        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, DllData);
                    }
                    DllList.Depth--;
                }
            }
            RtlInterlockedFlushSList(&DllList.Header);
        }

    }
    __finally {
        if (hActCtx != NULL)
            ReleaseActCtx(hActCtx);
        if (DllBase != NULL)
            NtUnmapViewOfSection(NtCurrentProcess(), DllBase);
        if (hSection != NULL)
            NtClose(hSection);
        if (hFile != NULL)
            NtClose(hFile);
    }
}
