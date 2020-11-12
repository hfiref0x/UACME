/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       APPINFO.C
*
*  VERSION:     1.49
*
*  DATE:        11 Nov 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "patterns.h"
#include "Shared/hde/hde64.h"
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "version.lib")

#define TEXT_SECTION ".text"
#define TEXT_SECTION_LEGNTH sizeof(TEXT_SECTION)

pfnSymSetOptions        pSymSetOptions;
pfnSymInitializeW       pSymInitializeW = NULL;
pfnSymLoadModuleExW     pSymLoadModuleExW = NULL;
pfnSymEnumSymbolsW      pSymEnumSymbolsW = NULL;
pfnSymUnloadModule64    pSymUnloadModule64 = NULL;
pfnSymFromAddrW         pSymFromAddrW = NULL;
pfnSymCleanup           pSymCleanup = NULL;

UAC_PATTERN g_MmcPatterns[] = {
    { ptMmcBlock_7600, sizeof(ptMmcBlock_7600), 4, 7600, 7600 },
    { ptMmcBlock_7601, sizeof(ptMmcBlock_7601), 4, 7601, 7601 },
    { ptMmcBlock_9200, sizeof(ptMmcBlock_9200), 4, 9200, 9200 },
    { ptMmcBlock_9600, sizeof(ptMmcBlock_9600), 4, 9600, 9600 },
    { ptMmcBlock_10240, sizeof(ptMmcBlock_10240), 4, 10240, 10240 },
    { ptMmcBlock_10586_16299, sizeof(ptMmcBlock_10586_16299), 4, 10586, 16299 },
    { ptMmcBlock_16300_17134, sizeof(ptMmcBlock_16300_17134), 4, 16300, 17134 }
};

#define TestChar(x)  (((WCHAR)x >= L'A') && ((WCHAR)x <= L'z')) 

/*
* GetAppInfoBuildVersion
*
* Purpose:
*
* Return build number of AppInfo.
*
*/
BOOL GetAppInfoBuildVersion(
    _In_ LPWSTR lpFileName,
    _Out_ ULONG* BuildNumber
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO* pFileInfo;

    *BuildNumber = 0;

    dwHandle = 0;
    dwSize = GetFileVersionInfoSize(lpFileName, &dwHandle);
    if (dwSize) {
        vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(lpFileName, 0, dwSize, vinfo)) {
                bResult = VerQueryValue(vinfo, TEXT("\\"), (LPVOID*)&pFileInfo, (PUINT)&Length);
                if (bResult) {
                    *BuildNumber = HIWORD(pFileInfo->dwFileVersionLS);
                }
            }
            HeapFree(GetProcessHeap(), 0, vinfo);
        }
    }
    return bResult;
}

/*
* InitDbgHelp
*
* Purpose:
*
* This function loads dbghelp.dll, symsrv.dll from symdll directory and
* initialize function pointers from dbghelp.dll.
*
*/
BOOL InitDbgHelp(
    VOID
)
{
    BOOL bResult = FALSE;
    HMODULE hDbgHelp = NULL;
    SIZE_T length;
    WCHAR szBuffer[MAX_PATH * 2];

    do {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        if (GetModuleFileName(NULL, szBuffer, MAX_PATH) == 0)
            break;

        _filepath(szBuffer, szBuffer);
        _strcat(szBuffer, L"symdll\\");
        length = _strlen(szBuffer);
        _strcat(szBuffer, L"dbghelp.dll");

        hDbgHelp = LoadLibrary(szBuffer);
        if (hDbgHelp == NULL)
            break;

        szBuffer[length] = 0;
        _strcat(szBuffer, L"symsrv.dll");
        if (LoadLibrary(szBuffer)) {

            pSymSetOptions = (pfnSymSetOptions)GetProcAddress(hDbgHelp, "SymSetOptions");
            if (pSymSetOptions == NULL)
                break;

            pSymInitializeW = (pfnSymInitializeW)GetProcAddress(hDbgHelp, "SymInitializeW");
            if (pSymInitializeW == NULL)
                break;

            pSymLoadModuleExW = (pfnSymLoadModuleExW)GetProcAddress(hDbgHelp, "SymLoadModuleExW");
            if (pSymLoadModuleExW == NULL)
                break;

            pSymEnumSymbolsW = (pfnSymEnumSymbolsW)GetProcAddress(hDbgHelp, "SymEnumSymbolsW");
            if (pSymEnumSymbolsW == NULL)
                break;

            pSymUnloadModule64 = (pfnSymUnloadModule64)GetProcAddress(hDbgHelp, "SymUnloadModule64");
            if (pSymUnloadModule64 == NULL)
                break;

            pSymFromAddrW = (pfnSymFromAddrW)GetProcAddress(hDbgHelp, "SymFromAddrW");
            if (pSymFromAddrW == NULL)
                break;

            pSymCleanup = (pfnSymCleanup)GetProcAddress(hDbgHelp, "SymCleanup");
            if (pSymCleanup == NULL)
                break;

            bResult = TRUE;
        }

    } while (FALSE);

    return bResult;
}

/*
* SymbolsAddToList
*
* Purpose:
*
* This function add symbol to the list.
*
*/
VOID SymbolAddToList(
    _In_ PSYMBOL_ENTRY SymbolsHead,
    _In_ LPWSTR SymbolName,
    _In_ DWORD64 lpAddress
)
{
    PSYMBOL_ENTRY Entry;
    SIZE_T        sz;

    Entry = SymbolsHead;

    while (Entry->Next != NULL)
        Entry = Entry->Next;

    sz = (1 + _strlen(SymbolName)) * sizeof(WCHAR);

    Entry->Next = (PSYMBOL_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYMBOL_ENTRY));
    if (Entry->Next) {

        Entry = Entry->Next;
        Entry->Next = NULL;

        Entry->Name = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (Entry->Name) {

            _strncpy(Entry->Name, sz / sizeof(WCHAR),
                SymbolName, sz / sizeof(WCHAR));

            Entry->Address = lpAddress;
        }
        else {
            HeapFree(GetProcessHeap(), 0, Entry);
        }
    }
}

/*
* SymbolAddressFromName
*
* Purpose:
*
* This function query address from the given symbol name.
*
*/
DWORD64 SymbolAddressFromName(
    _In_ PSYMBOL_ENTRY SymbolsHead,
    _In_ LPWSTR lpszName
)
{
    PSYMBOL_ENTRY Entry;

    Entry = SymbolsHead;

    while (Entry) {
        if (!_strcmp(lpszName, Entry->Name))
            return Entry->Address;
        Entry = Entry->Next;
    }
    return 0;
}

/*
* SymEnumSymbolsProc
*
* Purpose:
*
* Callback of SymEnumSymbolsW.
*
*/
BOOL CALLBACK SymEnumSymbolsProc(
    _In_ PSYMBOL_INFOW pSymInfo,
    _In_ ULONG SymbolSize,
    _In_opt_ PVOID UserContext
)
{
    PSYMBOL_ENTRY SymbolsHead = (PSYMBOL_ENTRY)UserContext;
    UNREFERENCED_PARAMETER(SymbolSize);

    if (UserContext == NULL)
        return FALSE;

    SymbolAddToList(SymbolsHead, pSymInfo->Name, pSymInfo->Address);
    return TRUE;
}

/*
* GetSupportedPattern
*
* Purpose:
*
* Return pointer to requested pattern if present.
*
*/
_Success_(return == TRUE)
BOOL GetSupportedPattern(
    _In_ ULONG AppInfoBuildNumber,
    _In_ UAC_PATTERN * Patterns,
    _Out_ LPCVOID * OutputPattern,
    _Out_ ULONG * OutputPatternSize,
    _Out_ ULONG * SubtractBytes
)
{
    ULONG i;

    *OutputPattern = NULL;
    *OutputPatternSize = 0;
    *SubtractBytes = 0;

    for (i = 0; i < RTL_NUMBER_OF(g_MmcPatterns); i++) {
        if ((AppInfoBuildNumber >= Patterns[i].AppInfoBuildMin) &&
            (AppInfoBuildNumber <= Patterns[i].AppInfoBuildMax))
        {
            *OutputPattern = Patterns[i].PatternData;
            *OutputPatternSize = Patterns[i].PatternSize;
            *SubtractBytes = Patterns[i].SubtractBytes;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN QueryAiMmcBlock21H1(
    _In_ UAC_AI_GLOBALS * AppInfo,
    _In_ PBYTE PtrCode,
    _In_ ULONG SectionSize
)
{
    ULONG       instOffset, patternOffset;
    LONG        rel = 0;
    PVOID       TestPtr = NULL;

    hde64s      hs;
    PBYTE       ptrCode;

    ptrCode = supFindPattern(PtrCode,
        SectionSize,
        (CONST PBYTE)ptMmcBlock_Start21H1,
        sizeof(ptMmcBlock_Start21H1));

    if (ptrCode) {

        patternOffset = RtlPointerToOffset(PtrCode, ptrCode);
        instOffset = 0;

        do {

            hde64_disasm((void*)RtlOffsetToPointer(ptrCode, instOffset), &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) {
                if ((ptrCode[instOffset] == 0x48) &&
                    (ptrCode[instOffset + 2] == 0x15))
                {
                    rel = *(PLONG)(ptrCode + instOffset + 3);
                    TestPtr = (UAC_MMC_BLOCK*)((ULONG_PTR)ptrCode + instOffset + 7 + rel);
                    if (IN_REGION(TestPtr, AppInfo->DllBase, AppInfo->DllVirtualSize)) {
                        AppInfo->MmcBlock = (UAC_MMC_BLOCK*)TestPtr;
                        return TRUE;
                    }
                }
            }

            instOffset += hs.len;

        } while (instOffset < ((SectionSize - patternOffset) - 16));

    }

    return FALSE;
}

BOOLEAN QueryAiMmcBlockPre21H1(
    _In_ UAC_AI_GLOBALS * AppInfo,
    _In_ PBYTE PtrCode,
    _In_ ULONG SectionSize
)
{
    ULONG       instOffset, tempOffset;
    LONG        rel = 0;
    PVOID       TestPtr = NULL;

    hde64s      hs;
    ULONG       sectionSize = SectionSize;
    PBYTE       ptrCode = PtrCode;
    SIZE_T      matchBytes, reqMatchSize;

    instOffset = 0;

    do {

        hde64_disasm((void*)(ptrCode + instOffset), &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 3) {

            hde64_disasm((void*)(void*)RtlOffsetToPointer(ptrCode, instOffset), &hs);
            if (hs.flags & F_ERROR)
                break;

            reqMatchSize = sizeof(ptMmcBlock_Start);

            matchBytes = RtlCompareMemory(
                (CONST VOID*)RtlOffsetToPointer(ptrCode, instOffset),
                (CONST VOID*)ptMmcBlock_Start,
                reqMatchSize);

            if (matchBytes == reqMatchSize) {

                //
                // Next instruction check.
                //
                tempOffset = (instOffset += hs.len);

                hde64_disasm((void*)(void*)RtlOffsetToPointer(ptrCode, instOffset), &hs);
                if (hs.flags & F_ERROR)
                    break;

                if (hs.len == 7) {

                    if ((ptrCode[tempOffset + 1] == 0x8D) &&
                        (ptrCode[tempOffset + 2] == 0x35))
                    {

                        //
                        // Next instruction check.
                        //                        
                        hde64_disasm((void*)(ptrCode + tempOffset + hs.len), &hs);
                        if (hs.flags & F_ERROR)
                            break;

                        if (hs.len == 3) {

                            rel = *(PLONG)(ptrCode + tempOffset + 3);
                            TestPtr = (UAC_MMC_BLOCK*)((ULONG_PTR)ptrCode + tempOffset + 7 + rel);
                            if (IN_REGION(TestPtr, AppInfo->DllBase, AppInfo->DllVirtualSize)) {
                                AppInfo->MmcBlock = (UAC_MMC_BLOCK*)TestPtr;
                                return TRUE;
                            }

                        }

                    }
                }
            }
        }

        instOffset += hs.len;

    } while (instOffset < (sectionSize - 16));

    return FALSE;
}

/*
* QueryAiMmcBlock
*
* Purpose:
*
* Locate mmc block. No corresponding symbol, code very vary from compiler version.
*
*/
BOOLEAN QueryAiMmcBlock(
    _In_ UAC_AI_GLOBALS * AppInfo
)
{
    ULONG       PatternSize = 0, SubtractBytes = 0;
    LONG        rel = 0;
    PVOID       Pattern = NULL, PatternData = NULL, TestPtr = NULL;

    ULONG       sectionSize = 0;
    PBYTE       ptrCode;

    //
    // Locate .text image section.
    //
    ptrCode = (PBYTE)supLookupImageSectionByName(TEXT_SECTION,
        TEXT_SECTION_LEGNTH,
        (PVOID)AppInfo->DllBase,
        &sectionSize);

    if ((ptrCode == NULL) || (sectionSize < 1024))
        return FALSE;

    if (AppInfo->AppInfoBuildNumber < 17763) {
        if (GetSupportedPattern(AppInfo->AppInfoBuildNumber,
            g_MmcPatterns,
            &PatternData,
            &PatternSize,
            &SubtractBytes))
        {
            if (PatternData) {
                Pattern = (PVOID)supFindPattern(ptrCode, sectionSize, (PBYTE)PatternData, PatternSize);
                if (Pattern != NULL) {
                    rel = *(DWORD*)((ULONG_PTR)Pattern - SubtractBytes);
                    TestPtr = (UAC_MMC_BLOCK*)((ULONG_PTR)Pattern + rel);
                    if (IN_REGION(TestPtr, AppInfo->DllBase, AppInfo->DllVirtualSize)) {
                        AppInfo->MmcBlock = (UAC_MMC_BLOCK*)TestPtr;
                        return TRUE;
                    }
                }
            }
        }
    }
    else {

        if (AppInfo->AppInfoBuildNumber < 19043) {
            return QueryAiMmcBlockPre21H1(AppInfo, ptrCode, sectionSize);
        }
        else {
            return QueryAiMmcBlock21H1(AppInfo, ptrCode, sectionSize);
        }

    }
    return FALSE;
}

/*
* QueryAiGlobalData
*
* Purpose:
*
* Load symbols for Appinfo global variables.
*
*/
VOID QueryAiGlobalData(
    _In_ UAC_AI_GLOBALS * AppInfo
)
{
    HANDLE  hSym = GetCurrentProcess();
    WCHAR   szFullSymbolInfo[MAX_PATH * 2];
    WCHAR   szSymbolName[MAX_PATH];

    SYMBOL_ENTRY SymbolsHead;

    DWORD64 DllBase;

    DllBase = (DWORD64)AppInfo->DllBase;
    if (DllBase == 0)
        return;

    do {
        pSymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
        RtlSecureZeroMemory(&SymbolsHead, sizeof(SymbolsHead));

        RtlSecureZeroMemory(szSymbolName, sizeof(szSymbolName));
        if (GetModuleFileName(NULL, szSymbolName, MAX_PATH) == 0)
            break;

        _strcpy(szFullSymbolInfo, TEXT("SRV*"));
        _filepath(szSymbolName, _strend_w(szFullSymbolInfo));
        _strcat(szFullSymbolInfo, TEXT("Symbols"));
        if (!CreateDirectory(&szFullSymbolInfo[4], NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

        _strcat(szFullSymbolInfo, TEXT("*https://msdl.microsoft.com/download/symbols"));
        if (pSymInitializeW(hSym, szFullSymbolInfo, FALSE)) {
            if (pSymLoadModuleExW(hSym, NULL, TEXT("appinfo.dll"), NULL, DllBase, 0, NULL, 0)) {
                if (pSymEnumSymbolsW(hSym, DllBase, NULL, SymEnumSymbolsProc, (PVOID)&SymbolsHead))
                {
                    AppInfo->lpAutoApproveEXEList = (PVOID*)SymbolAddressFromName(&SymbolsHead, TEXT("g_lpAutoApproveEXEList"));
                    AppInfo->lpIncludedPFDirs = (PVOID*)SymbolAddressFromName(&SymbolsHead, TEXT("g_lpIncludedPFDirs"));
                    AppInfo->lpIncludedWindowsDirs = (PVOID*)SymbolAddressFromName(&SymbolsHead, TEXT("g_lpIncludedWindowsDirs"));
                    AppInfo->lpIncludedSystemDirs = (PVOID*)SymbolAddressFromName(&SymbolsHead, TEXT("g_lpIncludedSystemDirs"));
                    AppInfo->lpExemptedAutoApproveExes = (PVOID*)SymbolAddressFromName(&SymbolsHead, TEXT("g_lpExemptedAutoApproveExes"));
                    AppInfo->lpExcludedWindowsDirs = (PVOID*)SymbolAddressFromName(&SymbolsHead, TEXT("g_lpExcludedWindowsDirs"));
                }
                pSymUnloadModule64(hSym, DllBase);
            }
            pSymCleanup(hSym);
        }
    } while (FALSE);

}

BOOL IsCrossPtr(
    _In_ UAC_AI_GLOBALS * AppInfo,
    _In_ ULONG_PTR Ptr,
    _In_ ULONG_PTR CurrentList
)
{
    if (Ptr == 0 || AppInfo == NULL) {
        return TRUE;
    }

    if (AppInfo->lpAutoApproveEXEList) {
        if (CurrentList != (ULONG_PTR)AppInfo->lpAutoApproveEXEList)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)AppInfo->lpAutoApproveEXEList[0])
                return TRUE;
    }
    if (AppInfo->lpExcludedWindowsDirs) {
        if (CurrentList != (ULONG_PTR)AppInfo->lpExcludedWindowsDirs)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)AppInfo->lpExcludedWindowsDirs[0])
                return TRUE;
    }
    if (AppInfo->lpExemptedAutoApproveExes) {
        if (CurrentList != (ULONG_PTR)AppInfo->lpExemptedAutoApproveExes)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)AppInfo->lpExemptedAutoApproveExes[0])
                return TRUE;
    }
    if (AppInfo->lpIncludedPFDirs) {
        if (CurrentList != (ULONG_PTR)AppInfo->lpIncludedPFDirs)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)AppInfo->lpIncludedPFDirs[0])
                return TRUE;
    }
    if (AppInfo->lpIncludedSystemDirs) {
        if (CurrentList != (ULONG_PTR)AppInfo->lpIncludedSystemDirs)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)AppInfo->lpIncludedSystemDirs[0])
                return TRUE;
    }
    if (AppInfo->lpIncludedWindowsDirs) {
        if (CurrentList != (ULONG_PTR)AppInfo->lpIncludedWindowsDirs)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)AppInfo->lpIncludedWindowsDirs[0])
                return TRUE;
    }
    return FALSE;
}

/*
* ListMMCFiles
*
* Purpose:
*
* Output MMC related block from appinfo.dll.
*
*/
VOID ListMMCFiles(
    _In_ UAC_AI_GLOBALS * AppInfo,
    _In_ OUTPUTCALLBACK OutputCallback
)
{
    SIZE_T          i, Length;
    LPWSTR          TestString = NULL;
    PVOID* MscArray = NULL;
    UAC_AI_DATA     CallbackData;

    if (!QueryAiMmcBlock(AppInfo))
        return;

    __try {
        if (AppInfo->MmcBlock->NumOfElements > 256) {
            OutputDebugString(TEXT("Invalid block data"));
        }
        else {
            CallbackData.Type = AiManagementConsole;
            TestString = AppInfo->MmcBlock->lpManagementApplication;
            if (TestString) {
                if (IN_REGION(TestString, AppInfo->DllBase, AppInfo->DllVirtualSize)) {
                    CallbackData.Name = TestString;
                    CallbackData.Length = _strlen(TestString);
                    OutputCallback((PVOID)&CallbackData);
                }
            }
            CallbackData.Type = AiSnapinFile;
            MscArray = (PVOID*)AppInfo->MmcBlock->Base;
            for (i = 0; i < AppInfo->MmcBlock->NumOfElements; i++) {
                TestString = (LPWSTR)MscArray[i];
                if (TestString != NULL) {
                    if (IN_REGION(TestString, AppInfo->DllBase, AppInfo->DllVirtualSize)) {
                        Length = _strlen(TestString);
                        CallbackData.Name = TestString;
                        CallbackData.Length = Length;
                        OutputCallback((PVOID)&CallbackData);
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugString(TEXT("Invalid block"));
        return;
    }
}

/*
* ListAutoApproveEXE
*
* Purpose:
*
* Output lpAutoApproveEXE list from appinfo.dll.
*
*/
VOID ListAutoApproveEXE(
    _In_ UAC_AI_GLOBALS * AppInfo,
    _In_ OUTPUTCALLBACK OutputCallback
)
{
    WCHAR           k, lk;
    SIZE_T          i, Length = 0;
    LPWSTR          TestString = NULL;
    UAC_AI_DATA     CallbackData;

    if (AppInfo->lpAutoApproveEXEList == NULL)
        return;

    CallbackData.Type = AiAutoApproveEXE;

    i = 0;
    k = 0;
    lk = 0;
    __try {
        do {
            TestString = (LPWSTR)AppInfo->lpAutoApproveEXEList[i];
            if (IsCrossPtr(AppInfo, (ULONG_PTR)TestString, (ULONG_PTR)AppInfo->lpAutoApproveEXEList))
                break;

            k = TestString[0];
            if (!TestChar(k))
                break;

            if (k < lk)
                break;
            lk = k;
            i += 1;
            if (i > 100)
                break;

            Length = _strlen(TestString);
            CallbackData.Length = Length;
            CallbackData.Name = TestString;
            OutputCallback((PVOID)&CallbackData);
        } while (1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugString(TEXT("Invalid pointer, enum stop"));
        return;
    }
}

/*
* ListStringDataUnsorted
*
* Purpose:
*
* Output unsorted string data from appinfo.dll.
*
*/
VOID ListStringDataUnsorted(
    UAC_AI_GLOBALS * AppInfo,
    AI_DATA_TYPE AiDataType,
    PVOID * Data,
    OUTPUTCALLBACK OutputCallback
)
{
    SIZE_T          i, Length = 0;
    LPWSTR          TestString = NULL;
    UAC_AI_DATA     CallbackData;

    if (Data == NULL)
        return;

    CallbackData.Type = AiDataType;

    i = 0;

    __try {
        do {
            TestString = (LPWSTR)Data[i];
            if (IsCrossPtr(AppInfo, (ULONG_PTR)TestString, (ULONG_PTR)Data))
                break;

            if (!TestChar(TestString[0]))
                break;

            i += 1;
            if (i > 100)
                break;

            Length = _strlen(TestString);
            CallbackData.Length = Length;
            CallbackData.Name = TestString;
            OutputCallback((PVOID)&CallbackData);
        } while (1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugString(TEXT("Invalid pointer, enum stop"));
        return;
    }
}

/*
* ScanAppInfo
*
* Purpose:
*
* Map appinfo.dll and extract various information from it.
*
*/
VOID ScanAppInfo(
    LPWSTR lpFileName,
    OUTPUTCALLBACK OutputCallback
)
{
    NTSTATUS            status;
    HANDLE              hFile = NULL, hSection = NULL;
    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usFileName;
    IO_STATUS_BLOCK     iosb;
    UAC_AI_GLOBALS      AppInfo;

    RtlSecureZeroMemory(&AppInfo, sizeof(AppInfo));
    RtlInitEmptyUnicodeString(&usFileName, NULL, 0);

    do {

        if (!GetAppInfoBuildVersion(lpFileName, &AppInfo.AppInfoBuildNumber))
            break;

        if (RtlDosPathNameToNtPathName_U(lpFileName, &usFileName, NULL, NULL) == FALSE)
            break;

        InitializeObjectAttributes(&attr, &usFileName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);
        RtlSecureZeroMemory(&iosb, sizeof(iosb));

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

        AppInfo.DllBase = DllBase;
        AppInfo.DllVirtualSize = DllVirtualSize;

        ListMMCFiles(&AppInfo, OutputCallback);

        if (InitDbgHelp()) {
            QueryAiGlobalData(&AppInfo);
            ListAutoApproveEXE(&AppInfo, OutputCallback);
            ListStringDataUnsorted(&AppInfo, AiIncludedPFDirs, AppInfo.lpIncludedPFDirs, OutputCallback);
            ListStringDataUnsorted(&AppInfo, AilpIncludedWindowsDirs, AppInfo.lpIncludedWindowsDirs, OutputCallback);
            ListStringDataUnsorted(&AppInfo, AiIncludedSystemDirs, AppInfo.lpIncludedSystemDirs, OutputCallback);
            ListStringDataUnsorted(&AppInfo, AiExemptedAutoApproveExes, AppInfo.lpExemptedAutoApproveExes, OutputCallback);
            ListStringDataUnsorted(&AppInfo, AiExcludedWindowsDirs, AppInfo.lpExcludedWindowsDirs, OutputCallback);
        }

    } while (FALSE);

    if (usFileName.Buffer != NULL)
        RtlFreeUnicodeString(&usFileName);

    if (DllBase != NULL)
        NtUnmapViewOfSection(NtCurrentProcess(), DllBase);

    if (hSection != NULL)
        NtClose(hSection);

    if (hFile != NULL)
        NtClose(hFile);
}
