/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       APPINFO.C
*
*  VERSION:     1.40
*
*  DATE:        19 Mar 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "patterns.h"
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "version.lib")

UAC_AI_GLOBALS g_AiData;
SYMBOL_ENTRY g_SymbolsHead;

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
    { ptMmcBlock_16300_17763, sizeof(ptMmcBlock_16300_17763), 4, 16300, 17763 },
    { ptMmcBlock_18300_18361, sizeof(ptMmcBlock_18300_18361), 4, 18300, 18361 }
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
    _Out_ ULONG *BuildNumber
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO *pFileInfo;

    *BuildNumber = 0;

    dwHandle = 0;
    dwSize = GetFileVersionInfoSize(lpFileName, &dwHandle);
    if (dwSize) {
        vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(lpFileName, 0, dwSize, vinfo)) {
                bResult = VerQueryValue(vinfo, TEXT("\\"), (LPVOID *)&pFileInfo, (PUINT)&Length);
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
    BOOL bCond = FALSE, bResult = FALSE;
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

    } while (bCond);

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
    _In_ LPWSTR SymbolName,
    _In_ DWORD64 lpAddress
)
{
    PSYMBOL_ENTRY Entry;
    SIZE_T        sz;

    Entry = &g_SymbolsHead;

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
    _In_ LPWSTR lpszName
)
{
    PSYMBOL_ENTRY Entry;

    Entry = g_SymbolsHead.Next;

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
    UNREFERENCED_PARAMETER(SymbolSize);
    UNREFERENCED_PARAMETER(UserContext);

    SymbolAddToList(pSymInfo->Name, pSymInfo->Address);
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
BOOL GetSupportedPattern(
    _In_ UAC_PATTERN *Patterns,
    _In_ LPCVOID *OutputPattern,
    _In_ ULONG *OutputPatternSize,
    _In_ ULONG *SubtractBytes
)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(g_MmcPatterns); i++) {
        if ((g_AiData.AppInfoBuildNumber >= Patterns[i].AppInfoBuildMin) &&
            (g_AiData.AppInfoBuildNumber <= Patterns[i].AppInfoBuildMax))
        {
            *OutputPattern = Patterns[i].PatternData;
            *OutputPatternSize = Patterns[i].PatternSize;
            *SubtractBytes = Patterns[i].SubtractBytes;
            return TRUE;
        }
    }
    return FALSE;
}

/*
* QueryAiMmcBlock
*
* Purpose:
*
* Locate mmc block.
*
*/
BOOLEAN QueryAiMmcBlock(
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize
)
{
    ULONG       PatternSize = 0, SubtractBytes = 0;
    ULONG_PTR   rel = 0;
    PVOID       Pattern = NULL, PatternData = NULL, TestPtr = NULL;

    if (DllBase == NULL)
        return FALSE;

    g_AiData.MmcBlock = NULL;
    if (GetSupportedPattern(g_MmcPatterns, &PatternData, &PatternSize, &SubtractBytes)) {
        Pattern = (PVOID)supFindPattern(DllBase, DllVirtualSize, (PBYTE)PatternData, PatternSize);
        if (Pattern != NULL) {
            rel = *(DWORD*)((ULONG_PTR)Pattern - SubtractBytes);
            TestPtr = (UAC_MMC_BLOCK*)((ULONG_PTR)Pattern + rel);
            if (IN_REGION(TestPtr, DllBase, DllVirtualSize)) {
                g_AiData.MmcBlock = (UAC_MMC_BLOCK*)TestPtr;
                return TRUE;
            }
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
    VOID
)
{
    BOOL    bCond = FALSE;
    HANDLE  hSym = GetCurrentProcess();
    WCHAR   szFullSymbolInfo[MAX_PATH * 2];
    WCHAR   szSymbolName[MAX_PATH];

    if (g_AiData.DllBase == NULL)
        return;

    do {
        pSymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
        RtlSecureZeroMemory(&g_SymbolsHead, sizeof(g_SymbolsHead));

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
            if (pSymLoadModuleExW(hSym, NULL, TEXT("appinfo.dll"), NULL, (DWORD64)g_AiData.DllBase, 0, NULL, 0)) {
                if (pSymEnumSymbolsW(hSym, (DWORD64)g_AiData.DllBase, NULL, SymEnumSymbolsProc, NULL)) {
                    g_AiData.lpAutoApproveEXEList = (PVOID*)SymbolAddressFromName(TEXT("g_lpAutoApproveEXEList"));
                    g_AiData.lpIncludedPFDirs = (PVOID*)SymbolAddressFromName(TEXT("g_lpIncludedPFDirs"));
                    g_AiData.lpIncludedWindowsDirs = (PVOID*)SymbolAddressFromName(TEXT("g_lpIncludedWindowsDirs"));
                    g_AiData.lpIncludedSystemDirs = (PVOID*)SymbolAddressFromName(TEXT("g_lpIncludedSystemDirs"));
                    g_AiData.lpExemptedAutoApproveExes = (PVOID*)SymbolAddressFromName(TEXT("g_lpExemptedAutoApproveExes"));
                    g_AiData.lpExcludedWindowsDirs = (PVOID*)SymbolAddressFromName(TEXT("g_lpExcludedWindowsDirs"));
                }
                pSymUnloadModule64(hSym, (DWORD64)g_AiData.DllBase);
            }
            pSymCleanup(hSym);
        }
    } while (bCond);

}

BOOL IsCrossPtr(
    ULONG_PTR Ptr,
    ULONG_PTR CurrentList
)
{
    if (Ptr == 0) {
        return TRUE;
    }

    if (g_AiData.lpAutoApproveEXEList) {
        if (CurrentList != (ULONG_PTR)g_AiData.lpAutoApproveEXEList)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)g_AiData.lpAutoApproveEXEList[0])
                return TRUE;
    }
    if (g_AiData.lpExcludedWindowsDirs) {
        if (CurrentList != (ULONG_PTR)g_AiData.lpExcludedWindowsDirs)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)g_AiData.lpExcludedWindowsDirs[0])
                return TRUE;
    }
    if (g_AiData.lpExemptedAutoApproveExes) {
        if (CurrentList != (ULONG_PTR)g_AiData.lpExemptedAutoApproveExes)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)g_AiData.lpExemptedAutoApproveExes[0])
                return TRUE;
    }
    if (g_AiData.lpIncludedPFDirs) {
        if (CurrentList != (ULONG_PTR)g_AiData.lpIncludedPFDirs)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)g_AiData.lpIncludedPFDirs[0])
                return TRUE;
    }
    if (g_AiData.lpIncludedSystemDirs) {
        if (CurrentList != (ULONG_PTR)g_AiData.lpIncludedSystemDirs)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)g_AiData.lpIncludedSystemDirs[0])
                return TRUE;
    }
    if (g_AiData.lpIncludedWindowsDirs) {
        if (CurrentList != (ULONG_PTR)g_AiData.lpIncludedWindowsDirs)
            if ((ULONG_PTR)Ptr == (ULONG_PTR)g_AiData.lpIncludedWindowsDirs[0])
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
    OUTPUTCALLBACK OutputCallback
)
{
    SIZE_T          i, Length;
    LPWSTR          TestString = NULL;
    PVOID          *MscArray = NULL;
    UAC_AI_DATA     CallbackData;

    if (!QueryAiMmcBlock((PBYTE)g_AiData.DllBase, g_AiData.DllVirtualSize))
        return;

    __try {
        if (g_AiData.MmcBlock->ControlFilesCount > 256) {
            OutputDebugString(TEXT("Invalid block data"));
        }
        else {
            CallbackData.Type = AiManagementConsole;
            TestString = g_AiData.MmcBlock->lpManagementApplication;
            if (TestString) {
                if (IN_REGION(TestString, g_AiData.DllBase, g_AiData.DllVirtualSize)) {
                    CallbackData.Name = TestString;
                    CallbackData.Length = _strlen(TestString);
                    OutputCallback((PVOID)&CallbackData);
                }
            }
            CallbackData.Type = AiSnapinFile;
            MscArray = (PVOID*)g_AiData.MmcBlock->ControlFiles;
            for (i = 0; i < g_AiData.MmcBlock->ControlFilesCount; i++) {
                TestString = (LPWSTR)MscArray[i];
                if (TestString != NULL) {
                    if (IN_REGION(TestString, g_AiData.DllBase, g_AiData.DllVirtualSize)) {
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
    OUTPUTCALLBACK OutputCallback
)
{
    WCHAR           k, lk;
    SIZE_T          i, Length = 0;
    LPWSTR          TestString = NULL;
    UAC_AI_DATA     CallbackData;

    if (g_AiData.lpAutoApproveEXEList == NULL)
        return;

    CallbackData.Type = AiAutoApproveEXE;

    i = 0;
    k = 0;
    lk = 0;
    __try {
        do {
            TestString = (LPWSTR)g_AiData.lpAutoApproveEXEList[i];
            if (IsCrossPtr((ULONG_PTR)TestString, (ULONG_PTR)g_AiData.lpAutoApproveEXEList))
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
    AI_DATA_TYPE AiDataType,
    PVOID *Data,
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
            if (IsCrossPtr((ULONG_PTR)TestString, (ULONG_PTR)Data))
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
    BOOL                bCond = FALSE;
    NTSTATUS            status;
    HANDLE              hFile = NULL, hSection = NULL;
    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usFileName;
    IO_STATUS_BLOCK     iosb;


    RtlSecureZeroMemory(&usFileName, sizeof(usFileName));
    RtlSecureZeroMemory(&g_AiData, sizeof(g_AiData));

    do {

        if (!GetAppInfoBuildVersion(lpFileName, &g_AiData.AppInfoBuildNumber))
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

        g_AiData.DllBase = DllBase;
        g_AiData.DllVirtualSize = DllVirtualSize;

        ListMMCFiles(OutputCallback);

        if (InitDbgHelp()) {
            QueryAiGlobalData();
            ListAutoApproveEXE(OutputCallback);
            ListStringDataUnsorted(AiIncludedPFDirs, g_AiData.lpIncludedPFDirs, OutputCallback);
            ListStringDataUnsorted(AilpIncludedWindowsDirs, g_AiData.lpIncludedWindowsDirs, OutputCallback);
            ListStringDataUnsorted(AiIncludedSystemDirs, g_AiData.lpIncludedSystemDirs, OutputCallback);
            ListStringDataUnsorted(AiExemptedAutoApproveExes, g_AiData.lpExemptedAutoApproveExes, OutputCallback);
            ListStringDataUnsorted(AiExcludedWindowsDirs, g_AiData.lpExcludedWindowsDirs, OutputCallback);
        }

    } while (bCond);

    if (usFileName.Buffer != NULL)
        RtlFreeUnicodeString(&usFileName);

    if (DllBase != NULL)
        NtUnmapViewOfSection(NtCurrentProcess(), DllBase);

    if (hSection != NULL)
        NtClose(hSection);

    if (hFile != NULL)
        NtClose(hFile);
}
