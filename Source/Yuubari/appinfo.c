/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       APPINFO.C
*
*  VERSION:     1.51
*
*  DATE:        31 Oct 2021
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
#pragma comment(lib, "version.lib")

#define DEFAULT_SYMPATH     L"*https://msdl.microsoft.com/download/symbols"

#define TEXT_SECTION ".text"
#define TEXT_SECTION_LEGNTH sizeof(TEXT_SECTION)

static UAC_PATTERN g_MmcPatterns[] = {
    { ptMmcBlock_7600, sizeof(ptMmcBlock_7600), 4, NT_WIN7_RTM, NT_WIN7_RTM },
    { ptMmcBlock_7601, sizeof(ptMmcBlock_7601), 4, NT_WIN7_SP1, NT_WIN7_SP1 },
    { ptMmcBlock_9200, sizeof(ptMmcBlock_9200), 4, NT_WIN8_RTM, NT_WIN8_RTM },
    { ptMmcBlock_9600, sizeof(ptMmcBlock_9600), 4, NT_WIN8_BLUE, NT_WIN8_BLUE },
    { ptMmcBlock_10240, sizeof(ptMmcBlock_10240), 4, NT_WIN10_THRESHOLD1, NT_WIN10_THRESHOLD1 },
    { ptMmcBlock_10586_16299, sizeof(ptMmcBlock_10586_16299), 4, NT_WIN10_THRESHOLD2, NT_WIN10_REDSTONE3},
    { ptMmcBlock_16300_17134, sizeof(ptMmcBlock_16300_17134), 4, NT_WIN10_REDSTONE4, NT_WIN10_REDSTONE4 }
};

static UAC_PATTERN g_MmcPatterns2[] = {
    { ptMmcBlock_StartW11, sizeof(ptMmcBlock_StartW11), 0, NT_WIN11_21H2, NTX_WIN11_ADB }
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
        vinfo = supHeapAlloc(dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(lpFileName, 0, dwSize, vinfo)) {
                bResult = VerQueryValue(vinfo, TEXT("\\"), (LPVOID*)&pFileInfo, (PUINT)&Length);
                if (bResult) {
                    *BuildNumber = HIWORD(pFileInfo->dwFileVersionLS);
                }
            }
            supHeapFree(vinfo);
        }
    }
    return bResult;
}

/*
* LookupAddressBySymbol
*
* Purpose:
*
* Return address of symbol by name.
*
*/
ULONG64 LookupAddressBySymbol(
    _In_ pfnSymFromNameW SymFromName,
    _In_ LPCWSTR SymbolName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    SIZE_T symSize;
    ULONG64 symAddress = 0;
    PSYMBOL_INFOW symbolInfo = NULL;

    symSize = sizeof(SYMBOL_INFOW);

    symbolInfo = (PSYMBOL_INFOW)supHeapAlloc(symSize);
    if (symbolInfo) {

        symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbolInfo->MaxNameLen = 0; //name is not used

        bStatus = SymFromName(
            GetCurrentProcess(),
            SymbolName,
            symbolInfo);

        if (bStatus)
            symAddress = symbolInfo->Address;

        supHeapFree(symbolInfo);
    }

    if (Status)
        *Status = bStatus;

    return symAddress;
}

/*
* ResolveAppInfoSymbols
*
* Purpose:
*
* Load dbghelp, resolve appinfo pointers through symbols lookup.
*
*/
BOOL ResolveAppInfoSymbols(
    _In_ PUAC_AI_GLOBALS AppInfo
)
{
    SIZE_T dirLength;
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szUserSearchPath[MAX_PATH * 2];

    HANDLE dllHandle;
    HANDLE processHandle = GetCurrentProcess();
    DWORD64 baseOfDll;

    pfnSymInitializeW pSymInitialize;
    pfnSymSetOptions pSymSetOptions;
    pfnSymLoadModuleExW pSymLoadModuleEx;
    pfnSymFromNameW pSymFromName;
    pfnSymUnloadModule64 pSymUnloadModule64;
    pfnSymCleanup pSymCleanup;


    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (GetModuleFileName(NULL, szBuffer, MAX_PATH) == 0)
        return FALSE;

    _filepath(szBuffer, szBuffer);
    _strcat(szBuffer, TEXT("symdll\\"));
    dirLength = _strlen(szBuffer);
    _strcat(szBuffer, TEXT("dbghelp.dll"));
    dllHandle = LoadLibrary(szBuffer);
    if (dllHandle == NULL)
        return FALSE;

    /*szBuffer[dirLength] = 0;
    _strcat(szBuffer, TEXT("symsrv.dll"));
    LoadLibrary(szBuffer);*/

    pSymInitialize = (pfnSymInitializeW)GetProcAddress(dllHandle, "SymInitializeW");
    if (pSymInitialize == NULL)
        return FALSE;

    pSymSetOptions = (pfnSymSetOptions)GetProcAddress(dllHandle, "SymSetOptions");
    if (pSymSetOptions == NULL)
        return FALSE;

    pSymLoadModuleEx = (pfnSymLoadModuleExW)GetProcAddress(dllHandle, "SymLoadModuleExW");
    if (pSymLoadModuleEx == NULL)
        return FALSE;

    pSymFromName = (pfnSymFromNameW)GetProcAddress(dllHandle, "SymFromNameW");
    if (pSymFromName == NULL)
        return FALSE;

    pSymUnloadModule64 = (pfnSymUnloadModule64)GetProcAddress(dllHandle, "SymUnloadModule64");
    if (pSymUnloadModule64 == NULL)
        return FALSE;

    pSymCleanup = (pfnSymCleanup)GetProcAddress(dllHandle, "SymCleanup");
    if (pSymCleanup == NULL)
        return FALSE;

    pSymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

    szBuffer[dirLength] = 0;
    _strcat(szBuffer, TEXT("Symbols"));
    if (!CreateDirectory((LPCWSTR)&szBuffer, NULL))
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            return FALSE;

    _strcpy(szUserSearchPath, TEXT("SRV*"));
    _strcat(szUserSearchPath, szBuffer);
    _strcat(szUserSearchPath, DEFAULT_SYMPATH);

    processHandle = GetCurrentProcess();

    if (pSymInitialize(processHandle, szUserSearchPath, FALSE)) {

        baseOfDll = pSymLoadModuleEx(processHandle,
            NULL,
            TEXT("appinfo.dll"),
            NULL,
            (DWORD64)AppInfo->DllBase,
            0,
            NULL,
            0);

        if (baseOfDll) {
            AppInfo->lpAutoApproveEXEList = (PVOID*)LookupAddressBySymbol(pSymFromName, TEXT("g_lpAutoApproveEXEList"), NULL);
            AppInfo->lpIncludedPFDirs = (PVOID*)LookupAddressBySymbol(pSymFromName, TEXT("g_lpIncludedPFDirs"), NULL);
            AppInfo->lpIncludedWindowsDirs = (PVOID*)LookupAddressBySymbol(pSymFromName, TEXT("g_lpIncludedWindowsDirs"), NULL);
            AppInfo->lpIncludedSystemDirs = (PVOID*)LookupAddressBySymbol(pSymFromName, TEXT("g_lpIncludedSystemDirs"), NULL);
            AppInfo->lpExemptedAutoApproveExes = (PVOID*)LookupAddressBySymbol(pSymFromName, TEXT("g_lpExemptedAutoApproveExes"), NULL);
            AppInfo->lpExcludedWindowsDirs = (PVOID*)LookupAddressBySymbol(pSymFromName, TEXT("g_lpExcludedWindowsDirs"), NULL);
            AppInfo->lpAutoApproveEXEList = (PVOID*)LookupAddressBySymbol(pSymFromName, TEXT("g_lpAutoApproveEXEList"), NULL);

            pSymUnloadModule64(processHandle, baseOfDll);
            pSymCleanup(processHandle);

            return TRUE;
        }

    }

    return FALSE;
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
    _In_ ULONG AppInfoBuildNumber,
    _In_ UAC_PATTERN* Patterns,
    _In_ ULONG PatternsCount,
    _Out_ LPCVOID* OutputPattern,
    _Out_ ULONG* OutputPatternSize,
    _Out_opt_ ULONG* SubtractBytes
)
{
    ULONG i;

    *OutputPattern = NULL;
    *OutputPatternSize = 0;

    if (SubtractBytes)
        *SubtractBytes = 0;

    for (i = 0; i < PatternsCount; i++) {
        if ((AppInfoBuildNumber >= Patterns[i].AppInfoBuildMin) &&
            (AppInfoBuildNumber <= Patterns[i].AppInfoBuildMax))
        {
            *OutputPattern = Patterns[i].PatternData;
            *OutputPatternSize = Patterns[i].PatternSize;

            if (SubtractBytes)
                *SubtractBytes = Patterns[i].SubtractBytes;

            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN QueryAiMmcBlockWin11(
    _In_ UAC_AI_GLOBALS* AppInfo,
    _In_ PBYTE PtrCode,
    _In_ ULONG SectionSize
)
{
    ULONG       instOffset, patternOffset;
    LONG        rel = 0;
    PVOID       TestPtr = NULL;

    hde64s      hs;
    PBYTE       ptrCode;

    ULONG       PatternSize = 0;
    PVOID       PatternData = NULL;


    if (GetSupportedPattern(AppInfo->AppInfoBuildNumber,
        g_MmcPatterns2,
        RTL_NUMBER_OF(g_MmcPatterns2),
        &PatternData,
        &PatternSize,
        NULL))
    {

        ptrCode = supFindPattern(PtrCode,
            SectionSize,
            (CONST PBYTE)PatternData,
            PatternSize);

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

    }

    return FALSE;
}

BOOLEAN QueryAiMmcBlockWin10(
    _In_ UAC_AI_GLOBALS* AppInfo,
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
    _In_ UAC_AI_GLOBALS* AppInfo
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

    if (AppInfo->AppInfoBuildNumber < NT_WIN10_REDSTONE5) {
        if (GetSupportedPattern(AppInfo->AppInfoBuildNumber,
            g_MmcPatterns,
            RTL_NUMBER_OF(g_MmcPatterns),
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

        //
        // Windows 10 RS5 - 21H2
        //
        if (AppInfo->AppInfoBuildNumber < NT_WIN11_21H2) {
            return QueryAiMmcBlockWin10(AppInfo, ptrCode, sectionSize);
        }
        else {
            //
            // Windows 11 21H2 - XXXX
            //
            return QueryAiMmcBlockWin11(AppInfo, ptrCode, sectionSize);
        }

    }
    return FALSE;
}

BOOL IsCrossPtr(
    _In_ UAC_AI_GLOBALS* AppInfo,
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
    _In_ UAC_AI_GLOBALS* AppInfo,
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
        if (AppInfo->MmcBlock->NumOfElements == 0 ||
            AppInfo->MmcBlock->NumOfElements > 256) {
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
    _In_ UAC_AI_GLOBALS* AppInfo,
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
    UAC_AI_GLOBALS* AppInfo,
    AI_DATA_TYPE AiDataType,
    PVOID* Data,
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

        //
        // Due to brilliant MS design all newest versions has the same build in file version attributes.
        //
        if (g_NtBuildNumber >= NT_WIN10_19H1) {
            AppInfo.AppInfoBuildNumber = g_NtBuildNumber;
        }
        else {
            if (!GetAppInfoBuildVersion(lpFileName, &AppInfo.AppInfoBuildNumber))
                break;
        }

#ifdef _DEBUG
        AppInfo.AppInfoBuildNumber = g_TestAppInfoBuildNumber;
#endif

        if (RtlDosPathNameToNtPathName_U(lpFileName, &usFileName, NULL, NULL) == FALSE)
            break;

        InitializeObjectAttributes(&attr, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);    
        RtlSecureZeroMemory(&iosb, sizeof(iosb));

        status = NtCreateFile(&hFile, 
            SYNCHRONIZE | FILE_READ_DATA,
            &attr, 
            &iosb, 
            NULL, 
            0, 
            FILE_SHARE_READ, 
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, 
            NULL, 
            0);

        if (!NT_SUCCESS(status))
            break;

        status = NtCreateSection(&hSection, 
            SECTION_ALL_ACCESS, 
            NULL,
            NULL, 
            PAGE_READONLY, 
            SEC_IMAGE, 
            hFile);

        if (!NT_SUCCESS(status))
            break;

        DllBase = NULL;
        DllVirtualSize = 0;

        status = NtMapViewOfSection(hSection, 
            NtCurrentProcess(), 
            (PVOID*)&DllBase,
            0, 
            0, 
            NULL, 
            &DllVirtualSize, 
            ViewUnmap, 
            0, 
            PAGE_READONLY);

        if (!NT_SUCCESS(status))
            break;

        AppInfo.DllBase = DllBase;
        AppInfo.DllVirtualSize = DllVirtualSize;

        ListMMCFiles(&AppInfo, OutputCallback);

        if (ResolveAppInfoSymbols(&AppInfo)) {
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
