/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       SUP.C
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

/*
* supIsCorImageFile
*
* Purpose:
*
* Return true if image has CliHeader entry, false otherwise.
*
*/
BOOL supIsCorImageFile(
    _In_ PVOID ImageBase
)
{
    ULONG               sz = 0;
    IMAGE_COR20_HEADER* CliHeader;

    CliHeader = (IMAGE_COR20_HEADER*)RtlImageDirectoryEntryToData(ImageBase, TRUE,
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &sz);

    return ((CliHeader != NULL) && (sz >= sizeof(IMAGE_COR20_HEADER)));
}

/*
* supReadKeyString
*
* Purpose:
*
* Read string value from registry key.
*
*/
LPWSTR supReadKeyString(
    _In_ HKEY hKey,
    _In_ LPWSTR KeyValue,
    _In_ PDWORD pdwDataSize
    )
{
    LRESULT lRet;
    LPWSTR  lpString = NULL;

    if (pdwDataSize == NULL)
        return NULL;

    lRet = RegQueryValueEx(hKey, KeyValue, NULL,
        NULL, NULL, pdwDataSize);
    if (lRet == ERROR_SUCCESS) {
        lpString = (LPWSTR)supHeapAlloc(*pdwDataSize);
        if (lpString != NULL) {
            lRet = RegQueryValueEx(hKey, KeyValue, NULL,
                NULL, (LPBYTE)lpString, pdwDataSize);
            if (lRet != ERROR_SUCCESS) {
                supHeapFree(lpString);
                lpString = NULL;
            }
        }
    }
    return lpString;
}

/*
* supQueryKeyName
*
* Purpose:
*
* Get key name from handle.
*
*/
PVOID supQueryKeyName(
    _In_ HKEY hKey,
    _Out_opt_ PSIZE_T ReturnedLength
    )
{
    NTSTATUS    status;
    ULONG       ulen = 0;
    SIZE_T      sz = 0;
    PVOID       ReturnBuffer = NULL;

    POBJECT_NAME_INFORMATION pObjName = NULL;

    if (ReturnedLength)
        *ReturnedLength = 0;

    NtQueryObject(hKey, ObjectNameInformation, NULL, 0, &ulen);
    pObjName = (POBJECT_NAME_INFORMATION)supHeapAlloc(ulen);
    if (pObjName) {
        status = NtQueryObject(hKey, ObjectNameInformation, pObjName, ulen, NULL);
        if (NT_SUCCESS(status)) {
            if ((pObjName->Name.Buffer != NULL) && (pObjName->Name.Length > 0)) {
                sz = pObjName->Name.Length + sizeof(UNICODE_NULL);
                ReturnBuffer = supHeapAlloc(sz);
                if (ReturnBuffer) {
                    RtlCopyMemory(ReturnBuffer, pObjName->Name.Buffer, pObjName->Name.Length);
                    if (ReturnedLength)
                        *ReturnedLength = sz;
                }
            }
        }
        supHeapFree(pObjName);
    }
    return ReturnBuffer;
}

/*
* supIsProcess32bit
*
* Purpose:
*
* Return TRUE if given process is under WOW64, FALSE otherwise.
*
*/
BOOLEAN supIsProcess32bit(
    _In_ HANDLE hProcess
    )
{
    NTSTATUS status;
    PROCESS_EXTENDED_BASIC_INFORMATION pebi;

    if (hProcess == NULL) {
        return FALSE;
    }

    //query if this is wow64 process
    RtlSecureZeroMemory(&pebi, sizeof(pebi));
    pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), NULL);
    if (NT_SUCCESS(status)) {
        return (pebi.IsWow64Process == 1);
    }
    return FALSE;
}

/*
* supFindPattern
*
* Purpose:
*
* Lookup pattern in buffer.
*
*/
PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize
)
{
    PBYTE p0 = Buffer, pnext;

    if (PatternSize == 0)
        return NULL;

    if (BufferSize < PatternSize)
        return NULL;

    do {
        pnext = (PBYTE)memchr(p0, Pattern[0], BufferSize);
        if (pnext == NULL)
            break;

        BufferSize -= (ULONG_PTR)(pnext - p0);

        if (BufferSize < PatternSize)
            return NULL;

        if (memcmp(pnext, Pattern, PatternSize) == 0)
            return pnext;

        p0 = pnext + 1;
        --BufferSize;
    } while (BufferSize > 0);

    return NULL;
}

/*
* supRegReadDword
*
* Purpose:
*
* Read DWORD value from given key.
*
*/
LRESULT supRegReadDword(
    _In_ HKEY hKey,
    _In_ LPWSTR lpValueName,
    _In_ LPDWORD Value
)
{
    LRESULT lResult;
    DWORD dwValue = 0, bytesIO;

    bytesIO = sizeof(DWORD);
    lResult = RegQueryValueEx(hKey, lpValueName,
        NULL, NULL,
        (LPBYTE)&dwValue, &bytesIO);

    if (lResult == ERROR_SUCCESS) {
        if (Value)
            *Value = dwValue;
    }
    return lResult;
}

/*
* supLookupImageSectionByName
*
* Purpose:
*
* Lookup section pointer and size for section name.
*
*/
PVOID supLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize
)
{
    BOOLEAN bFound = FALSE;
    ULONG i;
    PVOID Section;
    IMAGE_NT_HEADERS* NtHeaders = RtlImageNtHeader(DllBase);
    IMAGE_SECTION_HEADER* SectionTableEntry;

    //
    // Assume failure.
    //
    if (SectionSize)
        *SectionSize = 0;

    if (NtHeaders == NULL)
        return NULL;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    //
    // Locate section.
    //
    i = NtHeaders->FileHeader.NumberOfSections;
    while (i > 0) {

        if (_strncmp_a(
        (CHAR*)SectionTableEntry->Name,
            SectionName,
            SectionNameLength) == 0)
        {
            bFound = TRUE;
            break;
        }

        i -= 1;
        SectionTableEntry += 1;
    }

    //
    // Section not found, abort scan.
    //
    if (!bFound)
        return NULL;

    Section = (PVOID)((ULONG_PTR)DllBase + SectionTableEntry->VirtualAddress);
    if (SectionSize)
        *SectionSize = SectionTableEntry->Misc.VirtualSize;

    return Section;
}

/*
* supConcatenatePaths
*
* Purpose:
*
* Concatenate 2 paths.
*
*/
BOOL supConcatenatePaths(
    _Inout_ LPWSTR Target,
    _In_ LPCWSTR Path,
    _In_ SIZE_T TargetBufferSize
)
{
    SIZE_T TargetLength, PathLength;
    BOOL TrailingBackslash, LeadingBackslash;
    SIZE_T EndingLength;

    TargetLength = _strlen(Target);
    PathLength = _strlen(Path);

    if (TargetLength && (*CharPrev(Target, Target + TargetLength) == TEXT('\\'))) {
        TrailingBackslash = TRUE;
        TargetLength--;
    }
    else {
        TrailingBackslash = FALSE;
    }

    if (Path[0] == TEXT('\\')) {
        LeadingBackslash = TRUE;
        PathLength--;
    }
    else {
        LeadingBackslash = FALSE;
    }

    EndingLength = TargetLength + PathLength + 2;

    if (!LeadingBackslash && (TargetLength < TargetBufferSize)) {
        Target[TargetLength++] = TEXT('\\');
    }

    if (TargetBufferSize > TargetLength) {
        _strncpy(Target + TargetLength,
            TargetBufferSize - TargetLength,
            Path,
            TargetBufferSize - TargetLength);
    }

    if (TargetBufferSize) {
        Target[TargetBufferSize - 1] = 0;
    }

    return (EndingLength <= TargetBufferSize);
}
