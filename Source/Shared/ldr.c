/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       LDR.C
*
*  VERSION:     3.69
*
*  DATE:        07 Jul 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

DWORD align_gt(
    DWORD p,
    DWORD align
)
{
    DWORD remainder;

    if (align == 0) return p;
    remainder = p % align;
    if (remainder == 0) return p;

    if (p > MAXDWORD - (align - remainder)) return p;
    return p + (align - remainder);
}

DWORD align_le(
    DWORD p,
    DWORD align
)
{
    if ((p % align) == 0)
        return p;

    return p - (p % align);
}

LPVOID PELoaderLoadImage(
    _In_ LPVOID Buffer,
    _Out_opt_ PDWORD SizeOfImage
)
{
    DWORD c, p, rsz;
    DWORD optHeaderSize = 0, headersSize = 0;
    DWORD_PTR delta;
    LPWORD chains;
    LPVOID exeBuffer = NULL;
    PIMAGE_DOS_HEADER dosh;
    PIMAGE_FILE_HEADER fileh;
    PIMAGE_OPTIONAL_HEADER popth;
    PIMAGE_SECTION_HEADER sections;
    PIMAGE_BASE_RELOCATION rel;
    PIMAGE_NT_HEADERS nth = NULL;

    do {
        if (Buffer == NULL) {
            SetLastError(ERROR_INVALID_PARAMETER);
            break;
        }

        // check image headers
        // we are supposed to deal with valid or system bins usually so these checks are slightly redurant

        dosh = (PIMAGE_DOS_HEADER)Buffer;
        if (dosh->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            break;
        }

        if (dosh->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dosh->e_lfanew > 0xFFFFF) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            break;
        }

        nth = (PIMAGE_NT_HEADERS)((PBYTE)Buffer + dosh->e_lfanew);
        if (nth->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            break;
        }

        fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
        optHeaderSize = fileh->SizeOfOptionalHeader;
        if (optHeaderSize != sizeof(IMAGE_OPTIONAL_HEADER32) &&
            optHeaderSize != sizeof(IMAGE_OPTIONAL_HEADER64)) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            break;
        }

        popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
        if (popth->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
            popth->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            break;
        }

        if (SizeOfImage) *SizeOfImage = popth->SizeOfImage;

        // render image
        headersSize = align_gt(popth->SizeOfHeaders, popth->FileAlignment);
        if (headersSize > popth->SizeOfImage) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            break;
        }

        exeBuffer = VirtualAlloc(NULL, popth->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (exeBuffer == NULL) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
        }

        memcpy(exeBuffer, Buffer, min(headersSize, popth->SizeOfHeaders));

        sections = (PIMAGE_SECTION_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER) + fileh->SizeOfOptionalHeader);
        for (c = 0; c < fileh->NumberOfSections; c++) {
            if ((sections[c].SizeOfRawData > 0) && (sections[c].PointerToRawData > 0)) {
                memcpy((PBYTE)exeBuffer + sections[c].VirtualAddress,
                    (PBYTE)Buffer + align_le(sections[c].PointerToRawData, popth->FileAlignment),
                    align_gt(sections[c].SizeOfRawData, popth->FileAlignment));
            }
        }

        // reloc image
        dosh = (PIMAGE_DOS_HEADER)exeBuffer;
        fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
        popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));

        if (popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
            if (popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
            {
                rel = (PIMAGE_BASE_RELOCATION)((PBYTE)exeBuffer + popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                delta = (DWORD_PTR)exeBuffer - popth->ImageBase;

                c = 0;
                while (c < rsz) {
                    p = sizeof(IMAGE_BASE_RELOCATION);
                    chains = (LPWORD)((PBYTE)rel + p);

                    while (p < rel->SizeOfBlock) {

                        switch (*chains >> 12) {
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(LPDWORD)((ULONG_PTR)exeBuffer + rel->VirtualAddress + (*chains & 0x0fff)) += (DWORD)delta;
                            break;
                        case IMAGE_REL_BASED_DIR64:
                            *(PULONGLONG)((ULONG_PTR)exeBuffer + rel->VirtualAddress + (*chains & 0x0fff)) += delta;
                            break;
                        }

                        chains++;
                        p += sizeof(WORD);
                    }

                    c += rel->SizeOfBlock;
                    rel = (PIMAGE_BASE_RELOCATION)((PBYTE)rel + rel->SizeOfBlock);
                }
            }

        return exeBuffer;

    } while (FALSE);

    return NULL;
}

LPVOID PELoaderGetProcAddress(
    _In_ LPVOID ImageBase,
    _In_ PCHAR RoutineName
)
{
    USHORT OrdinalIndex;
    LONG Result;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PULONG NameTableBase, FunctionTableBase;
    PUSHORT NameOrdinalTableBase;
    PCHAR CurrentName;
    ULONG High, Low, Middle = 0;
    ULONG ExportDirRVA, ExportDirSize;
    ULONG FunctionRVA;

    union {
        PIMAGE_NT_HEADERS64 nt64;
        PIMAGE_NT_HEADERS32 nt32;
        PIMAGE_NT_HEADERS nt;
    } NtHeaders;

    if (ImageBase == NULL || RoutineName == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    NtHeaders.nt = RtlImageNtHeader(ImageBase);
    if (NtHeaders.nt == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        ExportDirRVA = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportDirSize = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        ExportDirRVA = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportDirSize = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else {
        SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH);
        return NULL;
    }

    if (ExportDirRVA == 0 || ExportDirSize == 0) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer((ULONG_PTR)ImageBase, ExportDirRVA);
    NameTableBase = (PULONG)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfNameOrdinals);
    FunctionTableBase = (PULONG)((ULONG_PTR)ImageBase + ExportDirectory->AddressOfFunctions);

    if (ExportDirectory->NumberOfNames == 0) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    Low = 0;
    High = ExportDirectory->NumberOfNames - 1;

    while (Low <= High) {
        Middle = Low + (High - Low) / 2;
        CurrentName = (PCHAR)RtlOffsetToPointer((ULONG_PTR)ImageBase, NameTableBase[Middle]);
        Result = _strcmp_a(RoutineName, CurrentName);
        if (Result == 0) {
            OrdinalIndex = NameOrdinalTableBase[Middle];
            if (OrdinalIndex >= ExportDirectory->NumberOfFunctions) {
                SetLastError(ERROR_PROC_NOT_FOUND);
                return NULL;
            }
            FunctionRVA = FunctionTableBase[OrdinalIndex];
            if (FunctionRVA == 0) {
                SetLastError(ERROR_PROC_NOT_FOUND);
                return NULL;
            }
            return (LPVOID)RtlOffsetToPointer((ULONG_PTR)ImageBase, FunctionRVA);
        }
        if (Result < 0) {
            if (Middle == 0) break;
            High = Middle - 1;
        }
        else {
            Low = Middle + 1;
        }

    }

    SetLastError(ERROR_PROC_NOT_FOUND);
    return NULL;
}
