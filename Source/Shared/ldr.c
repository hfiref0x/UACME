/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       LDR.C
*
*  VERSION:     2.72
*
*  DATE:        26 May 2017
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
    if ((p % align) == 0)
        return p;

    return p + align - (p % align);
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
    LPVOID                  exeBuffer = NULL;
    PIMAGE_DOS_HEADER       dosh = (PIMAGE_DOS_HEADER)Buffer;
    PIMAGE_FILE_HEADER      fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
    PIMAGE_OPTIONAL_HEADER  popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER   sections = (PIMAGE_SECTION_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER) + fileh->SizeOfOptionalHeader);
    DWORD                   c, p, rsz;
    PIMAGE_BASE_RELOCATION  rel;
    DWORD_PTR               delta;
    LPWORD                  chains;

    do {

        if (SizeOfImage) {
            *SizeOfImage = popth->SizeOfImage;
        }

        exeBuffer = VirtualAlloc(NULL, popth->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (exeBuffer == NULL)
            break;

        // render image
        memcpy(exeBuffer, Buffer, align_gt(popth->SizeOfHeaders, popth->FileAlignment));

        for (c = 0; c < fileh->NumberOfSections; c++)
            if ((sections[c].SizeOfRawData > 0) && (sections[c].PointerToRawData > 0))
                memcpy((PBYTE)exeBuffer + sections[c].VirtualAddress,
                (PBYTE)Buffer + align_le(sections[c].PointerToRawData, popth->FileAlignment),
                    align_gt(sections[c].SizeOfRawData, popth->FileAlignment));

        // reloc image
        dosh = (PIMAGE_DOS_HEADER)exeBuffer;
        fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
        popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
        sections = (PIMAGE_SECTION_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER) + fileh->SizeOfOptionalHeader);

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
    PIMAGE_EXPORT_DIRECTORY     ExportDirectory = NULL;
    PIMAGE_FILE_HEADER          fh1 = NULL;
    PIMAGE_OPTIONAL_HEADER32    oh32 = NULL;
    PIMAGE_OPTIONAL_HEADER64    oh64 = NULL;

    USHORT      OrdinalNumber;
    PULONG      NameTableBase;
    PUSHORT     NameOrdinalTableBase;
    PULONG      Addr;
    LONG        Result;
    ULONG       High, Low, Middle = 0;

    fh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew + sizeof(DWORD));
    oh32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG_PTR)fh1 + sizeof(IMAGE_FILE_HEADER));
    oh64 = (PIMAGE_OPTIONAL_HEADER64)oh32;

    if (fh1->Machine == IMAGE_FILE_MACHINE_AMD64) {
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
            oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else {
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
            oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }

    NameTableBase = (PULONG)((PBYTE)ImageBase + (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)((PBYTE)ImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
    Low = 0;
    High = ExportDirectory->NumberOfNames - 1;
    while (High >= Low) {
        Middle = (Low + High) >> 1;
        Result = _strcmp_a(
            RoutineName,
            (char *)ImageBase + NameTableBase[Middle]
        );
        if (Result < 0) {
            High = Middle - 1;
        }
        else {
            if (Result > 0) {
                Low = Middle + 1;
            }
            else {
                break;
            }
        }
    } //while
    if (High < Low)
        return NULL;

    OrdinalNumber = NameOrdinalTableBase[Middle];
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
        return NULL;

    Addr = (PULONG)((PBYTE)ImageBase + (ULONG)ExportDirectory->AddressOfFunctions);
    return (LPVOID)((PBYTE)ImageBase + Addr[OrdinalNumber]);
}
