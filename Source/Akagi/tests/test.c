/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2020
*
*  TITLE:       TEST.C
*
*  VERSION:     3.27
*
*  DATE:        10 Sep 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmTestRoutine
*
* Purpose:
*
* Test routine, can serve multiple purposes.
*
*/
BOOL ucmTestRoutine(
    _In_opt_ PVOID PayloadCode,
    _In_opt_ ULONG PayloadSize)
{
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize); 

    SetEvent(g_ctx->SharedContext.hCompletionEvent);
    return TRUE;
}
