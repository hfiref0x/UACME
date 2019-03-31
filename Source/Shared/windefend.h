/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       WINDEFEND.H
*
*  VERSION:     3.18
*
*  DATE:        29 Mar 2019
*
*  MSE / Windows Defender anti-emulation part header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include "mpclient.h"

typedef HRESULT(WINAPI *pfnMpRoutine)(PVOID);

typedef struct _MP_API_ENTRY {
    DWORD Hash;
    pfnMpRoutine Routine;
} MP_API_ENTRY, *PMP_API_ENTRY;

typedef struct _MP_API {
    MP_API_ENTRY MpManagerOpen;
    MP_API_ENTRY MpHandleClose;
    MP_API_ENTRY MpManagerVersionQuery;
    MP_API_ENTRY WDStatus;
    //Kuma part start here
    //
} MP_API, *PMP_API;

VOID wdCheckEmulatedVFS(
    VOID);

NTSTATUS wdIsEmulatorPresent(
    VOID);

BOOLEAN wdIsEmulatorPresent2(
    VOID);

NTSTATUS wdIsEnabled(
    VOID);

_Success_(return != FALSE)
BOOL wdGetAVSignatureVersion(
    _Out_ PMPCOMPONENT_VERSION SignatureVersion);

_Success_(return != NULL)
PVOID wdLoadClient(
    _In_ BOOL IsWow64,
    _Out_opt_ PNTSTATUS Status);
