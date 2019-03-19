/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       AIC.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  Common header file for the AppInfo routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef ULONG ELEVATION_REASON;

ULONG_PTR AicFindLaunchAdminProcess(
    _Out_ PNTSTATUS StatusCode);

_Success_(return != FALSE)
BOOL AicSetRemoveFunctionBreakpoint(
    _In_ PVOID pfnTargetRoutine,
    _Inout_ BYTE *pbRestoreBuffer,
    _In_ ULONG cbRestoreBuffer,
    _In_ BOOL bSet,
    _Out_opt_ PULONG pcbBytesWritten);
