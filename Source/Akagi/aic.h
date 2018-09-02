/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       AIC.H
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
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
    _In_ PULONG ErrorCode);

BOOL AicSetRemoveFunctionBreakpoint(
    _In_ PVOID pfnTargetRoutine,
    _Inout_ BYTE *pbRestoreBuffer,
    _In_ ULONG cbRestoreBuffer,
    _In_ BOOL bSet,
    _Out_opt_ PULONG pcbBytesWritten);
