/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       AIC.H
*
*  VERSION:     2.76
*
*  DATE:        12 July 2017
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

ULONG_PTR AipFindLaunchAdminProcess(
    _In_ PULONG ErrorCode);
