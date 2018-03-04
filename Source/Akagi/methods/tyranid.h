/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       TYRANID.H
*
*  VERSION:     2.87
*
*  DATE:        02 Mar 2018
*
*  Prototypes and definitions for James Forshaw method(s).
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmDiskCleanupEnvironmentVariable(
    _In_ LPWSTR lpszPayload);

BOOL ucmTokenModification(
    _In_ LPWSTR lpszPayload,
    _In_ BOOL fUseCommandLine);
