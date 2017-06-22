/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       COMFILEOP.H
*
*  VERSION:     2.74
*
*  DATE:        10 June 2017
*
*  Prototypes and definitions for IFileOperation based routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

HRESULT ucmMasqueradedCoGetObjectElevate(
    _In_ LPWSTR clsid,
    _In_ DWORD dwClassContext,
    _In_ REFIID riid,
    _Outptr_ void **ppv);

BOOL ucmMasqueradedCreateSubDirectoryCOM(
    _In_ LPWSTR ParentDirectory,
    _In_ LPWSTR SubDirectory);

BOOL ucmMasqueradedMoveCopyFileCOM(
    _In_ LPWSTR SourceFileName,
    _In_ LPWSTR DestinationDir,
    _In_ BOOL fMove);

BOOL ucmMasqueradedMoveFileCOM(
    _In_ LPWSTR SourceFileName,
    _In_ LPWSTR DestinationDir);

BOOL ucmMasqueradedRenameElementCOM(
    _In_ LPWSTR OldName,
    _In_ LPWSTR NewName);
