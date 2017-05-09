/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       PITOU.H
*
*  VERSION:     2.71
*
*  DATE:        06 May 2017
*
*  Prototypes and definitions for Leo Davidson method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmStandardAutoElevation(
    UCM_METHOD Method,
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmStandardAutoElevation2(
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize);

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

HRESULT ucmMasqueradedCoGetObjectElevate(
    _In_ LPWSTR clsid,
    _In_ DWORD dwClassContext,
    _In_ REFIID riid,
    _Outptr_ void **ppv);
