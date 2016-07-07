/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       PITOU.H
*
*  VERSION:     2.50
*
*  DATE:        06 July 2016
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
    UACBYPASSMETHOD Method,
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize
    );

BOOL ucmMasqueradedCreateSubDirectoryCOM(
    LPWSTR ParentDirectory,
    LPWSTR SubDirectory
    );

BOOL ucmMasqueradedMoveFileCOM(
    LPWSTR SourceFileName,
    LPWSTR DestinationDir
    );

BOOL ucmStandardAutoElevation2(
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize
    );

BOOL ucmMasqueradedRenameElementCOM(
    LPWSTR OldName,
    LPWSTR NewName
    );
