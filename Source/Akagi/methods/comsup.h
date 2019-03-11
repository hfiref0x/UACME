/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       COMSUP.H
*
*  VERSION:     3.16
*
*  DATE:        11 Mar 2019
*
*  Prototypes and definitions for COM interfaces support and
*  IFileOperation based routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#ifndef UCM_DEFINE_GUID
#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  
#endif

UCM_DEFINE_GUID(IID_ICreateNewLink, 0xB5AB9C96, 0xC11D, 0x43E7, 0xB4, 0x4C, 0x79, 0xB1, 0x3E, 0xE7, 0xAC, 0x6F);
UCM_DEFINE_GUID(IID_IColorDataProxy, 0x0A16D195, 0x6F47, 0x4964, 0x92, 0x87, 0x9F, 0x4B, 0xAB, 0x6D, 0x98, 0x27);
UCM_DEFINE_GUID(IID_ICMLuaUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);
UCM_DEFINE_GUID(IID_IFwCplLua, 0x56DA8B35, 0x7FC3, 0x45DF, 0x87, 0x68, 0x66, 0x41, 0x47, 0x86, 0x45, 0x73);
UCM_DEFINE_GUID(IID_ISecurityEditor, 0x14B2C619, 0xD07A, 0x46EF, 0x8B, 0x62, 0x31, 0xB6, 0x4F, 0x3B, 0x84, 0x5C);
UCM_DEFINE_GUID(IID_ISPPLUAObject, 0x12FBFECB, 0x7CCE, 0x473E, 0x87, 0x37, 0x78, 0xEE, 0x6C, 0x9C, 0xCA, 0xEB);
UCM_DEFINE_GUID(IID_IARPUninstallStringLauncher, 0xF885120E, 0x3789, 0x4FD9, 0x86, 0x5E, 0xDC, 0x9B, 0x4A, 0x64, 0x12, 0xD2);
UCM_DEFINE_GUID(IID_DateTimeStateWriter, 0x500DD1A1, 0xB32A, 0x4A37, 0x92, 0x83, 0x11, 0x85, 0xFB, 0x61, 0x38, 0x99);
UCM_DEFINE_GUID(IID_IAccessibilityCplAdmin, 0x97B9F488, 0xB188, 0x4B03, 0x9B, 0x27, 0xD7, 0x4B, 0x25, 0x75, 0x54, 0x64);

HRESULT ucmAllocateElevatedObject(
    _In_ LPWSTR lpObjectCLSID,
    _In_ REFIID riid,
    _In_ DWORD dwClassContext,
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

BOOL ucmMasqueradedDeleteDirectoryFileCOM(
    _In_ LPWSTR FileName);

BOOL ucmMasqueradedRenameElementCOM(
    _In_ LPWSTR OldName,
    _In_ LPWSTR NewName);
