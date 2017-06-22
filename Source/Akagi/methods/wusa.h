/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       WUSA.H
*
*  VERSION:     2.74
*
*  DATE:        20 June 2017
*
*  Prototypes and definitions for Windows Update Standalone Installer (WUSA) based methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmWusaExtractPackage(
    _In_ LPWSTR lpTargetDirectory);

BOOL ucmCreateCabinetForSingleFile(
    _In_ LPWSTR lpSourceDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

BOOL ucmWusaExtractViaJunction(
    _In_ LPWSTR lpTargetDirectory);
