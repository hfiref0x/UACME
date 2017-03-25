/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       CARBERP.H
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
*
*  Prototypes and definitions for Carberp method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmWusaMethod(
    _In_ UCM_METHOD Method,
    PVOID ProxyDll,
    DWORD ProxyDllSize);

BOOL ucmWusaExtractPackage(
    _In_ LPWSTR lpTargetDirectory);

BOOL ucmCreateCabinetForSingleFile(
    _In_ LPWSTR lpSourceDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);
