/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       DEROKO.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  Prototypes and definitions for deroko method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include "elvint.h"

HRESULT ucmSPLUAObjectRegSetValue(
    _In_ PVOID InterfaceObject,
    _In_ SSLUA_ROOTKEY RegType,
    _In_ LPWSTR KeyName,
    _In_ LPWSTR ValueName,
    _In_ DWORD dwType,
    _In_ PVOID lpData,
    _In_ ULONG cbData);

NTSTATUS ucmSPPLUAObjectMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);
