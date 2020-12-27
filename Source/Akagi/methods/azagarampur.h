/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       AZAGARAMPUR.H
*
*  VERSION:     3.54
*
*  DATE:        26 Dec 2020
*
*  Prototypes and definitions for AzAgarampur methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

NTSTATUS ucmNICPoisonMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmIeAddOnInstallMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmWscActionProtocolMethod(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmFwCplLuaMethod2(
    _In_ LPWSTR lpszPayload);

NTSTATUS ucmMsSettignsProtocolMethod(
    _In_ LPWSTR lpszPayload);
