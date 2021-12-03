/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       AZAGARAMPUR.H
*
*  VERSION:     3.58
*
*  DATE:        01 Dec 2021
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

NTSTATUS ucmNICPoisonMethod2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmIeAddOnInstallMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmWscActionProtocolMethod(
    _In_ LPCWSTR lpszPayload);

NTSTATUS ucmFwCplLuaMethod2(
    _In_ LPCWSTR lpszPayload);

NTSTATUS ucmMsSettingsProtocolMethod(
    _In_ LPCWSTR lpszPayload);

NTSTATUS ucmMsStoreProtocolMethod(
    _In_ LPCWSTR lpszPayload);

NTSTATUS ucmPcaMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);
