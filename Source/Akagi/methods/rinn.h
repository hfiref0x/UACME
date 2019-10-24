/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       RINN.H
*
*  VERSION:     3.20
*
*  DATE:        24 Oct 2019
*
*  Prototypes and definitions for RinN method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

NTSTATUS ucmCreateNewLinkMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmEditionUpgradeManagerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

BOOL ucmCreateNewLinkMethodCleanup(
    VOID);

BOOL ucmEditionUpgradeManagerMethodCleanup(
    VOID);
