/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       RINN.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
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

BOOL ucmCreateNewLinkMethodCleanup(
    VOID);
