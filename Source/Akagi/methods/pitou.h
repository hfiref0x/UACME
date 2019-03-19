/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       PITOU.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
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

NTSTATUS ucmStandardAutoElevation(
    _In_ UCM_METHOD Method,
    _In_  PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

NTSTATUS ucmStandardAutoElevation2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

BOOL ucmSysprepMethodsCleanup(
    UCM_METHOD Method);

BOOL ucmOobeMethodCleanup(
    VOID);
