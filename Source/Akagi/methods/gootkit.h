/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019, 
*  (C) FixIT Shim Patches by Jon Erickson
*
*  TITLE:       GOOTKIT.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  Prototypes and definitions for Gootkit method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

NTSTATUS ucmShimRedirectEXE(
    _In_ LPWSTR lpszPayloadEXE);

#ifndef _WIN64
NTSTATUS ucmShimPatch(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);
#endif /* _WIN64 */
