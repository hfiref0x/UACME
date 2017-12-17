/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       PITOU.H
*
*  VERSION:     2.85
*
*  DATE:        01 Dec 2017
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

BOOL ucmStandardAutoElevation(
    _In_ UCM_METHOD Method,
    _In_  PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

BOOL ucmStandardAutoElevation2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);
