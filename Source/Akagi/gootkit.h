/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016, 
*  (C) FixIT Shim Patches by Jon Erickson
*
*  TITLE:       GOOTKIT.H
*
*  VERSION:     2.20
*
*  DATE:        20 Apr 2016
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

BOOL ucmAppcompatElevation(
    UACBYPASSMETHOD Method,
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize,
    LPWSTR lpszPayloadEXE
    );
