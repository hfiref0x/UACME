/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017, 
*  (C) FixIT Shim Patches by Jon Erickson
*
*  TITLE:       GOOTKIT.H
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
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
    UCM_METHOD Method,
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize,
    LPWSTR lpszPayloadEXE);
