/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016, 
*  (C) Original idea (?) mzH,
*  (C) FixIT Shim Patches by Jon Erickson
*
*  TITLE:       GOOTKIT.H
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
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
