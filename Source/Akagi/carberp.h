/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       CARBERP.H
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
*
*  Prototypes and definitions for Carberp method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmWusaMethod(
	UACBYPASSMETHOD Method,
	PVOID ProxyDll,
	DWORD ProxyDllSize
	);

BOOL ucmWusaExtractPackage(
	LPWSTR lpCommandLine
	);

BOOL ucmCreateCabinetForSingleFile(
	LPWSTR lpSourceDll,
	PVOID ProxyDll,
	DWORD ProxyDllSize
	);
