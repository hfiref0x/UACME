/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       HYBRIDS.H
*
*  VERSION:     2.01
*
*  DATE:        04 Jan 2016
*
*  Prototypes and definitions for hybrid methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmAvrfMethod(
	CONST PVOID AvrfDll,
	DWORD AvrfDllSize
	);

BOOL ucmWinSATMethod(
	LPWSTR lpTargetDll,
	PVOID ProxyDll,
	DWORD ProxyDllSize,
	BOOL UseWusa
	);

BOOL ucmMMCMethod(
	LPWSTR lpTargetDll,
	PVOID ProxyDll,
	DWORD ProxyDllSize
	);

BOOL ucmSirefefMethod(
	PVOID ProxyDll,
	DWORD ProxyDllSize
	);

BOOL ucmGenericAutoelevation(
	LPWSTR lpTargetApp,
	LPWSTR lpTargetDll,
	PVOID ProxyDll,
	DWORD ProxyDllSize
	);

BOOL ucmGWX(
	VOID
	);
