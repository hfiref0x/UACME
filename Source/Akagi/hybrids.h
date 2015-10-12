/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       HYBRIDS.H
*
*  VERSION:     1.91
*
*  DATE:        12 Oct 2015
*
*  Prototypes and definitions for hybrid methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

BOOL ucmAvrfMethod(
	PVOID AvrfDll,
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

BOOL ucmH1N1Method(
	PVOID ProxyDll,
	DWORD ProxyDllSize
	);
