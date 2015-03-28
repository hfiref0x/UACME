/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       SUP.H
*
*  VERSION:     1.10
*
*  DATE:        27 Mar 2015
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

BOOLEAN supIsProcess32bit(
	_In_ HANDLE hProcess
	);

HANDLE supGetExplorerHandle(
	VOID
	);

BOOL supGetElevationType(
	TOKEN_ELEVATION_TYPE *lpType
	);
