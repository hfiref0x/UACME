/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       SIMDA.H
*
*  VERSION:     1.60
*
*  DATE:        20 Apr 2015
*
*  Prototypes and definitions for Simda method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#define T_UACKEY                    L"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system"
#define T_SDDL_ALL_FOR_EVERYONE     L"D:(A;;GA;;;WD)"

BOOL ucmSimdaTurnOffUac(
	VOID
	);

BOOL ucmSimdaAlterKeySecurity(
	LPWSTR lpTargetKey,
	LPWSTR lpSddlString
	);
