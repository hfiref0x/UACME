/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       SIMDA.H
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
*
*  Prototypes and definitions for Simda method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmSimdaTurnOffUac(
	VOID
	);

BOOL ucmSimdaAlterObjectSecurity(
	SE_OBJECT_TYPE ObjectType,
	SECURITY_INFORMATION SecurityInformation,
	LPWSTR lpTargetObject,
	LPWSTR lpSddlString
	);
