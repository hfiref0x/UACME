/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       MAKECAB.H
*
*  VERSION:     2.00
*
*  DATE:        12 Nov 2015
*
*  Prototypes and definitions for makecab module.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <fci.h>
#include <fcntl.h>

typedef struct _CABDATA {
	ERF erf;
	CCAB cab;
	HFCI hfci;
} CABDATA, *PCABDATA;

CABDATA *cabCreate(
	_In_ LPWSTR lpszCabName
	);

BOOL cabAddFile(
	_In_ CABDATA *Cabinet,
	_In_ LPWSTR lpszFileName,
	_In_ LPWSTR lpszInternalName
	);

VOID cabClose(
	_In_ CABDATA *Cabinet
	);

