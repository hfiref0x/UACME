/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       CUI.H
*
*  VERSION:     1.10
*
*  DATE:        04 Feb 2017
*
*  Common header file for console ui.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

VOID cuiPrintTextA(
	_In_ HANDLE hOutConsole,
	_In_ LPSTR lpText,
	_In_ BOOL ConsoleOutputEnabled,
	_In_ BOOL UseReturn
	);

VOID cuiPrintTextW(
    _In_ HANDLE hOutConsole,
    _In_ LPWSTR lpText,
    _In_ BOOL ConsoleOutputEnabled,
    _In_ BOOL UseReturn
);

#ifdef UNICODE
#define cuiPrintText cuiPrintTextW
#else
#define cuiPrintText cuiPrintTextA
#endif
