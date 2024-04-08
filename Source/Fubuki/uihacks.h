/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2024
*
*  TITLE:       UIHACKS.H
*
*  VERSION:     3.66
*
*  DATE:        03 Apr 2024
*
*  Fubuki UIAccess related code header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _SEARCH_WND {
    HWND hWnd;
    ULONG ProcessId;
} SEARCH_WND, *PSEARCH_WND;

VOID ucmUIHackExecute(
    _In_ LPWSTR lpPayload);

VOID ucmUIHackExecute2(
    VOID);
