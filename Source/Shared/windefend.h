/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       WINDEFEND.H
*
*  VERSION:     2.89
*
*  DATE:        14 June 2018
*
*  MSE / Windows Defender anti-emulation part header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

VOID wdCheckEmulatedVFS(
    VOID);

LRESULT CALLBACK wdDummyWindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam);

NTSTATUS wdIsEmulatorPresent(
    VOID);
