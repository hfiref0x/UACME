/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       WINDEFEND.H
*
*  VERSION:     3.50
*
*  DATE:        05 Oct 2020
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

NTSTATUS wdIsEmulatorPresent(
    VOID);

BOOLEAN wdIsEmulatorPresent2(
    VOID);

BOOLEAN wdIsEmulatorPresent3(
    VOID);

