/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2020
*
*  TITLE:       AIC.H
*
*  VERSION:     3.23
*
*  DATE:        17 Dec 2019
*
*  Common header file for the AppInfo routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef ULONG ELEVATION_REASON;

BOOLEAN AicLaunchAdminProcess(
    _In_opt_ LPWSTR ExecutablePath,
    _In_opt_ LPWSTR CommandLine,
    _In_ DWORD StartFlags,
    _In_ DWORD CreationFlags,
    _In_ LPWSTR CurrentDirectory,
    _In_ LPWSTR WindowStation,
    _In_opt_ HWND hWnd,
    _In_ DWORD Timeout,
    _In_ DWORD ShowFlags,
    _Out_ PROCESS_INFORMATION* ProcessInformation);
