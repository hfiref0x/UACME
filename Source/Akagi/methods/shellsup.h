/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2020
*
*  TITLE:       SHELLSUP.H
*
*  VERSION:     3.50
*
*  DATE:        14 Sep 2020
*
*  Prototypes and definitions for shell registry hijack autoelevation method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

NTSTATUS ucmShellRegModMethod(
    _In_ UCM_METHOD Method,
    LPWSTR lpTargetKey,
    LPWSTR lpszTargetApp,
    LPWSTR lpszPayload);

NTSTATUS ucmShellRegModMethod2(
    _In_ UCM_METHOD Method,
    LPWSTR lpTargetKey,
    LPWSTR lpszTargetApp,
    LPWSTR lpszPayload);
