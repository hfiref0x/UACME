/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       TYRANID.H
*
*  VERSION:     2.73
*
*  DATE:        27 May 2017
*
*  Prototypes and definitions for James Forshaw method(s).
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL ucmDiskCleanupEnvironmentVariable(
    _In_opt_ LPWSTR lpszPayload);

BOOL ucmTokenModification(
    _In_opt_ LPWSTR lpszPayload);
