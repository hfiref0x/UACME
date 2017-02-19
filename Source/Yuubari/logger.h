#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       LOGGER.H
*
*  VERSION:     1.0F
*
*  DATE:        13 Feb 2017
*
*  Header file for the log file writter.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

HANDLE LoggerCreate(
    _In_opt_ LPWSTR lpLogFileName
    );

VOID LoggerWrite(
    _In_ HANDLE hLogFile,
    _In_ LPWSTR lpText,
    _In_ BOOL UseReturn
    );
