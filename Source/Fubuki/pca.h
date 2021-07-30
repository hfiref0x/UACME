/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       PCA.H
*
*  VERSION:     3.56
*
*  DATE:        19 July 2021
*
*  Fubuki Program Compatibility Assistant related code header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _PCA_LOADER_BLOCK {
    ULONG OpResult;
    WCHAR szLoader[MAX_PATH + 1];
} PCA_LOADER_BLOCK, * PPCA_LOADER_BLOCK;
