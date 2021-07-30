/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2021
*
*  TITLE:       NAKA.H
*
*  VERSION:     3.03
*
*  DATE:        15 July 2021
*
*  Common header file for Naka.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once


#if !defined UNICODE
#error ANSI build is not supported
#endif

#include "shared\libinc.h"

#pragma comment(lib, "msdelta.lib")
#pragma comment(lib, "Bcrypt.lib")

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#include <Windows.h>
#include <ntstatus.h>
#include <msdelta.h>
#include <Bcrypt.h>
#include "shared\ntos\ntos.h"
#include "shared\minirtl.h"
#include "shared\cmdline.h"
#include "shared\_filename.h"

#define UACME_CONTAINER_PACKED_UNIT 'UPCU' //Naka handling
#define UACME_CONTAINER_PACKED_DATA 'DPCU' //Naka handling
#define UACME_CONTAINER_PACKED_CODE 'CPCU' //Kuma handling
#define UACME_CONTAINER_PACKED_KEYS 'KPCU' //Kuma handling

//Initialization vector max bytes
#define DCU_IV_MAX_BLOCK_LENGTH 16

typedef struct _DCU_HEADER {
    DWORD Magic;
    DWORD cbData;
    DWORD cbDeltaSize;
    DWORD HeaderCrc;
    BYTE bIV[DCU_IV_MAX_BLOCK_LENGTH];
    //PBYTE pbData[1];     /* not a member of the structure */
} DCU_HEADER, *PDCU_HEADER;
