/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2021
*
*  TITLE:       SHARED.H
*
*  VERSION:     3.56
*
*  DATE:        26 July 2021
*
*  Shared include header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//disable nonmeaningful warnings.
#pragma warning(push)
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union

#include <Windows.h>
#include <ntstatus.h>
#include "ntos\ntos.h"
#include "ntos\ntbuilds.h"

#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_

#include "minirtl.h"
#include "_filename.h"
#include "util.h"
#include "windefend.h"
#include "consts.h"

#if defined(__cplusplus)
#include <malloc.h>
#endif

#pragma warning(pop)
