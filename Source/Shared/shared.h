/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       SAHRED.H
*
*  VERSION:     2.89
*
*  DATE:        14 June 2018
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
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u

#include <Windows.h>
#include <ntstatus.h>
#include "ntos.h"
#include "lsa.h"
#include "minirtl.h"
#include "_filename.h"
#include "util.h"
#include "windefend.h"
