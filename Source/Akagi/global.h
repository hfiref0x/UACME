/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.90
*
*  DATE:        17 Sept 2015
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) //exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#include <Windows.h>
#include <ntstatus.h>
#include "..\shared\ntos.h"
#include "..\shared\minirtl.h"
#include "sup.h"
#include "inject.h"
#include "cmdline.h"
#include "pitou.h"
#include "gootkit.h"
#include "simda.h"
#include "carberp.h"
#include "hybrids.h"
