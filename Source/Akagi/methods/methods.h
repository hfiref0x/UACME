/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       METHODS.H
*
*  VERSION:     2.80
*
*  DATE:        31 Aug 2017
*
*  Prototypes and definitions for UAC bypass methods table.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef enum _UCM_METHOD {
    UacMethodTest = 0,      //+
    UacMethodSysprep1 = 1,  //+
    UacMethodSysprep2,      //+
    UacMethodOobe,          //+
    UacMethodRedirectExe,   //+
    UacMethodSimda,         //+
    UacMethodCarberp1,      //+
    UacMethodCarberp2,      //+
    UacMethodTilon,         //+
    UacMethodAVrf,          //+
    UacMethodWinsat,        //+
    UacMethodShimPatch,     //+
    UacMethodSysprep3,      //+
    UacMethodMMC1,          //+
    UacMethodSirefef,       //+
    UacMethodGeneric,       //+
    UacMethodGWX,           //+
    UacMethodSysprep4,      //+
    UacMethodManifest,      //+
    UacMethodInetMgr,       //+
    UacMethodMMC2,          //+
    UacMethodSXS,           //+
    UacMethodSXSConsent,    //+
    UacMethodDISM,          //+
    UacMethodComet,         //+
    UacMethodEnigma0x3,     //+
    UacMethodEnigma0x3_2,   //+
    UacMethodExpLife,       //+
    UacMethodSandworm,      //+
    UacMethodEnigma0x3_3,   //+
    UacMethodWow64Logger,   //+
    UacMethodEnigma0x3_4,   //+
    UacMethodUiAccess,      //+
    UacMethodMsSettings,    //+
    UacMethodTyranid,       //+
    UacMethodTokenMod,      //+
    UacMethodJunction,      //+
    UacMethodSXSDccw,       //+
    UacMethodHakril,        //+
    UacMethodCorProfiler,   //+
    UacMethodCOMHandlers,   //+
    UacMethodCMLuaUtil,     //+
    UacMethodMax
} UCM_METHOD;

#define UCM_DISPATCH_ENTRY_MAX UacMethodMax

typedef struct _UCM_METHOD_AVAILABILITY {
    ULONG MinumumWindowsBuildRequired;             //if the current build less this value this method is not working here
    ULONG MinimumExpectedFixedWindowsBuild;        //if the current build equal or greater this value this method is not working here or fixed
} UCM_METHOD_AVAILABILITY;

typedef BOOL(CALLBACK *PUCM_API_ROUTINE)(
    UCM_METHOD Method,
    _Inout_opt_ PVOID ExtraContext,
    _In_opt_ PVOID PayloadCode,
    _In_opt_ ULONG PayloadSize
    );

#define UCM_API(n) BOOL CALLBACK n(     \
    _In_ UCM_METHOD Method,             \
    _Inout_opt_ PVOID ExtraContext,     \
    _In_opt_ PVOID PayloadCode,         \
    _In_opt_ ULONG PayloadSize)

typedef struct _UCM_API_DISPATCH_ENTRY {
    PUCM_API_ROUTINE Routine;               //method to execute
    PVOID ExtraContext;                     //unused, future use
    UCM_METHOD_AVAILABILITY Availability;   //min and max supported Windows builds
    ULONG PayloadResourceId;                //which payload dll must be used
    BOOL Win32OrWow64Required;              
    BOOL DisallowWow64;                     
    BOOL SetParametersInRegistry;           //need shared parameters to be set in the registry
} UCM_API_DISPATCH_ENTRY, *PUCM_API_DISPATCH_ENTRY;

#include "api0cradle.h"
#include "apphelp.h"
#include "b33f.h"
#include "carberp.h"
#include "comet.h"
#include "comfileop.h"
#include "enigma0x3.h"
#include "explife.h"
#include "gootkit.h"
#include "hakril.h"
#include "hybrids.h"
#include "pitou.h"
#include "sandworm.h"
#include "simda.h"
#include "sirefef.h"
#include "wusa.h"
#include "tests\test.h"
#include "tyranid.h"

BOOL MethodsManagerCall(
    _In_ UCM_METHOD Method);
