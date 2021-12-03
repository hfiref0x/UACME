/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       METHODS.H
*
*  VERSION:     3.58
*
*  DATE:        21 Nov 2021
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
    UacMethodTest = 0,          //+
    UacMethodSysprep1 = 1,      
    UacMethodSysprep2,          
    UacMethodOobe,              
    UacMethodRedirectExe,       
    UacMethodSimda,             
    UacMethodCarberp1,          
    UacMethodCarberp2,          
    UacMethodTilon,             
    UacMethodAVrf,              
    UacMethodWinsat,            
    UacMethodShimPatch,         
    UacMethodSysprep3,          
    UacMethodMMC1,              
    UacMethodSirefef,           
    UacMethodGeneric,           
    UacMethodGWX,               
    UacMethodSysprep4,          
    UacMethodManifest,          
    UacMethodInetMgr,           
    UacMethodMMC2,              
    UacMethodSXS,               
    UacMethodSXSConsent,        //+
    UacMethodDISM,              //+
    UacMethodComet,             
    UacMethodEnigma0x3,         
    UacMethodEnigma0x3_2,       
    UacMethodExpLife,           
    UacMethodSandworm,          
    UacMethodEnigma0x3_3,       
    UacMethodWow64Logger,       //+
    UacMethodEnigma0x3_4,       
    UacMethodUiAccess,          //+
    UacMethodMsSettings,        //+
    UacMethodDiskSilentCleanup, //+
    UacMethodTokenMod,          
    UacMethodJunction,          //+
    UacMethodSXSDccw,           //+
    UacMethodHakril,            //+
    UacMethodCorProfiler,       //+
    UacMethodCOMHandlers,       
    UacMethodCMLuaUtil,         //+
    UacMethodFwCplLua,          
    UacMethodDccwCOM,           //+
    UacMethodVolatileEnv,       
    UacMethodSluiHijack,        
    UacMethodBitlockerRC,       
    UacMethodCOMHandlers2,      
    UacMethodSPPLUAObject,      
    UacMethodCreateNewLink,     
    UacMethodDateTimeWriter,    
    UacMethodAcCplAdmin,        
    UacMethodDirectoryMock,     //+
    UacMethodShellSdclt,        //+
    UacMethodEgre55,            
    UacMethodTokenModUiAccess,  //+
    UacMethodShellWSReset,      
    UacMethodSysprep5,          
    UacMethodEditionUpgradeMgr, //+
    UacMethodDebugObject,       //+
    UacMethodGlupteba,          
    UacMethodShellChangePk,     //+
    UacMethodMsSettings2,       //+
    UacMethodNICPoison,         //+
    UacMethodIeAddOnInstall,    //+
    UacMethodWscActionProtocol, //+
    UacMethodFwCplLua2,         //+
    UacMethodMsSettingsProtocol,//+
    UacMethodMsStoreProtocol,   //+
    UacMethodPca,               //+
    UacMethodCurVer,            //+
    UacMethodNICPoison2,        //+
    UacMethodMax,
    UacMethodInvalid = 0xabcdef
} UCM_METHOD;

#define UCM_DISPATCH_ENTRY_MAX UacMethodMax

typedef struct _UCM_METHOD_AVAILABILITY {
    ULONG MinumumWindowsBuildRequired;             //if the current build less this value this method is not working here
    ULONG MinimumExpectedFixedWindowsBuild;        //if the current build equal or greater this value this method is not working here or fixed
} UCM_METHOD_AVAILABILITY;

typedef struct tagUCM_PARAMS_BLOCK {
    UCM_METHOD Method;
    PVOID PayloadCode;
    ULONG PayloadSize;
} UCM_PARAMS_BLOCK, *PUCM_PARAMS_BLOCK;

typedef NTSTATUS(CALLBACK *PUCM_API_ROUTINE)(
    _In_ PUCM_PARAMS_BLOCK Parameter
    );
                  
#define UCM_API(n) NTSTATUS CALLBACK n(     \
    _In_ PUCM_PARAMS_BLOCK Parameter)  

typedef struct _UCM_API_DISPATCH_ENTRY {
    PUCM_API_ROUTINE Routine;               //method to execute
    UCM_METHOD_AVAILABILITY Availability;   //min and max supported Windows builds
    ULONG PayloadResourceId;                //which payload dll must be used
    BOOL Win32OrWow64Required;
    BOOL DisallowWow64;
    BOOL SetParameters;                     //need shared parameters to be set
} UCM_API_DISPATCH_ENTRY, *PUCM_API_DISPATCH_ENTRY;

#include "elvint.h"
#include "api0cradle.h"
#include "azagarampur.h"
#include "comsup.h"
#include "dwells.h"
#include "shellsup.h"
#include "hakril.h"
#include "hybrids.h"
#include "rinn.h"
#include "wusa.h"
#include "tests\test.h"
#include "tyranid.h"

NTSTATUS MethodsManagerCall(
    _In_ UCM_METHOD Method);
