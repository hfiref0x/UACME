/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       ATLDLL.H
*
*  VERSION:     3.64
*
*  DATE:        04 Feb 2023
*
*  ATL forwarded import.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#pragma comment(linker, " /EXPORT:AtlAdvise=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAdvise,@10")
#pragma comment(linker, " /EXPORT:AtlAxAttachControl=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxAttachControl,@41")
#pragma comment(linker, " /EXPORT:AtlAxCreateControl=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxCreateControl,@39")
#pragma comment(linker, " /EXPORT:AtlAxCreateControlEx=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxCreateControlEx,@40")
#pragma comment(linker, " /EXPORT:AtlAxCreateDialogA=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxCreateDialogA,@38")
#pragma comment(linker, " /EXPORT:AtlAxCreateDialogW=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxCreateDialogW,@37")
#pragma comment(linker, " /EXPORT:AtlAxDialogBoxA=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxDialogBoxA,@36")
#pragma comment(linker, " /EXPORT:AtlAxDialogBoxW=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxDialogBoxW,@35")
#pragma comment(linker, " /EXPORT:AtlAxGetControl=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxGetControl,@47")
#pragma comment(linker, " /EXPORT:AtlAxGetHost=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxGetHost,@48")
#pragma comment(linker, " /EXPORT:AtlAxWinInit=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlAxWinInit,@42")
#pragma comment(linker, " /EXPORT:AtlComPtrAssign=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlComPtrAssign,@30")
#pragma comment(linker, " /EXPORT:AtlComQIPtrAssign=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlComQIPtrAssign,@31")
#pragma comment(linker, " /EXPORT:AtlCreateTargetDC=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlCreateTargetDC,@26")
#pragma comment(linker, " /EXPORT:AtlDevModeW2A=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlDevModeW2A,@29")
#pragma comment(linker, " /EXPORT:AtlFreeMarshalStream=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlFreeMarshalStream,@12")
#pragma comment(linker, " /EXPORT:AtlGetObjectSourceInterface=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlGetObjectSourceInterface,@54")
#pragma comment(linker, " /EXPORT:AtlGetVersion=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlGetVersion,@34")
#pragma comment(linker, " /EXPORT:AtlHiMetricToPixel=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlHiMetricToPixel,@27")
#pragma comment(linker, " /EXPORT:AtlIPersistPropertyBag_Load=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlIPersistPropertyBag_Load,@52")
#pragma comment(linker, " /EXPORT:AtlIPersistPropertyBag_Save=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlIPersistPropertyBag_Save,@53")
#pragma comment(linker, " /EXPORT:AtlIPersistStreamInit_GetSizeMax=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlIPersistStreamInit_GetSizeMax,@60")
#pragma comment(linker, " /EXPORT:AtlIPersistStreamInit_Load=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlIPersistStreamInit_Load,@50")
#pragma comment(linker, " /EXPORT:AtlIPersistStreamInit_Save=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlIPersistStreamInit_Save,@51")
#pragma comment(linker, " /EXPORT:AtlInternalQueryInterface=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlInternalQueryInterface,@32")
#pragma comment(linker, " /EXPORT:AtlMarshalPtrInProc=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlMarshalPtrInProc,@13")
#pragma comment(linker, " /EXPORT:AtlModuleAddCreateWndData=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleAddCreateWndData,@43")
#pragma comment(linker, " /EXPORT:AtlModuleAddTermFunc=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleAddTermFunc,@58")
#pragma comment(linker, " /EXPORT:AtlModuleExtractCreateWndData=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleExtractCreateWndData,@44")
#pragma comment(linker, " /EXPORT:AtlModuleGetClassObject=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleGetClassObject,@15")
#pragma comment(linker, " /EXPORT:AtlModuleInit=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleInit,@16")
#pragma comment(linker, " /EXPORT:AtlModuleLoadTypeLib=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleLoadTypeLib,@56")
#pragma comment(linker, " /EXPORT:AtlModuleRegisterClassObjects=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleRegisterClassObjects,@17")
#pragma comment(linker, " /EXPORT:AtlModuleRegisterServer=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleRegisterServer,@18")
#pragma comment(linker, " /EXPORT:AtlModuleRegisterTypeLib=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleRegisterTypeLib,@19")
#pragma comment(linker, " /EXPORT:AtlModuleRegisterWndClassInfoA=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleRegisterWndClassInfoA,@46")
#pragma comment(linker, " /EXPORT:AtlModuleRegisterWndClassInfoW=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleRegisterWndClassInfoW,@45")
#pragma comment(linker, " /EXPORT:AtlModuleRevokeClassObjects=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleRevokeClassObjects,@20")
#pragma comment(linker, " /EXPORT:AtlModuleTerm=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleTerm,@21")
#pragma comment(linker, " /EXPORT:AtlModuleUnRegisterTypeLib=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleUnRegisterTypeLib,@55")
#pragma comment(linker, " /EXPORT:AtlModuleUnregisterServer=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleUnregisterServer,@22")
#pragma comment(linker, " /EXPORT:AtlModuleUnregisterServerEx=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleUnregisterServerEx,@57")
#pragma comment(linker, " /EXPORT:AtlModuleUpdateRegistryFromResourceD=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlModuleUpdateRegistryFromResourceD,@23")
#pragma comment(linker, " /EXPORT:AtlPixelToHiMetric=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlPixelToHiMetric,@28")
#pragma comment(linker, " /EXPORT:AtlRegisterClassCategoriesHelper=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlRegisterClassCategoriesHelper,@49")
#pragma comment(linker, " /EXPORT:AtlSetErrorInfo=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlSetErrorInfo,@25")
#pragma comment(linker, " /EXPORT:AtlSetErrorInfo2=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlSetErrorInfo2,@59")
#pragma comment(linker, " /EXPORT:AtlUnadvise=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlUnadvise,@11")
#pragma comment(linker, " /EXPORT:AtlUnmarshalPtr=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlUnmarshalPtr,@14")
#pragma comment(linker, " /EXPORT:AtlWaitWithMessageLoop=\\\\?\\globalroot\\systemroot\\system32\\atl.AtlWaitWithMessageLoop,@24")
