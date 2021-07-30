/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2021
*
*  TITLE:       AIC.C
*
*  VERSION:     3.56
*
*  DATE:        30 July 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#ifdef _WIN64
#include "appinfo/x64/appinfo64.h"
#else
#include "appinfo/x86-32/appinfo32.h"
#endif

/*
* AicpAsyncInitializeHandle
*
* Purpose:
*
* Init RPC_ASYNC_STATE structure.
*
*/
RPC_STATUS AicpAsyncInitializeHandle(
    _Inout_ RPC_ASYNC_STATE* AsyncState)
{
    RPC_STATUS status;

    status = RpcAsyncInitializeHandle(AsyncState, sizeof(RPC_ASYNC_STATE));
    if (status == RPC_S_OK) {
        AsyncState->NotificationType = RpcNotificationTypeEvent;
        AsyncState->u.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (AsyncState->u.hEvent == NULL)
            status = GetLastError();
    }

    return status;
}

/*
* AicpAsyncCloseHandle
*
* Purpose:
*
* Close RPC_ASYNC_STATE notification event.
*
*/
VOID AicpAsyncCloseHandle(
    _Inout_ RPC_ASYNC_STATE* AsyncState)
{
    if (AsyncState->u.hEvent) {
        CloseHandle(AsyncState->u.hEvent);
        AsyncState->u.hEvent = NULL;
    }
}

/*
* AicLaunchAdminProcess
*
* Purpose:
*
* Create process by talking to APPINFO via RPC.
*
*/
BOOLEAN AicLaunchAdminProcess(
    _In_opt_ LPWSTR ExecutablePath,
    _In_opt_ LPWSTR CommandLine,
    _In_ DWORD StartFlags,
    _In_ DWORD CreationFlags,
    _In_ LPWSTR CurrentDirectory,
    _In_ LPWSTR WindowStation,
    _In_opt_ HWND hWnd,
    _In_ DWORD Timeout,
    _In_ DWORD ShowFlags,
    _Out_ PROCESS_INFORMATION* ProcessInformation
)
{
    BOOLEAN bResult = FALSE;
    RPC_BINDING_HANDLE rpcHandle;
    RPC_ASYNC_STATE asyncState;
    APP_PROCESS_INFORMATION procInfo;
    APP_STARTUP_INFO appStartup;
    RPC_STATUS status;
    VOID* Reply = NULL;

    LONG elevationType = 0;

    if (ProcessInformation) {
        ProcessInformation->hProcess = NULL;
        ProcessInformation->hThread = NULL;
        ProcessInformation->dwProcessId = 0;
        ProcessInformation->dwThreadId = 0;
    }

    RtlSecureZeroMemory(&procInfo, sizeof(procInfo));
    RtlSecureZeroMemory(&appStartup, sizeof(appStartup));

    appStartup.dwFlags = STARTF_USESHOWWINDOW;
    appStartup.wShowWindow = (SHORT)ShowFlags;

    RtlSecureZeroMemory(&asyncState, sizeof(RPC_ASYNC_STATE));

    if ((supCreateBindingHandle(APPINFO_RPC, &rpcHandle) == RPC_S_OK) &&
        (AicpAsyncInitializeHandle(&asyncState) == RPC_S_OK))
    {

        __try {

            RAiLaunchAdminProcess(&asyncState,
                rpcHandle,
                ExecutablePath,
                CommandLine,
                StartFlags,
                CreationFlags,
                CurrentDirectory,
                WindowStation,
                &appStartup,
                (ULONG_PTR)hWnd,
                Timeout,
                &procInfo,
                &elevationType);

            if (WaitForSingleObject(asyncState.u.hEvent, INFINITE) == WAIT_FAILED)
            {
                RpcRaiseException(-1);
            }

            status = RpcAsyncCompleteCall(&asyncState, &Reply);
            if (status == 0 && Reply == NULL) {

                if (ProcessInformation) {
                    ProcessInformation->hProcess = (HANDLE)procInfo.ProcessHandle;
                    ProcessInformation->hThread = (HANDLE)procInfo.ThreadHandle;
                    ProcessInformation->dwProcessId = (DWORD)procInfo.ProcessId;
                    ProcessInformation->dwThreadId = (DWORD)procInfo.ThreadId;
                }

                bResult = TRUE;

            }

            AicpAsyncCloseHandle(&asyncState);

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SetLastError(RpcExceptionCode());
            return FALSE;
        }

        RpcBindingFree(&rpcHandle);
    }

    return bResult;
}
