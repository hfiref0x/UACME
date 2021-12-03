/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.52
*
*  DATE:        23 Nov 2021
*
*  Program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "Shlobj.h"

BOOL    g_VerboseOutput = FALSE;
ULONG   g_NtBuildNumber = 0;
HANDLE  g_LogFile = INVALID_HANDLE_VALUE;

#ifdef _DEBUG
ULONG   g_TestAppInfoBuildNumber = 0;
#endif

VOID LoggerWriteHeader(
    _In_ LPWSTR lpHeaderData)
{
    LoggerWrite(g_LogFile, T_SPLIT, FALSE);
    LoggerWrite(g_LogFile, lpHeaderData, FALSE);
    LoggerWrite(g_LogFile, T_SPLIT, TRUE);
}

/*
* AppInfoDataOutputCallback
*
* Purpose:
*
* Output callback for AppInfo scan.
*
*/
VOID AppInfoDataOutputCallback(
    _In_ UAC_AI_DATA* Data
)
{
    LPWSTR lpLog = NULL, Text = NULL;
    SIZE_T sz = 0;

    if (Data == NULL)
        return;

    sz = (_strlen(Data->Name) * sizeof(WCHAR)) + MAX_PATH;
    lpLog = (LPWSTR)supHeapAlloc(sz);
    if (lpLog) {
        switch (Data->Type) {
        case AiSnapinFile:
            Text = TEXT("SnapinFile: ");
            break;
        case AiManagementConsole:
            Text = TEXT("ManagementConsole: ");
            break;
        case AiAutoApproveEXE:
            Text = TEXT("AutoApproveEXE: ");
            break;
        case AiIncludedPFDirs:
            Text = TEXT("IncludedPFDir: ");
            break;
        case AiIncludedSystemDirs:
            Text = TEXT("IncludedSystemDir: ");
            break;
        case AiExemptedAutoApproveExes:
            Text = TEXT("ExemptedAutoApproveExe: ");
            break;
        case AilpIncludedWindowsDirs:
            Text = TEXT("IncludedWindowsDirs: ");
            break;
        case AiExcludedWindowsDirs:
            Text = TEXT("ExcludedWindowsDir: ");
            break;
        default:
            Text = TEXT("Unknown ");
            break;
        }
        _strcpy(lpLog, Text);
        _strcat(lpLog, Data->Name);
        LoggerWrite(g_LogFile, lpLog, TRUE);

        cuiPrintText(lpLog, TRUE);
        supHeapFree(lpLog);
    }
}

/*
* BasicDataOutputCallback
*
* Purpose:
*
* Output callback for basic UAC settings scan.
*
*/
VOID WINAPI BasicDataOutputCallback(
    _In_ UAC_BASIC_DATA* Data
)
{
    LPWSTR lpLog = NULL;
    SIZE_T sz = 0;

    if (Data == NULL)
        return;

    sz = (_strlen(Data->Name) * sizeof(WCHAR)) + MAX_PATH;
    lpLog = (LPWSTR)supHeapAlloc(sz);
    if (lpLog) {
        _strcpy(lpLog, Data->Name);
        _strcat(lpLog, TEXT("="));
        if (Data->IsValueBool) {
            if (Data->Value == 0)
                _strcat(lpLog, TEXT("Disabled"));
            else
                _strcat(lpLog, TEXT("Enabled"));
        }
        else {
            ultostr(Data->Value, _strend(lpLog));
        }
        LoggerWrite(g_LogFile, lpLog, TRUE);
        cuiPrintText(lpLog, TRUE);
        supHeapFree(lpLog);
    }
}

/*
* RegistryOutputCallback
*
* Purpose:
*
* Output callback for registry autoelevated objects scan.
*
*/
VOID WINAPI RegistryOutputCallback(
    _In_ UAC_REGISTRY_DATA* Data
)
{
    UAC_INTERFACE_DATA* InterfaceData;
    LPOLESTR OutputString = NULL;

    if (Data == NULL)
        return;

    if (Data->DataType == UacCOMDataVirtualFactory) {
        LoggerWrite(g_LogFile, TEXT("VirtualFactory"), TRUE);
    }
    if ((Data->DataType == UacCOMDataCommonType) ||
        (Data->DataType == UacCOMDataVirtualFactory))
    {
        //
        // Output current registry key to show that we are alive.
        //
        LoggerWrite(g_LogFile, Data->Name, TRUE);
        cuiPrintText(Data->Key, TRUE);
        LoggerWrite(g_LogFile, Data->AppId, TRUE);
        LoggerWrite(g_LogFile, Data->LocalizedString, TRUE);
        LoggerWrite(g_LogFile, Data->Key, TRUE);
        LoggerWrite(g_LogFile, TEXT("\r\n"), TRUE);
    }

    if (Data->DataType == UacCOMDataInterfaceTypeVF) {
        LoggerWrite(g_LogFile, TEXT("VirtualFactory Item"), TRUE);
    }

    if ((Data->DataType == UacCOMDataInterfaceType) ||
        (Data->DataType == UacCOMDataInterfaceTypeVF))
    {
        InterfaceData = (UAC_INTERFACE_DATA*)(PVOID)Data;

        LoggerWrite(g_LogFile, InterfaceData->Name, TRUE);
        cuiPrintText(InterfaceData->Name, TRUE);

        if (StringFromCLSID(&InterfaceData->Clsid, &OutputString) == S_OK) {
            LoggerWrite(g_LogFile, TEXT("CLSID"), TRUE);
            LoggerWrite(g_LogFile, OutputString, TRUE);
            cuiPrintText(OutputString, TRUE);
            CoTaskMemFree(OutputString);
        }
        if (StringFromIID(&InterfaceData->IID, &OutputString) == S_OK) {
            LoggerWrite(g_LogFile, TEXT("IID"), TRUE);
            LoggerWrite(g_LogFile, OutputString, TRUE);
            cuiPrintText(OutputString, TRUE);
            CoTaskMemFree(OutputString);
        }
        LoggerWrite(g_LogFile, TEXT("\r\n"), TRUE);
        cuiPrintText(TEXT("\r\n"), TRUE);
    }
}

/*
* FusionOutputCallback
*
* Purpose:
*
* Output callback for autoelevated applications scan.
*
*/
VOID WINAPI FusionOutputCallback(
    _In_ UAC_FUSION_DATA* Data
)
{
    LPWSTR lpText;
    LPWSTR lpLog = NULL;
    SIZE_T sz = 0;
    UAC_FUSION_DATA_DLL* Dll;

    if (Data == NULL)
        return;

    if (Data->DataType == UacFusionDataCommonType) {

        //
        // Display only binaries with autoelevation flags if not in verbose output
        //
        if ((Data->AutoElevateState == AutoElevateUnspecified) && (g_VerboseOutput == FALSE))
            return;

        //
        // Output current filename
        //
        LoggerWrite(g_LogFile, TEXT("\r\n"), FALSE);
        LoggerWrite(g_LogFile, Data->Name, TRUE);
        cuiPrintText(Data->Name, TRUE);

        //
        // If application has autoElevate attribute, report full info
        //
        if (Data->IsFusion) {
            switch (Data->RunLevel.RunLevel) {
            case ACTCTX_RUN_LEVEL_AS_INVOKER:
                lpText = TEXT("asInvoker");
                break;
            case ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE:
                lpText = TEXT("highestAvailable");
                break;
            case ACTCTX_RUN_LEVEL_REQUIRE_ADMIN:
                lpText = TEXT("requireAdministrator");
                break;
            case ACTCTX_RUN_LEVEL_UNSPECIFIED:
            default:
                lpText = TEXT("unspecified");
                break;
            }
            //RequestedExecutionLevel 
            LoggerWrite(g_LogFile, lpText, TRUE);

            if (Data->RunLevel.UiAccess > 0) {
                lpText = TEXT("uiAccess=TRUE");
            }
            else {
                lpText = TEXT("uiAccess=FALSE");
            }
            //UIAccess state
            LoggerWrite(g_LogFile, lpText, TRUE);

            //autoElevate state
            if (Data->AutoElevateState != AutoElevateUnspecified) {
                switch (Data->AutoElevateState) {
                case AutoElevateEnabled:
                    lpText = TEXT("autoElevate=TRUE");
                    break;
                case AutoElevateDisabled:
                    lpText = TEXT("autoElevate=FALSE");
                    break;
                case AutoElevateExempted:
                    lpText = TEXT("autoElevate=Exempted");
                    break;
                default:
                    break;
                }
                LoggerWrite(g_LogFile, lpText, TRUE);
            }
        }
        else {
            // no embedded manifest
            lpText = TEXT("Binary without embedded manifest");
            LoggerWrite(g_LogFile, lpText, TRUE);
            if (Data->IsOSBinary) {
                if (Data->IsSignatureValidOrTrusted == FALSE) {
                    lpText = TEXT("Warning: signature not valid or trusted");
                    LoggerWrite(g_LogFile, lpText, TRUE);
                }
                else {
                    lpText = TEXT("OS binary with valid digital signature");
                    LoggerWrite(g_LogFile, lpText, TRUE);
                }
            }
        }
        if (Data->IsDotNet) {
            lpText = TEXT("DotNet");
            LoggerWrite(g_LogFile, lpText, TRUE);
        }
    }
    if (Data->DataType == UacFusionDataRedirectedDllType) {
        Dll = (UAC_FUSION_DATA_DLL*)Data;
        sz = (_strlen(Dll->DllName) + _strlen(Dll->FileName) + MAX_PATH) * sizeof(WCHAR);
        lpLog = (LPWSTR)supHeapAlloc(sz);
        if (lpLog) {
            _strcpy(lpLog, TEXT("DllRedirection: "));
            _strcat(lpLog, Dll->FileName);
            _strcat(lpLog, TEXT(" -> "));
            _strcat(lpLog, Dll->DllName);
            LoggerWrite(g_LogFile, lpLog, TRUE);
            supHeapFree(lpLog);
        }
    }
}

/*
* ListBasicSettings
*
* Purpose:
*
* Scan basic UAC settings.
*
*/
VOID ListBasicSettings(
    VOID
)
{
    cuiPrintText(T_BASIC_HEAD, TRUE);
    LoggerWriteHeader(T_BASIC_HEAD);
    ScanBasicUacData((OUTPUTCALLBACK)BasicDataOutputCallback);
}

/*
* ListCOMFromRegistry
*
* Purpose:
*
* Scan HKEY_CLASSES_ROOT for autoelevated COM objects.
*
*/
VOID ListCOMFromRegistry(
    VOID
)
{
    INTERFACE_INFO_LIST InterfaceList;

    if (CoInitializeEx(NULL, COINIT_APARTMENTTHREADED) != S_OK)
        return;

    RtlSecureZeroMemory(&InterfaceList, sizeof(InterfaceList));

    __try {

        if (!CoEnumInterfaces(&InterfaceList))
            __leave;

        cuiPrintText(T_COM_HEAD, TRUE);
        LoggerWriteHeader(T_COM_HEAD);
        CoListInformation((OUTPUTCALLBACK)RegistryOutputCallback, &InterfaceList);


        //
        // AutoApproval COM list added since RS1.
        //
        if (g_NtBuildNumber >= NT_WIN10_REDSTONE1) {
            cuiPrintText(T_COM_APPROVE_HEAD, TRUE);
            LoggerWriteHeader(T_COM_APPROVE_HEAD);
            CoScanAutoApprovalList((OUTPUTCALLBACK)RegistryOutputCallback, &InterfaceList);
        }
        cuiPrintText(T_BROKER_APPROVE_HEAD, TRUE);
        LoggerWriteHeader(T_BROKER_APPROVE_HEAD);
        CoScanBrokerApprovalList((OUTPUTCALLBACK)RegistryOutputCallback, &InterfaceList);
    }
    __finally {
        CoUninitialize();
        if (InterfaceList.List)
            supHeapFree(InterfaceList.List);
    }
}

/*
* ListFusion
*
* Purpose:
*
* Scan Windows directory for autoelevated apps.
*
*/
VOID ListFusion(
    VOID
)
{
    HMODULE hModule;
    WCHAR   szPath[MAX_PATH * 2];

    RtlSecureZeroMemory(szPath, sizeof(szPath));
    _strcpy(szPath, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szPath, TEXT("\\system32\\wintrust.dll"));

    hModule = LoadLibraryEx(szPath, NULL, 0);
    if (hModule != NULL) {
        WTGetSignatureInfo = (ptrWTGetSignatureInfo)GetProcAddress(hModule, "WTGetSignatureInfo");
    }

    //scan Windows first
    cuiPrintText(T_WINFILES_HEAD, TRUE);
    LoggerWriteHeader(T_WINFILES_HEAD);

#ifdef _DEBUG
    FusionScanDirectory(L"C:\\Windows\\WinSxS", (OUTPUTCALLBACK)FusionOutputCallback);
    return;
#else
    FusionScanDirectory(USER_SHARED_DATA->NtSystemRoot, (OUTPUTCALLBACK)FusionOutputCallback);

    //scan program files next
    cuiPrintText(T_PFDIRFILES_HEAD, TRUE);
    LoggerWriteHeader(T_PFDIRFILES_HEAD);

    RtlSecureZeroMemory(szPath, sizeof(szPath));
    if (SUCCEEDED(SHGetFolderPath(NULL,
        CSIDL_PROGRAM_FILES,
        NULL,
        SHGFP_TYPE_CURRENT,
        (LPWSTR)&szPath)))
    {
        FusionScanDirectory(szPath, (OUTPUTCALLBACK)FusionOutputCallback);
    }
#endif
}

/*
* ListAppInfo
*
* Purpose:
*
* Scan memory of appinfo.dll.
*
*/
VOID ListAppInfo(
    VOID
)
{
    WCHAR szFileName[MAX_PATH * 2];

    cuiPrintText(T_APPINFO_HEAD, TRUE);
    LoggerWriteHeader(T_APPINFO_HEAD);

#ifndef _DEBUG
    _strcpy(szFileName, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szFileName, TEXT("\\system32\\appinfo.dll"));
#else
    g_TestAppInfoBuildNumber = 22494;
    _strcpy(szFileName, TEXT("C:\\appinfo\\appinfo_22494.dll"));
#endif
    ScanAppInfo(szFileName, (OUTPUTCALLBACK)AppInfoDataOutputCallback);
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
VOID main()
{
    ULONG l = 0;
    WCHAR szBuffer[MAX_PATH + 1];
    RTL_OSVERSIONINFOW  osv;

    __security_init_cookie();

    HeapSetInformation(GetProcessHeap(), HeapEnableTerminationOnCorruption, NULL, 0);

    cuiInitialize(FALSE, NULL);

    cuiPrintText(T_PROGRAM_TITLE, TRUE);

    RtlSecureZeroMemory(&osv, sizeof(osv));
    osv.dwOSVersionInfoSize = sizeof(osv);
    RtlGetVersion((RTL_OSVERSIONINFOW*)&osv);

    g_NtBuildNumber = osv.dwBuildNumber;

    if (g_NtBuildNumber < YUUBARI_MIN_SUPPORTED_NT_BUILD) {
        cuiPrintText(TEXT("[UacView] Unsupported Windows version."), TRUE);
        ExitProcess(0);
    }
    if (g_NtBuildNumber > YUUBARI_MAX_SUPPORTED_NT_BUILD) {
        cuiPrintText(TEXT("\r\n[UacView] Not all features available for this build\r\n"), TRUE);
    }

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    GetCommandLineParam(GetCommandLine(), 1, (LPWSTR)&szBuffer, MAX_PATH, &l);
    if (_strcmpi(szBuffer, TEXT("/?")) == 0) {
        MessageBox(GetDesktopWindow(), T_HELP, T_PROGRAM_NAME, MB_ICONINFORMATION);
        ExitProcess(0);
    }
    else {
        g_VerboseOutput = (_strcmpi(szBuffer, TEXT("/v")) == 0);
    }

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, TEXT("uac"));
    ultostr(g_NtBuildNumber, _strend(szBuffer));
    _strcat(szBuffer, TEXT(".log"));

    g_LogFile = LoggerCreate(szBuffer);
    if (g_LogFile != INVALID_HANDLE_VALUE) {
        cuiPrintText(TEXT("Output will be logged to the file"), TRUE);
        cuiPrintText(szBuffer, TRUE);
    }

#ifndef _DEBUG
    ListBasicSettings();
    ListCOMFromRegistry();
#endif
    ListFusion();
#ifndef _DEBUG
    ListAppInfo();
#endif
    if (g_LogFile != INVALID_HANDLE_VALUE)
        CloseHandle(g_LogFile);

    ExitProcess(0);
}
