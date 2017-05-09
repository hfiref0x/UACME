/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.25
*
*  DATE:        07 May 2017
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
HANDLE  g_ConOut = NULL;
HANDLE  g_LogFile = INVALID_HANDLE_VALUE;

/*
* AppInfoDataOutputCallback
*
* Purpose:
*
* Output callback for AppInfo scan.
*
*/
VOID AppInfoDataOutputCallback(
    UAC_AI_DATA *Data
    )
{
    LPWSTR lpLog = NULL, Text = NULL;
    SIZE_T sz = 0;

    if (Data == NULL)
        return;

    sz = (_strlen(Data->Name) * sizeof(WCHAR)) + MAX_PATH;
    lpLog = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
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

        cuiPrintText(g_ConOut, lpLog, TRUE, TRUE);
        HeapFree(GetProcessHeap(), 0, lpLog);
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
    UAC_BASIC_DATA *Data
    )
{
    LPWSTR lpLog = NULL;
    SIZE_T sz = 0;

    if (Data == NULL)
        return;

    sz = (_strlen(Data->Name) * sizeof(WCHAR)) + MAX_PATH;
    lpLog = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
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
        cuiPrintText(g_ConOut, lpLog, TRUE, TRUE);
        HeapFree(GetProcessHeap(), 0, lpLog);
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
    UAC_REGISTRY_DATA *Data
    )
{
    UAC_INTERFACE_DATA *InterfaceData;
    LPOLESTR OutputString = NULL;

    if (Data == NULL)
        return;


    if (Data->DataType == UacCOMDataCommonType) {
        //
        // Output current registry key to show that we are alive.
        //
        LoggerWrite(g_LogFile, Data->Name, TRUE);
        cuiPrintText(g_ConOut, Data->Key, TRUE, TRUE);
        LoggerWrite(g_LogFile, Data->AppId, TRUE);
        LoggerWrite(g_LogFile, Data->LocalizedString, TRUE);
        LoggerWrite(g_LogFile, Data->Key, TRUE);
        LoggerWrite(g_LogFile, TEXT("\n"), TRUE);
    }

    if (Data->DataType == UacCOMDataInterfaceType) {

        InterfaceData = (UAC_INTERFACE_DATA*)Data;

        LoggerWrite(g_LogFile, InterfaceData->Name, TRUE);
        cuiPrintText(g_ConOut, InterfaceData->Name, TRUE, TRUE);

        if (StringFromCLSID(&InterfaceData->Clsid, &OutputString) == S_OK) {
            LoggerWrite(g_LogFile, TEXT("CLSID"), TRUE);
            LoggerWrite(g_LogFile, OutputString, TRUE);
            cuiPrintText(g_ConOut, OutputString, TRUE, TRUE);
            CoTaskMemFree(OutputString);
        }
        if (StringFromIID(&InterfaceData->IID, &OutputString) == S_OK) {
            LoggerWrite(g_LogFile, TEXT("IID"), TRUE);
            LoggerWrite(g_LogFile, OutputString, TRUE);
            cuiPrintText(g_ConOut, OutputString, TRUE, TRUE);
            CoTaskMemFree(OutputString);
        }
        LoggerWrite(g_LogFile, TEXT("\n"), TRUE);
        cuiPrintText(g_ConOut, TEXT("\n"), TRUE, TRUE);
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
    UAC_FUSION_DATA *Data
    )
{
    LPWSTR lpText;
    LPWSTR lpLog = NULL;
    SIZE_T sz = 0;
    UAC_FUSION_DATA_DLL *Dll;

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
        cuiPrintText(g_ConOut, Data->Name, TRUE, TRUE);

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
        sz = _strlen(Dll->DllName) + _strlen(Dll->FileName) + MAX_PATH;
        lpLog = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz * sizeof(WCHAR));
        if (lpLog) {
            _strcpy(lpLog, TEXT("DllRedirection: "));
            _strcat(lpLog, Dll->FileName);
            _strcat(lpLog, TEXT(" -> "));
            _strcat(lpLog, Dll->DllName);
            LoggerWrite(g_LogFile, lpLog, TRUE);
            HeapFree(GetProcessHeap(), 0, lpLog);
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
    cuiPrintText(g_ConOut, TEXT("\n[UacView] Basic UAC settings\n"), TRUE, TRUE);
    ScanBasicUacData((BASICDATACALLBACK)BasicDataOutputCallback);
    LoggerWrite(g_LogFile, TEXT("================================================\n"), TRUE);
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
    cuiPrintText(g_ConOut, TEXT("\n[UacView] Autoelevated COM objects\n"), TRUE, TRUE);
    CoListInformation((REGCALLBACK)RegistryOutputCallback);
    LoggerWrite(g_LogFile, TEXT("================================================\n"), TRUE);
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
    cuiPrintText(g_ConOut, TEXT("\n[UacView] Autoelevated applications in Windows directory\n"), TRUE, TRUE);
    FusionScanDirectory(USER_SHARED_DATA->NtSystemRoot, (FUSIONCALLBACK)FusionOutputCallback);
    LoggerWrite(g_LogFile, TEXT("================================================\n"), TRUE);

    //scan program files next
    cuiPrintText(g_ConOut, TEXT("\n[UacView] Autoelevated applications in Program Files directory\n"), TRUE, TRUE);
    RtlSecureZeroMemory(szPath, sizeof(szPath));
    if (SUCCEEDED(SHGetFolderPath(NULL,
        CSIDL_PROGRAM_FILES,
        NULL,
        SHGFP_TYPE_CURRENT,
        (LPWSTR)&szPath)))
    {
        FusionScanDirectory(szPath, (FUSIONCALLBACK)FusionOutputCallback);
    }
    LoggerWrite(g_LogFile, TEXT("================================================\n"), TRUE);
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

    cuiPrintText(g_ConOut, TEXT("\n[UacView] Appinfo data\n"), TRUE, TRUE);

    _strcpy(szFileName, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szFileName, TEXT("\\system32\\appinfo.dll"));

    ScanAppInfo(szFileName, (APPINFODATACALLBACK)AppInfoDataOutputCallback);

    LoggerWrite(g_LogFile, TEXT("================================================\n"), TRUE);
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
    WCHAR szBuffer[MAX_PATH];

    __security_init_cookie();

    g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_ConOut != INVALID_HANDLE_VALUE) {

        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);

        cuiPrintText(g_ConOut, T_PROGRAM_TITLE, TRUE, TRUE);

        RtlGetNtVersionNumbers(NULL, NULL, (ULONG*)&g_NtBuildNumber);
        g_NtBuildNumber &= 0x00003fff;
        if (g_NtBuildNumber < YUUBARI_MIN_SUPPORTED_NT_BUILD) {
            cuiPrintText(g_ConOut, TEXT("[UacView] Unsupported Windows version."), TRUE, TRUE);
            ExitProcess(0);
        }
        if (g_NtBuildNumber > YUUBARI_MAX_SUPPORTED_NT_BUILD) {
            cuiPrintText(g_ConOut, TEXT("\n[UacView] Not all features available for this build\n"), TRUE, TRUE);
        }

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        GetCommandLineParam(GetCommandLine(), 1, (LPWSTR)&szBuffer, MAX_PATH * sizeof(WCHAR), &l);
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
            cuiPrintText(g_ConOut, TEXT("Output will be logged to file"), TRUE, TRUE);
            cuiPrintText(g_ConOut, szBuffer, TRUE, TRUE);
        }

#ifndef _DEBUG
        ListBasicSettings();
        ListCOMFromRegistry();
        ListAppInfo();
#endif
        ListFusion();

        if (g_LogFile != INVALID_HANDLE_VALUE)
            CloseHandle(g_LogFile);

    }
    ExitProcess(0);
}
