/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.10
*
*  DATE:        21 Feb 2017
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

HANDLE     g_ConOut = NULL;
BOOL       g_ConsoleOutput = FALSE;
HANDLE     g_LogFile = INVALID_HANDLE_VALUE;

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

    sz = (_strlen(Data->Name) + sizeof(WCHAR)) + MAX_PATH;
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

        cuiPrintText(g_ConOut, lpLog, g_ConsoleOutput, TRUE);
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

    sz = (_strlen(Data->Name) + _strlen(Data->Desc) * sizeof(WCHAR)) + MAX_PATH;
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
            if (Data->IsDescUsed) {
                _strcat(lpLog, Data->Desc);
            }
            else {
                ultostr(Data->Value, _strend(lpLog));
            }
        }
        LoggerWrite(g_LogFile, lpLog, TRUE);
        cuiPrintText(g_ConOut, lpLog, g_ConsoleOutput, TRUE);
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
    if (Data == NULL)
        return;

    LoggerWrite(g_LogFile, Data->Name, TRUE);

    //output current registry key to show that we are alive
    cuiPrintText(g_ConOut, Data->Key, g_ConsoleOutput, TRUE);

    LoggerWrite(g_LogFile, Data->AppId, TRUE);
    LoggerWrite(g_LogFile, Data->LocalizedString, TRUE);
    LoggerWrite(g_LogFile, Data->Key, TRUE);
    LoggerWrite(g_LogFile, TEXT("\n"), TRUE);
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

    if (Data == NULL)
        return;

    if (Data->DataType == UacFusionDataCommonType) {

        //FileName
        LoggerWrite(g_LogFile, TEXT("\r\n"), FALSE);
        LoggerWrite(g_LogFile, Data->Name, TRUE);

        // Output current filename, to show that we are alive
        cuiPrintText(g_ConOut, Data->Name, g_ConsoleOutput, TRUE);

        //
        // If application has autoElevate attribute, report full info
        //
        if (Data->IsFusion) {
            switch (Data->RunLevel) {
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
                if (Data->IsSignatureValidOrTrusted != TRUE) {
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
        sz = (_strlen(Data->Name) * sizeof(WCHAR)) + MAX_PATH;
        lpLog = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (lpLog) {
            _strcpy(lpLog, TEXT("DllRedirection: "));
            _strcat(lpLog, Data->Name);
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
    cuiPrintText(g_ConOut, TEXT("\n[UacView] Enumerating basic UAC settings\n"), g_ConsoleOutput, TRUE);
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
    cuiPrintText(g_ConOut, TEXT("\n[UacView] Enumerating registry for autoelevated COM objects\n"), g_ConsoleOutput, TRUE);
    ScanRegistry(HKEY_CLASSES_ROOT, (REGCALLBACK)RegistryOutputCallback);
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
    cuiPrintText(g_ConOut, TEXT("\n[UacView] Enumerating autoelevated applications in Windows directory\n"), g_ConsoleOutput, TRUE);
    FusionScanDirectory(USER_SHARED_DATA->NtSystemRoot, (FUSIONCALLBACK)FusionOutputCallback);
    LoggerWrite(g_LogFile, TEXT("================================================\n"), TRUE);

    //scan program files next
    cuiPrintText(g_ConOut, TEXT("\n[UacView] Enumerating autoelevated applications in Program Files directory\n"), g_ConsoleOutput, TRUE);
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

    cuiPrintText(g_ConOut, TEXT("\n[UacView] Enumerating appinfo data\n"), g_ConsoleOutput, TRUE);

    _strcpy(szFileName, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szFileName, TEXT("\\system32\\appinfo.dll"));

//    _strcpy(szFileName, TEXT("D:\\Dumps\\APPINFO\\14393.dll"));

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
    DWORD l;

    WCHAR szLogFile[MAX_PATH];

    __security_init_cookie();

    g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_ConOut != INVALID_HANDLE_VALUE) {

        g_ConsoleOutput = TRUE;
        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);

        cuiPrintText(g_ConOut, TEXT("[UacView] Tool for gathering information about UAC, v1.1.0 (22/02/2017)\n"), g_ConsoleOutput, TRUE);

        RtlGetNtVersionNumbers(NULL, NULL, (ULONG*)&l);
        l &= 0x00003fff;
        if (l > 14393) {
            cuiPrintText(g_ConOut, TEXT("\n[UacView] Not all features available for this build\n"), g_ConsoleOutput, TRUE);
        }

        //TestActivationContext();

        RtlSecureZeroMemory(szLogFile, sizeof(szLogFile));
        _strcpy(szLogFile, TEXT("uac"));
        ultostr(l, _strend(szLogFile));
        _strcat(szLogFile, TEXT(".log"));

        g_LogFile = LoggerCreate(szLogFile);
        if (g_LogFile != INVALID_HANDLE_VALUE) {
            cuiPrintText(g_ConOut, TEXT("Output will be logged to file"), g_ConsoleOutput, TRUE);
            cuiPrintText(g_ConOut, szLogFile, g_ConsoleOutput, TRUE);
        }

        ListBasicSettings();
        ListCOMFromRegistry();
        ListAppInfo();
        ListFusion();

        if (g_LogFile != INVALID_HANDLE_VALUE)
            CloseHandle(g_LogFile);

    }
    ExitProcess(0);
}
