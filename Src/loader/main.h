/*++

Module Name:

	main.h

Abstract:

	This file contains program entry point constants and definitions.

--*/

#define PROGRAMTITLE L"UACMe"
#define UNSUPPORTEDSTRING L"Unsupported version"
#define INFOSTRING L"UACMe v1.0.0 Defeating Windows User Account Control \n\r\n\r\
Supported Windows: 7/8/8.1/10TP, all from build 7xxx up to 9901 \n\r\
Based on (c) 2009 Leo Davidson code and WinNT/Pitou dropper code \n\r\n\r\
Press \"No\" to close application and \"Yes\" to continue \n\r\
If you press \"Yes\" then elevated CMD.EXE will be started \n\r\
as result of payload execution"
#define WOW64STRING L"Apparently it seems you are running under WOW64.\n\r\
This is not supported, run x64 version of this tool.\n\r\
Or adapt this code for heavens gate"

typedef DWORD(APIENTRY *PFNRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
