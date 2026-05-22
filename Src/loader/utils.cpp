/*++

Module Name:

	utils.cpp

Abstract:

	This file contains support routines.

--*/

#include "global.h"

HANDLE GetExplorerHandle(
	VOID
	)
{
	HWND hTrayWnd = NULL;
	DWORD dwProcessId = 0;

	hTrayWnd = FindWindowW(L"Shell_TrayWnd", NULL);
	if (hTrayWnd == NULL) return NULL;

	GetWindowThreadProcessId(hTrayWnd, &dwProcessId);
	if (dwProcessId == 0) return NULL;

	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
}

PVOID AllocAndCopyMemory(
	CONST VOID *pLocalBuffer, 
	SIZE_T bufferSize, 
	BOOL bExecutable 
	)
{
	PVOID pRemoteAllocation = NULL;
	DWORD dwOldProtect = 0;
	BOOL bFailure = FALSE;

	pRemoteAllocation = VirtualAllocEx(g_ctx.hRemoteProcess, 0, bufferSize,
		MEM_COMMIT | PAGE_READWRITE,
		bExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);

	if (pRemoteAllocation) {
		
		if (WriteProcessMemory(g_ctx.hRemoteProcess, pRemoteAllocation, pLocalBuffer, bufferSize, NULL)) {

			if (!VirtualProtectEx(g_ctx.hRemoteProcess, pRemoteAllocation, bufferSize, bExecutable ? PAGE_EXECUTE_READ : PAGE_READWRITE, &dwOldProtect)) {
				bFailure = TRUE;
			}
		}
		else {
			bFailure = TRUE;
		}
	
		if (bFailure) {
			VirtualFreeEx(g_ctx.hRemoteProcess, pRemoteAllocation, 0, MEM_RELEASE);
			pRemoteAllocation = NULL;
		}
	}
	return pRemoteAllocation;
}

WCHAR* AllocAndCopyStringW(
	CONST WCHAR *szLocalString
	)
{
	return (WCHAR*)AllocAndCopyMemory((VOID*)szLocalString,
		(lstrlenW(szLocalString) + 1) * sizeof(WCHAR), FALSE);
}

CHAR* AllocAndCopyStringA(
	CONST CHAR *szLocalString
	)
{
	return (CHAR*)AllocAndCopyMemory((VOID*)szLocalString,
		(lstrlenA(szLocalString) + 1) * sizeof(CHAR), FALSE);
}

wchar_t *_strendW(const wchar_t *s)
{
	if (s == 0)
		return 0;

	while (*s != 0)
		s++;

	return (wchar_t *)s;
}

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

BOOL IsWow64(
	VOID
	)
{
	BOOL bIsWow64 = FALSE;
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
	if (fnIsWow64Process != NULL) {
		fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
	}
	return bIsWow64;
}
