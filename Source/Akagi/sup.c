/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       SUP.C
*
*  VERSION:     1.60
*
*  DATE:        20 Apr 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* supIsProcess32bit
*
* Purpose:
*
* Return TRUE if given process is under WOW64, FALSE otherwise.
*
*/
BOOLEAN supIsProcess32bit(
	_In_ HANDLE hProcess
	)
{
	NTSTATUS status;
	PROCESS_EXTENDED_BASIC_INFORMATION pebi;

	if (hProcess == NULL) {
		return FALSE;
	}

	//query if this is wow64 process
	RtlSecureZeroMemory(&pebi, sizeof(pebi));
	pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), NULL);
	if (NT_SUCCESS(status)) {
		return (pebi.IsWow64Process == 1);
	}
	return FALSE;
}

/*
* supGetExplorerHandle
*
* Purpose:
*
* Returns Explorer process handle opened with maximum allowed rights or NULL on error.
*
*/
HANDLE supGetExplorerHandle(
	VOID
	)
{
	HWND	hTrayWnd = NULL;
	DWORD	dwProcessId = 0;

	hTrayWnd = FindWindow(TEXT("Shell_TrayWnd"), NULL);
	if (hTrayWnd == NULL)
		return NULL;

	GetWindowThreadProcessId(hTrayWnd, &dwProcessId);
	if (dwProcessId == 0)
		return NULL;

	return OpenProcess(MAXIMUM_ALLOWED, FALSE, dwProcessId);
}

/*
* supGetElevationType
*
* Purpose:
*
* Returns client elevation type.
*
*/
BOOL supGetElevationType(
	TOKEN_ELEVATION_TYPE *lpType
	)
{
	HANDLE hToken = NULL;
	NTSTATUS status;
	ULONG bytesRead = 0;

	if (lpType == NULL) {
		return FALSE;
	}

	status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	if (!NT_SUCCESS(status)) {
		SetLastError(RtlNtStatusToDosError(status));
		return FALSE;
	}

	status = NtQueryInformationToken(hToken, TokenElevationType, lpType,
		sizeof(TOKEN_ELEVATION_TYPE), &bytesRead);

	SetLastError(RtlNtStatusToDosError(status));

	NtClose(hToken);

	return (NT_SUCCESS(status));
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file and write buffer to it.
*
*/
BOOL supWriteBufferToFile(
	_In_ LPWSTR lpFileName,
	_In_ PVOID Buffer,
	_In_ DWORD BufferSize
	)
{
	HANDLE hFile;
	DWORD bytesIO;

	if (
		(lpFileName == NULL) ||
		(Buffer == NULL) ||
		(BufferSize == 0)
		)
	{
		return FALSE;
	}

	hFile = CreateFileW(lpFileName,
		GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	WriteFile(hFile, Buffer, BufferSize, &bytesIO, NULL);
	CloseHandle(hFile);

	return (bytesIO == BufferSize);
}

/*
* supRunProcess
*
* Purpose:
*
* Execute given process with given parameters.
*
*/
BOOL supRunProcess(
	_In_ LPWSTR lpszProcessName,
	_In_opt_ LPWSTR lpszParameters
	)
{
	BOOL bResult;
	SHELLEXECUTEINFOW shinfo;
	RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

	if (lpszProcessName == NULL) {
		return FALSE;
	}

	shinfo.cbSize = sizeof(shinfo);
	shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shinfo.lpFile = lpszProcessName;
	shinfo.lpParameters = lpszParameters;
	shinfo.lpDirectory = NULL;
	shinfo.nShow = SW_SHOW;
	bResult = ShellExecuteExW(&shinfo);
	if (bResult) {
		WaitForSingleObject(shinfo.hProcess, 0x4000);
		CloseHandle(shinfo.hProcess);
	}
	return bResult;
}

/*
* supRunProcessEx
*
* Purpose:
*
* Start new process in suspended state.
*
*/
HANDLE supRunProcessEx(
	_In_ LPWSTR lpszParameters,
	_In_opt_ LPWSTR lpCurrentDirectory,
	_Out_opt_ HANDLE *PrimaryThread
	)
{
	BOOL cond = FALSE;
	LPWSTR pszBuffer = NULL;
	SIZE_T ccb;
	STARTUPINFOW sti1;
	PROCESS_INFORMATION pi1;

	if (PrimaryThread) {
		*PrimaryThread = NULL;
	}

	if (lpszParameters == NULL) {
		return NULL;
	}

	ccb = (_strlen_w(lpszParameters) * sizeof(WCHAR)) + sizeof(WCHAR);
	pszBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ccb);
	if (pszBuffer == NULL) {
		return NULL;
	}

	_strcpy_w(pszBuffer, lpszParameters);

	RtlSecureZeroMemory(&pi1, sizeof(pi1));
	RtlSecureZeroMemory(&sti1, sizeof(sti1));
	GetStartupInfoW(&sti1);

	do {

		if (!CreateProcessW(NULL, pszBuffer, NULL, NULL, FALSE,
			CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED,
			NULL, lpCurrentDirectory, &sti1, &pi1))
		{
			break;
		}

		if (PrimaryThread) {
			*PrimaryThread = pi1.hThread;
		}
		else {
			CloseHandle(pi1.hThread);
		}
	} while (cond);

	HeapFree(GetProcessHeap(), 0, pszBuffer);

	return pi1.hProcess;
}

/*
* _filenameW
*
* Purpose:
*
* Return name part of filename.
*
*/
wchar_t *_filenameW(
	const wchar_t *f
	)
{
	wchar_t *p = (wchar_t *)f;

	if (f == 0)
		return 0;

	while (*f != (wchar_t)0) {
		if (*f == (wchar_t)'\\')
			p = (wchar_t *)f + 1;
		f++;
	}
	return p;
}
