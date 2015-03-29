/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       SUP.C
*
*  VERSION:     1.20
*
*  DATE:        29 Mar 2015
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
