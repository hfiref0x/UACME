/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       SUP.C
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
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
		WaitForSingleObject(shinfo.hProcess, 0x8000);
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

/*
* supCopyMemory
*
* Purpose:
*
* Copies bytes between buffers.
*
* dest - Destination buffer
* cbdest - Destination buffer size in bytes
* src - Source buffer
* cbsrc - Source buffer size in bytes
*
*/
void supCopyMemory(
	_Inout_ void *dest,
	_In_ size_t cbdest,
	_In_ const void *src,
	_In_ size_t cbsrc
	)
{
	char *d = (char*)dest;
	char *s = (char*)src;

	if ((dest == 0) || (src == 0) || (cbdest == 0))
		return;
	if (cbdest<cbsrc)
		cbsrc = cbdest;

	while (cbsrc>0) {
		*d++ = *s++;
		cbsrc--;
	}
}

/*
* supQueryEntryPointRVA
*
* Purpose:
*
* Return EP RVA of the given PE file.
*
*/
DWORD supQueryEntryPointRVA(
	_In_ LPWSTR lpImageFile
	)
{
	PVOID                       ImageBase;
	PIMAGE_DOS_HEADER           pdosh;
	PIMAGE_FILE_HEADER          pfh1;
	PIMAGE_OPTIONAL_HEADER      poh;
	DWORD                       epRVA = 0;

	if (lpImageFile == NULL) {
		return 0;
	}

	ImageBase = LoadLibraryExW(lpImageFile, 0, DONT_RESOLVE_DLL_REFERENCES);
	if (ImageBase) {

		pdosh = (PIMAGE_DOS_HEADER)ImageBase;
		pfh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)ImageBase + (pdosh->e_lfanew + sizeof(DWORD)));
		poh = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pfh1 + sizeof(IMAGE_FILE_HEADER));

		//AddressOfEntryPoint is in standard fields.
		epRVA = poh->AddressOfEntryPoint;

		FreeLibrary(ImageBase);
	}
	return epRVA;
}

/*
* supSetParameter
*
* Purpose:
*
* Set parameter for payload execution.
*
*/
BOOL supSetParameter(
	LPWSTR lpParameter,
	DWORD cbParameter
	)
{
	BOOL cond = FALSE, bResult = FALSE;
	HKEY hKey;
	LRESULT lRet;

	hKey = NULL;

	do {
		lRet = RegCreateKeyExW(HKEY_CURRENT_USER, T_AKAGI_KEY, 0, NULL,
			REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);

		if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
			break;
		}

		lRet = RegSetValueExW(hKey, T_AKAGI_PARAM, 0, REG_SZ,
			(LPBYTE)lpParameter, cbParameter);

		bResult = (lRet == ERROR_SUCCESS);

	} while (cond);

	if (hKey) {
		RegCloseKey(hKey);
	}

	return bResult;
}

/*
* supChkSum
*
* Purpose:
*
* Calculate partial checksum for given buffer.
*
*/
USHORT supChkSum(
	ULONG PartialSum,
	PUSHORT Source,
	ULONG Length
	)
{
	while (Length--) {
		PartialSum += *Source++;
		PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
	}
	return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);
}

/*
* supVerifyMappedImageMatchesChecksum
*
* Purpose:
*
* Calculate PE file checksum and compare it with checksum in PE header.
*
*/
BOOLEAN supVerifyMappedImageMatchesChecksum(
	_In_ PVOID BaseAddress,
	_In_ ULONG FileLength
	)
{
	PUSHORT AdjustSum;
	PIMAGE_NT_HEADERS NtHeaders;
	USHORT PartialSum;
	ULONG HeaderSum;
	ULONG CheckSum;

	HeaderSum = 0;
	PartialSum = supChkSum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

	NtHeaders = RtlImageNtHeader(BaseAddress);
	if (NtHeaders != NULL) {
		HeaderSum = NtHeaders->OptionalHeader.CheckSum;
		AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
		PartialSum -= (PartialSum < AdjustSum[0]);
		PartialSum -= AdjustSum[0];
		PartialSum -= (PartialSum < AdjustSum[1]);
		PartialSum -= AdjustSum[1];
	}
	else
	{
		PartialSum = 0;
		HeaderSum = FileLength;
	}
	CheckSum = (ULONG)PartialSum + FileLength;
	return (CheckSum == HeaderSum);
}

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
