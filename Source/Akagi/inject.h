/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       INJECT.H
*
*  VERSION:     1.30
*
*  DATE:        30 Mar 2015
*
*  Injector prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <AccCtrl.h>

#define METHOD_SYSPREP		0x00000001
#define METHOD_SYSPREP_EX	0x00000002
#define METHOD_OOBE			0x00000004
#define METHOD_APPCOMPAT	0x00000008
#define METHOD_SIMDA		0x00000010
#define METHOD_CARBERP		0x00000020
#define METHOD_CARBERP_EX	0x00000040

#define SHELL32DLL			TEXT("shell32.dll")
#define OLE32DLL			TEXT("ole32.dll")
#define KERNEL32DLL			TEXT("kernel32.dll")

typedef HRESULT(__stdcall *pfnCoInitialize)(LPVOID pvReserved);
typedef HRESULT(__stdcall *pfnCoCreateInstance)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID FAR * ppv);
typedef HRESULT(__stdcall *pfnCoGetObject)(LPCWSTR pszName, BIND_OPTS *pBindOptions, REFIID riid, void **ppv);
typedef HRESULT(__stdcall *pfnSHCreateItemFromParsingName)(PCWSTR pszPath, IBindCtx *pbc, REFIID riid, void **ppv);
typedef BOOL(__stdcall *pfnShellExecuteExW)(SHELLEXECUTEINFOW *pExecInfo);
typedef DWORD(__stdcall *pfnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef BOOL(__stdcall *pfnCloseHandle)(HANDLE hObject);
typedef void(__stdcall *pfnCoUninitialize)(void);
typedef void(WINAPI *pfnOutputDebugStringW)(LPCWSTR lpOutputString);

typedef struct _ELOAD_PARAMETERS {
	WCHAR	SourceFilePathAndName[MAX_PATH + 1];
	WCHAR	DestinationDir[MAX_PATH + 1];
	WCHAR	ExePathAndName[MAX_PATH + 1];
	WCHAR	EleMoniker[MAX_PATH];
	//
	IID		xIID_IShellItem;
	IID		xIID;
	CLSID	xCLSID;
	//
	pfnCoInitialize					xCoInitialize;
	pfnCoCreateInstance				xCoCreateInstance;
	pfnCoGetObject					xCoGetObject;
	pfnSHCreateItemFromParsingName	xSHCreateItemFromParsingName;
	pfnShellExecuteExW				xShellExecuteExW;
	pfnWaitForSingleObject			xWaitForSingleObject;
	pfnCloseHandle					xCloseHandle;
	pfnCoUninitialize				xCoUninitialize;
	pfnOutputDebugStringW			xOutputDebugStringW;
} ELOAD_PARAMETERS, *PELOAD_PARAMETERS;

typedef struct _ELOAD_PARAMETERS_2 {
	WCHAR	ObjectName[MAX_PATH * 2];
	WCHAR   szKey[MAX_PATH];
	WCHAR   szNewSDDL[MAX_PATH];
	WCHAR	EleMoniker[MAX_PATH];
	//
	IID		xIID_ISecurityEditor;
	CLSID	xCLSID_ShellSecurityEditor;
	//
	pfnCoInitialize					xCoInitialize;
	pfnCoCreateInstance				xCoCreateInstance;
	pfnCoGetObject					xCoGetObject;
	pfnCoUninitialize				xCoUninitialize;
	pfnOutputDebugStringW			xOutputDebugStringW;
} ELOAD_PARAMETERS_2, *PELOAD_PARAMETERS_2;

typedef interface ISecurityEditor ISecurityEditor;

typedef struct ISecurityEditorVtbl {

	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE *QueryInterface)(
		__RPC__in ISecurityEditor * This,
		__RPC__in REFIID riid,
		_COM_Outptr_  void **ppvObject);

		ULONG(STDMETHODCALLTYPE *AddRef)(
			__RPC__in ISecurityEditor * This);

		ULONG(STDMETHODCALLTYPE *Release)(
			__RPC__in ISecurityEditor * This);

		HRESULT(STDMETHODCALLTYPE *GetSecurity)(
			__RPC__in ISecurityEditor * This,
			_In_ LPCOLESTR ObjectName,
			_In_ SE_OBJECT_TYPE ObjectType,
			_In_ SECURITY_INFORMATION SecurityInfo,
			_Out_opt_ LPCOLESTR * ppSDDLStr);

		HRESULT(STDMETHODCALLTYPE *SetSecurity)(
			__RPC__in ISecurityEditor * This,
			_In_ LPCOLESTR ObjectName,
			_In_ SE_OBJECT_TYPE ObjectType,
			_In_ SECURITY_INFORMATION SecurityInfo,
			_In_ LPCOLESTR ppSDDLStr);

	END_INTERFACE

} *PISecurityEditorVtbl;

interface ISecurityEditor
{
	CONST_VTBL struct ISecurityEditorVtbl *lpVtbl;
};

BOOL ucmInjectExplorer(
	_In_ LPVOID ElevParams,
	_In_ LPVOID ElevatedLoadProc
	);
