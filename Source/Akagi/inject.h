/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       INJECT.H
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
*
*  Injector prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <AccCtrl.h>

typedef HRESULT(WINAPI *pfnCoInitialize)(LPVOID pvReserved);
typedef HRESULT(WINAPI *pfnCoCreateInstance)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID FAR * ppv);
typedef HRESULT(WINAPI *pfnCoGetObject)(LPCWSTR pszName, BIND_OPTS *pBindOptions, REFIID riid, void **ppv);
typedef HRESULT(WINAPI *pfnSHCreateItemFromParsingName)(PCWSTR pszPath, IBindCtx *pbc, REFIID riid, void **ppv);
typedef BOOL(WINAPI *pfnShellExecuteExW)(SHELLEXECUTEINFOW *pExecInfo);
typedef DWORD(WINAPI *pfnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef BOOL(WINAPI *pfnCloseHandle)(HANDLE hObject);
typedef void(WINAPI *pfnCoUninitialize)(void);
typedef void(WINAPI *pfnOutputDebugStringW)(LPCWSTR lpOutputString);
typedef void (WINAPI *pfnSleep)(DWORD dwMilliseconds);

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
	SE_OBJECT_TYPE        ObjectType;
	SECURITY_INFORMATION  SecurityInformation;
	//
	WCHAR            szTargetObject[MAX_PATH + 1];
	WCHAR            szNewSDDL[MAX_PATH + 1];
	WCHAR	         EleMoniker[MAX_PATH];
	//
	IID		         xIID_ISecurityEditor;
	CLSID	         xCLSID_ShellSecurityEditor;
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
