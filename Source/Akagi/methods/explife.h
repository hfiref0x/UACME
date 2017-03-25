/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       EXPLIFE.H
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
*
*  Prototypes and definitions for ExpLife method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef interface IARPUninstallStringLauncher IARPUninstallStringLauncher;

typedef struct IARPUninstallStringLauncherVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in IARPUninstallStringLauncher * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in IARPUninstallStringLauncher * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in IARPUninstallStringLauncher * This);

        HRESULT(STDMETHODCALLTYPE *LaunchUninstallStringAndWait)(
            __RPC__in IARPUninstallStringLauncher * This,
            _In_ HKEY hKey,
            _In_ LPCOLESTR Item,
            _In_ BOOL bModify,
            _In_ HWND hWnd);

        HRESULT(STDMETHODCALLTYPE *RemoveBrokenItemFromInstalledProgramsList)(
            __RPC__in IARPUninstallStringLauncher * This,
            _In_ HKEY hKey,
            _In_ LPCOLESTR Item);

    END_INTERFACE

} *PIARPUninstallStringLauncherVtbl;

interface IARPUninstallStringLauncher
{
    CONST_VTBL struct IARPUninstallStringLauncherVtbl *lpVtbl;
};

BOOL ucmUninstallLauncherMethod(
    _In_ LPWSTR lpszExecutable);
