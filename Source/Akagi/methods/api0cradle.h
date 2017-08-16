/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       API0CRADLE.H
*
*  VERSION:     2.79
*
*  DATE:        16 Aug 2017
*
*  Prototypes and definitions for api0cradle method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in ICMLuaUtil * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in ICMLuaUtil * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method1)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method2)(
           __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method3)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method4)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method5)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method6)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *ShellExec)(
            __RPC__in ICMLuaUtil * This,
             _In_     LPCTSTR lpFile,
            _In_opt_ LPCTSTR lpParameters,
            _In_opt_ LPCTSTR lpDirectory,
            _In_     ULONG fMask,
            _In_     ULONG nShow
            );

        HRESULT(STDMETHODCALLTYPE *Method8)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method9)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method10)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method11)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method12)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method13)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method14)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method15)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method16)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method17)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method18)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method19)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *Method20)(
            __RPC__in ICMLuaUtil * This);

    END_INTERFACE

} *PICMLuaUtilVtbl;

interface ICMLuaUtil
{
    CONST_VTBL struct ICMLuaUtilVtbl *lpVtbl;
};

BOOL ucmCMLuaUtilShellExecMethod(
    _In_ LPWSTR lpszExecutable);
