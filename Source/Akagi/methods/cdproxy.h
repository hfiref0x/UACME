/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       CDPROXY.H
*
*  VERSION:     2.83
*
*  DATE:        04 Nov 2017
*
*  Prototypes and definitions for ColorDataProxy method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef interface IColorDataProxy IColorDataProxy;

typedef struct IColorDataProxyVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in IColorDataProxy * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in IColorDataProxy * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method1)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method2)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method3)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method4)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method5)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method6)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method7)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method8)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method9)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method10)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *Method11)(
            __RPC__in IColorDataProxy * This);

        HRESULT(STDMETHODCALLTYPE *LaunchDccw)(
            __RPC__in IColorDataProxy * This,
            _In_      HWND hwnd);

    END_INTERFACE

} *PIColorDataProxyVtbl;

interface IColorDataProxy
{
    CONST_VTBL struct IColorDataProxyVtbl *lpVtbl;
};
