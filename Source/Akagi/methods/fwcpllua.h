/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       FWCPLLUA.H
*
*  VERSION:     2.82
*
*  DATE:        02 Nov 2017
*
*  Prototypes and definitions for FwCplLua method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once


typedef interface IFwCplLua IFwCplLua;

typedef struct IFwCplLuaInterfaceVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in IFwCplLua * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in IFwCplLua * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method1)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method2)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method3)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method4)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method5)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method6)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method7)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method8)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method9)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method10)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method11)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method12)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method13)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method14)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *Method15)(
            __RPC__in IFwCplLua * This);

        HRESULT(STDMETHODCALLTYPE *LaunchAdvancedUI)(
            __RPC__in IFwCplLua * This);

    END_INTERFACE

} *PIFwCplLuaInterfaceVtbl;

interface IFwCplLua
{
    CONST_VTBL struct IFwCplLuaInterfaceVtbl *lpVtbl;
};
