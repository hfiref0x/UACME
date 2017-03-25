#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       TEST.H
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
*
*  Test unit header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef interface ITestInterface ITestInterface;

typedef struct ITestInterfaceVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in ITestInterface * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

    ULONG(STDMETHODCALLTYPE *AddRef)(
        __RPC__in ITestInterface * This);

    ULONG(STDMETHODCALLTYPE *Release)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method1)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method2)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method3)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method4)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method5)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method6)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method7)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method8)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method9)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method10)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method11)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method12)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method13)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method14)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method15)(
        __RPC__in ITestInterface * This);

    HRESULT(STDMETHODCALLTYPE *Method16)(
        __RPC__in ITestInterface * This);
    END_INTERFACE

} *PITestInterfaceVtbl;

interface ITestInterface
{
    CONST_VTBL struct ITestInterfaceVtbl *lpVtbl;
};

BOOL ucmTestRoutine(
    _In_opt_ PVOID PayloadCode, 
    _In_opt_ ULONG PayloadSize);
