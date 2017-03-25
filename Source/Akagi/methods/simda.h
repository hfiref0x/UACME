/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       SIMDA.H
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
*
*  Prototypes and definitions for Simda method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <AccCtrl.h>

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

DWORD WINAPI ucmMasqueradedAlterObjectSecurityCOM(
    _In_ LPWSTR lpTargetObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ SE_OBJECT_TYPE ObjectType,
    _In_ LPWSTR NewSddl);

BOOL ucmSimdaTurnOffUac(
    VOID);
