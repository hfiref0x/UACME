/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       SPPLUAOBJECT.H
*
*  VERSION:     2.89
*
*  DATE:        14 June 2018
*
*  Prototypes and definitions for SPPLUAObject (Software Licensing) method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef enum _SLLUA_ROOTKEY {
    SSLUA_HKEY_CLASSES_ROOT = 1,
    SSLUA_HKEY_CURRENT_CONFIG,
    SSLUA_HKEY_LOCAL_MACHINE,
    SSLUA_HKEY_USERS,
} SSLUA_ROOTKEY, *PSSLUA_ROOTKEY;

typedef interface ISLLUACOMWin7 ISLLUACOMWin7;

typedef struct ISLLUACOMVtblWin7
{
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in ISLLUACOMWin7 * This,
            __RPC__in REFIID riid,
            _COM_Outptr_ void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in ISLLUACOMWin7 * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in ISLLUACOMWin7 * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAActivateProduct)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUADepositOfflineConfirmationId)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAFireEvent)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAInstallLicense)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAUninstallLicense)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAInstallPackage)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUACancelPackageInstall)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAQueryLicensePackageProgress)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAUninstallPackage)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAInstallProofOfPurchase)(
            __RPC__in ISLLUACOMWin7 *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAUninstallProofOfPurchase)(
            __RPC__in ISLLUACOMWin7 *This);

        HRESULT(STDMETHODCALLTYPE *SLLUARegKeySetValue)(
            __RPC__in ISLLUACOMWin7 *This,
            __RPC__in SSLUA_ROOTKEY RegType,
            __RPC__in WCHAR *wsRegPath,
            __RPC__in WCHAR *wsValueName,
            __RPC__in SAFEARRAY *ArrayData,
            __RPC__in DWORD dwKeyType);

    END_INTERFACE

} *PISLLUACOMVtblWin7;

interface ISLLUACOMWin7
{
    CONST_VTBL struct ISLLUACOMVtblWin7 *lpVtbl;
};

typedef interface ISLLUACOM ISLLUACOM;

typedef struct ISLLUACOMInterfaceVtbl
{
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in ISLLUACOM * This,
            __RPC__in REFIID riid,
            _COM_Outptr_ void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in ISLLUACOM * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in ISLLUACOM * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAActivateProduct)(
            __RPC__in ISLLUACOM *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUADepositOfflineConfirmationId)(
            __RPC__in ISLLUACOM *This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SLLUAInstallProofOfPurchase)(
            __RPC__in ISLLUACOM *This);

        HRESULT(STDMETHODCALLTYPE *SLLUARegKeySetValue)(
            __RPC__in ISLLUACOM *This,
            __RPC__in SSLUA_ROOTKEY RegType,
            __RPC__in WCHAR *wsRegPath,
            __RPC__in WCHAR *wsValueName,
            __RPC__in SAFEARRAY *ArrayData,
            __RPC__in DWORD dwKeyType);

    END_INTERFACE

} *PISLLUACOMIinterfaceVtbl;

interface ISLLUACOM
{
    CONST_VTBL struct ISLLUACOMInterfaceVtbl *lpVtbl;
};

