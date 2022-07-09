/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2022
*
*  TITLE:       ELVINT.H
*
*  VERSION:     3.62
*
*  DATE:        04 Jul 2022
*
*  Prototypes and definitions for elevated interface methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once
 
typedef interface IColorDataProxy IColorDataProxy;
typedef interface ICMLuaUtil ICMLuaUtil;
typedef interface IFwCplLua IFwCplLua;
typedef interface IEditionUpgradeManager IEditionUpgradeManager;
typedef interface ISecurityEditor ISecurityEditor;
typedef interface IIEAdminBrokerObject IIEAdminBrokerObject;
typedef interface IActiveXInstallBroker IActiveXInstallBroker;
typedef interface IWscAdmin IWscAdmin;
typedef interface IElevatedFactoryServer IElevatedFactoryServer;

//VTBL DEF

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

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SetRasCredentials)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SetRasEntryProperties)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *DeleteRasEntry)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *LaunchInfSection)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *LaunchInfSectionEx)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *CreateLayerDirectory)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *ShellExec)(
            __RPC__in ICMLuaUtil * This,
            _In_     LPCTSTR lpFile,
            _In_opt_  LPCTSTR lpParameters,
            _In_opt_  LPCTSTR lpDirectory,
            _In_      ULONG fMask,
            _In_      ULONG nShow);

        HRESULT(STDMETHODCALLTYPE *SetRegistryStringValue)(
            __RPC__in ICMLuaUtil * This,
            _In_      HKEY hKey,
            _In_opt_  LPCTSTR lpSubKey,
            _In_opt_  LPCTSTR lpValueName,
            _In_      LPCTSTR lpValueString);

        HRESULT(STDMETHODCALLTYPE *DeleteRegistryStringValue)(
            __RPC__in ICMLuaUtil * This,
            _In_      HKEY hKey,
            _In_      LPCTSTR lpSubKey,
            _In_      LPCTSTR lpValueName);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *DeleteRegKeysWithoutSubKeys)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *DeleteRegTree)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *ExitWindowsFunc)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *AllowAccessToTheWorld)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *CreateFileAndClose)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *DeleteHiddenCmProfileFiles)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *CallCustomActionDll)(
            __RPC__in ICMLuaUtil * This);

        HRESULT(STDMETHODCALLTYPE *RunCustomActionExe)(
            __RPC__in       ICMLuaUtil * This,
            _In_            LPCTSTR lpFile,
            _In_opt_        LPCTSTR lpParameters,
            _COM_Outptr_    LPCTSTR *pszHandleAsHexString);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SetRasSubEntryProperties)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *DeleteRasSubEntry)(
            __RPC__in ICMLuaUtil * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *SetCustomAuthData)(
            __RPC__in ICMLuaUtil * This);

    END_INTERFACE

} *PICMLuaUtilVtbl;

typedef struct IFwCplLuaInterfaceVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in IFwCplLua* This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            __RPC__in IFwCplLua* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* GetTypeInfoCount)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* GetTypeInfo)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* GetIDsOfNames)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* Invoke)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* AddGlobalPort)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* AddProgram)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* DeleteGlobalPort)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* DeleteApplication)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* EnablePort)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* EnableProgram)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* EnableRuleGroup)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* EnableCustomRule)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* EditGlobalPort)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* EditProgram)(
            __RPC__in IFwCplLua* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* Activate)(
            __RPC__in IFwCplLua* This);

        HRESULT(STDMETHODCALLTYPE* LaunchAdvancedUI)(
            __RPC__in IFwCplLua* This);

    END_INTERFACE

} *PIFwCplLuaInterfaceVtbl;

typedef struct IEditionUpgradeManagerVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in IEditionUpgradeManager * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in IEditionUpgradeManager * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in IEditionUpgradeManager * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *InitializeWindow)(
            __RPC__in IEditionUpgradeManager * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *UpdateOperatingSystem)(
            __RPC__in IEditionUpgradeManager * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *ShowProductKeyUI)(
            __RPC__in IEditionUpgradeManager * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *UpdateOperatingSystemWithParams)(
            __RPC__in IEditionUpgradeManager * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *AcquireModernLicenseForWindows)(
            __RPC__in IEditionUpgradeManager * This);

        HRESULT(STDMETHODCALLTYPE *AcquireModernLicenseWithPreviousId)(
            __RPC__in IEditionUpgradeManager * This,
            __RPC__in LPWSTR PreviousId,
            __RPC__in DWORD *Data);

    //incomplete, irrelevant
    END_INTERFACE

} *PIEditionUpgradeManagerVtbl;

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

typedef struct IIEAdminBrokerObjectVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in IIEAdminBrokerObject* This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            __RPC__in IIEAdminBrokerObject* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            __RPC__in IIEAdminBrokerObject* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* InitializeAdminInstaller)(
            __RPC__in IIEAdminBrokerObject* This,
            _In_opt_ LPCOLESTR ProviderName,
            _In_ DWORD Unknown0,
            _COM_Outptr_ void** InstanceGuid);

    END_INTERFACE

} *PIIEAdminBrokerObjectVtbl;

typedef struct IActiveXInstallBrokerVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in IActiveXInstallBroker* This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            __RPC__in IActiveXInstallBroker* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            __RPC__in IActiveXInstallBroker* This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE* VerifyFile)(
            __RPC__in IActiveXInstallBroker* This,
            _In_ BSTR InstanceGuid,
            _In_ HWND ParentWindow,
            _In_ BSTR Unknown0,
            _In_ BSTR pcwszFilePath,
            _In_ BSTR Unknown1,
            _In_ ULONG dwUIChoice,
            _In_ ULONG dwUIContext,
            _In_ REFGUID GuidKey,
            _Out_ BSTR* VerifiedFileName,
            _Out_ PULONG CertDetailsSize,
            _Out_ void** CertDetails);

        HRESULT(STDMETHODCALLTYPE* RunSetupCommand)(
            __RPC__in IActiveXInstallBroker* This,
            _In_ BSTR InstanceGuid,
            _In_ HWND ParentWindow,
            _In_ BSTR szCmdName,
            _In_ BSTR szInfSection,
            _In_ BSTR szDir,
            _In_ BSTR szTitle,
            _In_ ULONG dwFlags,
            _Out_ PHANDLE lpTargetHandle);

        //incomplete definition

    END_INTERFACE

} *PIActiveXInstallBrokerVtbl;

typedef struct IWscAdminVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in IWscAdmin* This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            __RPC__in IWscAdmin* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            __RPC__in IWscAdmin* This);

        HRESULT(STDMETHODCALLTYPE* Initialize)(
            __RPC__in IWscAdmin* This);

        HRESULT(STDMETHODCALLTYPE* DoModalSecurityAction)(
            __RPC__in IWscAdmin* This,
            __RPC__in HWND ParentWindow,
            __RPC__in UINT Action,
            _Reserved_ PVOID Reserved);

    END_INTERFACE

} *PIWscAdminVtbl;

typedef struct IElevatedFactoryServerVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in IElevatedFactoryServer* This,
            __RPC__in REFIID riid,
            _COM_Outptr_ void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            __RPC__in IElevatedFactoryServer* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            __RPC__in IElevatedFactoryServer* This);

        HRESULT(STDMETHODCALLTYPE* ServerCreateElevatedObject)(
            __RPC__in IElevatedFactoryServer* This,
            __RPC__in REFCLSID rclsid,
            __RPC__in REFIID riid,
            _COM_Outptr_ void** ppvObject);

    //incomplete definition

    END_INTERFACE

} *PIElevatedFactoryServerVtbl;

// INTERFACE DEF

interface IColorDataProxy { CONST_VTBL struct IColorDataProxyVtbl* lpVtbl; };
interface ICMLuaUtil { CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl; };
interface IFwCplLua { CONST_VTBL struct IFwCplLuaInterfaceVtbl* lpVtbl; };
interface IEditionUpgradeManager { CONST_VTBL struct IEditionUpgradeManagerVtbl* lpVtbl; };
interface ISecurityEditor { CONST_VTBL struct ISecurityEditorVtbl* lpVtbl; };
interface IIEAdminBrokerObject { CONST_VTBL struct IIEAdminBrokerObjectVtbl* lpVtbl; };
interface IActiveXInstallBroker { CONST_VTBL struct IActiveXInstallBrokerVtbl* lpVtbl; };
interface IWscAdmin { CONST_VTBL struct IWscAdminVtbl* lpVtbl; };
interface IElevatedFactoryServer { CONST_VTBL struct IElevatedFactoryServerVtbl* lpVtbl; };
