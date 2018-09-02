/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       ELVINT.H
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
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
 
typedef interface IAccessibilityCplAdmin IAccessibilityCplAdmin;
typedef interface IARPUninstallStringLauncher IARPUninstallStringLauncher;
typedef interface IColorDataProxy IColorDataProxy;
typedef interface ICMLuaUtil ICMLuaUtil;
typedef interface ICreateNewLink ICreateNewLink;
typedef interface IDateTimeStateWriter IDateTimeStateWriter;
typedef interface IFwCplLua IFwCplLua;
typedef interface ISecurityEditor ISecurityEditor;
typedef interface ISLLUACOMWin7 ISLLUACOMWin7;
typedef interface ISLLUACOM ISLLUACOM;

//VTBL DEF

typedef struct IAccessibilityCplAdminVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in IAccessibilityCplAdmin * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in IAccessibilityCplAdmin * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in IAccessibilityCplAdmin * This);

        HRESULT(STDMETHODCALLTYPE *LinktoSystemRestorePoint)(
            __RPC__in IAccessibilityCplAdmin * This);

        //incomplete
        HRESULT(STDMETHODCALLTYPE *ApplyToLogonDesktop)(
            __RPC__in IAccessibilityCplAdmin * This);

    END_INTERFACE

} *PIAccessibilityCplAdmin;

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

typedef struct tagCREATELINKDATA {
    ULONG dwFlags;
    WCHAR szLinkName[MAX_PATH];     // + 0x20C
    WCHAR szExeName[MAX_PATH];      // + 0x414
    WCHAR szParams[MAX_PATH];       // + 0x61C
    WCHAR szWorkingDir[MAX_PATH];   // + 0x824
    WCHAR szOriginalName[MAX_PATH]; // + 0xA2C
    WCHAR szExpExeName[MAX_PATH];   // + 0xC34
    WCHAR szProgDesc[MAX_PATH];     // + 0xE3C
    WCHAR szFolder[MAX_PATH];       // + 0x1044
    WCHAR szExt[MAX_PATH];          // + 0x124C
    WCHAR szIconFile[MAX_PATH];     // + 0x1454
    USHORT wIconIndex;
} CREATELINKDATA, *PCREATELINKDATA;

typedef struct ICreateNewLinkVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in ICreateNewLink * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in ICreateNewLink * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in ICreateNewLink * This);

        HRESULT(STDMETHODCALLTYPE *CreateNewLink)(
            __RPC__in ICreateNewLink * This,
            __RPC__in PCREATELINKDATA LinkData,
            __RPC__in DWORD dwFlags);

        HRESULT(STDMETHODCALLTYPE *RenameLink)(
            __RPC__in ICreateNewLink * This,
            __RPC__in PCREATELINKDATA LinkData);

    END_INTERFACE

} *PICreateNewLinkVtbl;

typedef struct IDateTimeStateWriterVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)(
            __RPC__in IDateTimeStateWriter * This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(
            __RPC__in IDateTimeStateWriter * This);

        ULONG(STDMETHODCALLTYPE *Release)(
            __RPC__in IDateTimeStateWriter * This);

        HRESULT(STDMETHODCALLTYPE *HasTimePrivilege)(
            __RPC__in IDateTimeStateWriter * This);

        HRESULT(STDMETHODCALLTYPE *HasInternetTimePrivilege)(
            __RPC__in IDateTimeStateWriter * This);

        HRESULT(STDMETHODCALLTYPE *HasTimeZonePrivilege)(
            __RPC__in IDateTimeStateWriter * This);

        HRESULT(STDMETHODCALLTYPE *SetSystemTime)(
            __RPC__in IDateTimeStateWriter * This,
            __RPC__in const SYSTEMTIME *lpSystemTime);

        HRESULT(STDMETHODCALLTYPE *SetAutoDST)(
            __RPC__in IDateTimeStateWriter * This,
            __RPC__in ULONG DisableAutoDaylightTimeSet);

        HRESULT(STDMETHODCALLTYPE *SetTimeZoneInfo)(
            __RPC__in IDateTimeStateWriter * This,
            __RPC__in PVOID TimeZoneParam);

        HRESULT(STDMETHODCALLTYPE *SetW32TimeServer)(
            __RPC__in IDateTimeStateWriter * This,
            __RPC__in PVOID W32TimeServerParam);

        HRESULT(STDMETHODCALLTYPE *SetSyncFlags)(
            __RPC__in IDateTimeStateWriter * This,
            __RPC__in DWORD dwSyncFlags);

        HRESULT(STDMETHODCALLTYPE *SetW32TimeServerAndKeys)(
            __RPC__in IDateTimeStateWriter * This,
            __RPC__in PVOID Param1,
            __RPC__in ULONG Param2,
            __RPC__in ULONG Param3);

        HRESULT(STDMETHODCALLTYPE *StopAndDisableService)(
            __RPC__in IDateTimeStateWriter * This);

        HRESULT(STDMETHODCALLTYPE *StartServiceAndRefresh)(
            __RPC__in IDateTimeStateWriter * This,
            __RPC__in ULONG NeedRefresh);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *W32TimeSyncNow)(
            __RPC__in IDateTimeStateWriter * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *CreateW32TimeCfgSuccessErrorString)(
            __RPC__in IDateTimeStateWriter * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *StartInternetTimeSync)(
            __RPC__in IDateTimeStateWriter * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *GetSyncStatus)(
            __RPC__in IDateTimeStateWriter * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *StopInternetTimeSync)(
            __RPC__in IDateTimeStateWriter * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *Advise)(
            __RPC__in IDateTimeStateWriter * This);

        //incomplete definition
        HRESULT(STDMETHODCALLTYPE *UnAdvise)(
            __RPC__in IDateTimeStateWriter * This);

    END_INTERFACE

} *PIDateTimeStateWriterVtbl;

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

typedef enum _SLLUA_ROOTKEY {
    SSLUA_HKEY_CLASSES_ROOT = 1,
    SSLUA_HKEY_CURRENT_CONFIG,
    SSLUA_HKEY_LOCAL_MACHINE,
    SSLUA_HKEY_USERS,
} SSLUA_ROOTKEY, *PSSLUA_ROOTKEY;

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

// INTERFACE DEF

interface IAccessibilityCplAdmin { CONST_VTBL struct IAccessibilityCplAdminVtbl *lpVtbl; };
interface IARPUninstallStringLauncher { CONST_VTBL struct IARPUninstallStringLauncherVtbl *lpVtbl; };
interface IColorDataProxy { CONST_VTBL struct IColorDataProxyVtbl *lpVtbl; };
interface ICMLuaUtil { CONST_VTBL struct ICMLuaUtilVtbl *lpVtbl; };
interface ICreateNewLink { CONST_VTBL struct ICreateNewLinkVtbl *lpVtbl; };
interface IDateTimeStateWriter { CONST_VTBL struct IDateTimeStateWriterVtbl *lpVtbl; };
interface IFwCplLua { CONST_VTBL struct IFwCplLuaInterfaceVtbl *lpVtbl; };
interface ISecurityEditor { CONST_VTBL struct ISecurityEditorVtbl *lpVtbl; };
interface ISLLUACOMWin7 { CONST_VTBL struct ISLLUACOMVtblWin7 *lpVtbl; };
interface ISLLUACOM { CONST_VTBL struct ISLLUACOMInterfaceVtbl *lpVtbl; };
