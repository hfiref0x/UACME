#ifndef _CMDLINEH_
#define _CMDLINEH_

BOOL GetCommandLineParamW(
	IN	LPCWSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPWSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	);

BOOL GetCommandLineParamA(
	IN	LPCSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	);

char *ExtractFilePathA(const char *FileName, char *FilePath);
wchar_t *ExtractFilePathW(const wchar_t *FileName, wchar_t *FilePath);

#ifdef UNICODE

#define ExtractFilePath			ExtractFilePathW
#define GetCommandLineParam		GetCommandLineParamW

#else // ANSI

#define ExtractFilePath			ExtractFilePathA
#define GetCommandLineParam		GetCommandLineParamA

#endif

#endif /* _CMDLINEH_ */
