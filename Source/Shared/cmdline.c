#include <windows.h>

BOOL GetCommandLineParamW(
	IN	LPCWSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPWSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	)
{
	ULONG	c, plen = 0;
	TCHAR	divider;

	if (ParamLen != NULL)
		*ParamLen = 0;

	if (CmdLine == NULL) {
		if ((Buffer != NULL) && (BufferSize > 0))
			*Buffer = 0;
		return FALSE;
	}

	for (c = 0; c <= ParamIndex; c++) {
		plen = 0;

		while (*CmdLine == ' ')
			CmdLine++;

		switch (*CmdLine) {
		case 0:
			goto zero_term_exit;

		case '"':
			CmdLine++;
			divider = '"';
			break;

		default:
			divider = ' ';
		}

		while ((*CmdLine != '"') && (*CmdLine != divider) && (*CmdLine != 0)) {
			plen++;
			if (c == ParamIndex)
				if ((plen < BufferSize) && (Buffer != NULL)) {
					*Buffer = *CmdLine;
					Buffer++;
				}
			CmdLine++;
		}

		if (*CmdLine != 0)
			CmdLine++;
	}

zero_term_exit:

	if ((Buffer != NULL) && (BufferSize > 0))
		*Buffer = 0;

	if (ParamLen != NULL)
		*ParamLen = plen;

	if (plen < BufferSize)
		return TRUE;
	else
		return FALSE;
}

BOOL GetCommandLineParamA(
	IN	LPCSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	)
{
	ULONG	c, plen = 0;
	TCHAR	divider;

	if (CmdLine == NULL)
		return FALSE;

	if (ParamLen != NULL)
		*ParamLen = 0;

	for (c = 0; c <= ParamIndex; c++) {
		plen = 0;

		while (*CmdLine == ' ')
			CmdLine++;

		switch (*CmdLine) {
		case 0:
			goto zero_term_exit;

		case '"':
			CmdLine++;
			divider = '"';
			break;

		default:
			divider = ' ';
		}

		while ((*CmdLine != '"') && (*CmdLine != divider) && (*CmdLine != 0)) {
			plen++;
			if (c == ParamIndex)
				if ((plen < BufferSize) && (Buffer != NULL)) {
					*Buffer = *CmdLine;
					Buffer++;
				}
			CmdLine++;
		}

		if (*CmdLine != 0)
			CmdLine++;
	}

zero_term_exit:

	if ((Buffer != NULL) && (BufferSize > 0))
		*Buffer = 0;

	if (ParamLen != NULL)
		*ParamLen = plen;

	if (plen < BufferSize)
		return TRUE;
	else
		return FALSE;
}

char *ExtractFilePathA(const char *FileName, char *FilePath)
{
	char *p = (char *)FileName, *p0 = (char *)FileName;

	if ((FileName == 0) || (FilePath == 0))
		return 0;

	while (*FileName != 0) {
		if (*FileName == '\\')
			p = (char *)FileName + 1;
		FileName++;
	}

	while (p0 < p) {
		*FilePath = *p0;
		FilePath++;
		p0++;
	}

	*FilePath = 0;

	return FilePath;
}

wchar_t *ExtractFilePathW(const wchar_t *FileName, wchar_t *FilePath)
{
	wchar_t *p = (wchar_t *)FileName, *p0 = (wchar_t *)FileName;

	if ((FileName == 0) || (FilePath == 0))
		return 0;

	while (*FileName != 0) {
		if (*FileName == '\\')
			p = (wchar_t *)FileName + 1;
		FileName++;
	}

	while (p0 < p) {
		*FilePath = *p0;
		FilePath++;
		p0++;
	}

	*FilePath = 0;

	return FilePath;
}
