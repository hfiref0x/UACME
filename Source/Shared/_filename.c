#include <Windows.h>

char *_filename_a(const char *f)
{
	char *p = (char *)f;

	if (f == 0)
		return 0;

	while (*f != (char)0) {
		if (*f == '\\')
			p = (char *)f + 1;
		f++;
	}
	return p;
}

wchar_t *_filename_w(const wchar_t *f)
{
	wchar_t *p = (wchar_t *)f;

	if (f == 0)
		return 0;

	while (*f != (wchar_t)0) {
		if (*f == (wchar_t)'\\')
			p = (wchar_t *)f + 1;
		f++;
	}
	return p;
}

char *_fileext_a(const char *f)
{
	char *p = 0;

	if (f == 0)
		return 0;

	while (*f != (char)0) {
		if (*f == '.')
			p = (char *)f;
		f++;
	}

	if (p == 0)
		p = (char *)f;

	return p;
}

wchar_t *_fileext_w(const wchar_t *f)
{
	wchar_t *p = 0;

	if (f == 0)
		return 0;

	while (*f != (wchar_t)0) {
		if (*f == '.')
			p = (wchar_t *)f;
		f++;
	}

	if (p == 0)
		p = (wchar_t *)f;

	return p;
}

char *_filepath_a(const char *f)
{
	char *p = (char *)f;

	if (f == 0)
		return 0;

	while (*f != (char)0) {
		if (*f == '\\')
			p = (char *)f;
		f++;
	}
	return p;
}

wchar_t *_filepath_w(const wchar_t *f)
{
	wchar_t *p = (wchar_t *)f;

	if (f == 0)
		return 0;

	while (*f != (wchar_t)0) {
		if (*f == '\\')
			p = (wchar_t *)f;
		f++;
	}
	return p;
}
