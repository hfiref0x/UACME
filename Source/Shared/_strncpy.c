#include "rtltypes.h"

char *_strncpy_a(char *dest, size_t ccdest, const char *src, size_t ccsrc)
{
	char *p;

	if ( (dest==0) || (src==0) || (ccdest==0) )
		return dest;

	ccdest--;
	p = dest;

	while ( (*src!=0) && (ccdest>0) && (ccsrc>0) ) {
		*p = *src;
		p++;
		src++;
		ccdest--;
		ccsrc--;
	}

	*p = 0;
	return dest;
}

wchar_t *_strncpy_w(wchar_t *dest, size_t ccdest, const wchar_t *src, size_t ccsrc)
{
	wchar_t *p;

	if ( (dest==0) || (src==0) || (ccdest==0) )
		return dest;

	ccdest--;
	p = dest;

	while ( (*src!=0) && (ccdest>0) && (ccsrc>0) ) {
		*p = *src;
		p++;
		src++;
		ccdest--;
		ccsrc--;
	}

	*p = 0;
	return dest;
}
