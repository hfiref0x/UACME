#include "rtltypes.h"

char *_strcpy_a(char *dest, const char *src)
{
	char *p;

	if ( (dest==0) || (src==0) )
		return dest;

	if (dest == src)
		return dest;

	p = dest;
	while ( *src!=0 ) {
		*p = *src;
		p++;
		src++;
	} 

	*p = 0;
	return dest;
}

wchar_t *_strcpy_w(wchar_t *dest, const wchar_t *src)
{
	wchar_t *p;

	if ((dest == 0) || (src == 0))
		return dest;

	if (dest == src)
		return dest;

	p = dest;
	while ( *src!=0 ) {
		*p = *src;
		p++;
		src++;
	} 

	*p = 0;
	return dest;
}
