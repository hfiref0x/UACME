#include "rtltypes.h"

char *_strend_a(const char *s)
{
	if ( s==0 )
		return 0;

	while ( *s!=0 )
		s++;

	return (char *)s;
}

wchar_t *_strend_w(const wchar_t *s)
{
	if ( s==0 )
		return 0;

	while ( *s!=0 )
		s++;

	return (wchar_t *)s;
}
