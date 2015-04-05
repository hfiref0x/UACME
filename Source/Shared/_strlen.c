#include "rtltypes.h"

size_t _strlen_a(const char *s)
{
	char *s0 = (char *)s;

	if ( s==0 )
		return 0;

	while ( *s!=0 )
		s++;

	return (s-s0);
}

size_t _strlen_w(const wchar_t *s)
{
	wchar_t *s0 = (wchar_t *)s;

	if ( s==0 )
		return 0;

	while ( *s!=0 )
		s++;

	return (s-s0);
}
