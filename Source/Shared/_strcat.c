#include "rtltypes.h"

char *_strcat_a(char *dest, const char *src)
{
	if ( (dest==0) || (src==0) )
		return dest;

	while ( *dest!=0 )
		dest++;

	while ( *src!=0 ) {
		*dest = *src;
		dest++;
		src++;
	} 

	*dest = 0;
	return dest;
}

wchar_t *_strcat_w(wchar_t *dest, const wchar_t *src)
{
	if ( (dest==0) || (src==0) )
		return dest;

	while ( *dest!=0 )
		dest++;

	while ( *src!=0 ) {
		*dest = *src;
		dest++;
		src++;
	} 

	*dest = 0;
	return dest;
}
