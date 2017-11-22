#include "rtltypes.h"

size_t u64tostr_a(unsigned long long x, char *s)
{
	unsigned long long	t = x;
	size_t	i, r=1;

	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if (s == 0)
		return r;
	
	for (i = r; i != 0; i--) {
		s[i-1] = (char)(x % 10) + '0';
		x /= 10;
	}

	s[r] = (char)0;
	return r;
}

size_t u64tostr_w(unsigned long long x, wchar_t *s)
{
	unsigned long long	t = x;
	size_t	i, r=1;

	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if (s == 0)
		return r;
	
	for (i = r; i != 0; i--) {
		s[i-1] = (wchar_t)(x % 10) + L'0';
		x /= 10;
	}

	s[r] = (wchar_t)0;
	return r;
}
