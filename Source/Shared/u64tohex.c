#include "rtltypes.h"

size_t u64tohex_a(unsigned long long x, char *s)
{
	char	p;
	size_t	c;

	if (s==0)
		return 16;

	for (c=0; c<16; c++) {
		p = (char)(x & 0xf);
		x >>= 4;

		if (p<10)
			p += '0';
		else
			p = 'A' + (p-10);

		s[15-c] = p;
	}

	s[16] = 0;
	return 16;
}

size_t u64tohex_w(unsigned long long x, wchar_t *s)
{
	wchar_t	p;
	size_t	c;

	if (s==0)
		return 16;

	for (c = 0; c<16; c++) {
		p = (wchar_t)(x & 0xf);
		x >>= 4;

		if (p<10)
			p += L'0';
		else
			p = L'A' + (p-10);

		s[15-c] = p;
	}

	s[16] = 0;
	return 16;
}
