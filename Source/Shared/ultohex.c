#include "rtltypes.h"

size_t ultohex_a(unsigned long x, char *s)
{
	char	p;
	size_t	c;

	if (s==0)
		return 8;

	for (c=0; c<8; c++) {
		p = (char)(x & 0xf);
		x >>= 4;

		if (p<10)
			p += '0';
		else
			p = 'A' + (p-10);

		s[7-c] = p;
	}

	s[8] = 0;
	return 8;
}

size_t ultohex_w(unsigned long x, wchar_t *s)
{
	wchar_t	p;
	size_t	c;

	if (s==0)
		return 8;

	for (c=0; c<8; c++) {
		p = (wchar_t)(x & 0xf);
		x >>= 4;

		if (p<10)
			p += L'0';
		else
			p = L'A' + (p-10);

		s[7-c] = p;
	}

	s[8] = 0;
	return 8;
}
