#include "rtltypes.h"

int strtoi_a(char *s)
{
	int		a = 0, sign;
	char	c;

	if (s == 0)
		return 0;

	switch (*s) {
	case '-':
		s++;
		sign = -1;
		break;

	case '+':
		s++;
		sign = 1;
		break;

	default:
		sign = 1;
	}

	while (*s != 0) {
		c = *s;
		if (_isdigit_a(c))
			a = (a*10) + (c-'0');
		else
			break;
		s++;
	}
	return a*sign;
}

int strtoi_w(wchar_t *s)
{
	int			a = 0, sign;
	wchar_t		c;

	if (s == 0)
		return 0;

	switch (*s) {
	case L'-':
		s++;
		sign = -1;
		break;

	case L'+':
		s++;
		sign = 1;
		break;

	default:
		sign = 1;
	}

	while (*s != 0) {
		c = *s;
		if (_isdigit_w(c))
			a = (a*10)+(c-L'0');
		else
			break;
		s++;
	}
	return a*sign;
}
