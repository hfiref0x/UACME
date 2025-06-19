#include "rtltypes.h"

size_t itostr_a(int x, char *s)
{
	int		t;
	size_t	i, r = 1, sign;

	t = x;

	if (x < 0) {
		sign = 1;
		while (t <= -10) {
			t /= 10;
			r++;
		}
	}
	else {
		sign = 0;
		while (t >= 10) {
			t /= 10;
			r++;
		}
	}

	if (s == 0)
		return r + sign;

	if (sign) {
		*s = '-';
		s++;
	}

	for (i = r; i != 0; i--) {
		s[i - 1] = (char)byteabs(x % 10) + '0';
		x /= 10;
	}

	s[r] = (char)0;
	return r + sign;
}


size_t itostr_w(int x, wchar_t *s)
{
	int		t;
	size_t	i, r = 1, sign;

	t = x;

	if (x < 0) {
		sign = 1;
		while (t <= -10) {
			t /= 10;
			r++;
		}
	}
	else {
		sign = 0;
		while (t >= 10) {
			t /= 10;
			r++;
		}
	}

	if (s == 0)
		return r + sign;

	if (sign) {
		*s = '-';
		s++;
	}

	for (i = r; i != 0; i--) {
		s[i - 1] = (wchar_t)byteabs(x % 10) + L'0';
		x /= 10;
	}

	s[r] = (wchar_t)0;
	return r + sign;
}
