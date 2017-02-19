#include "rtltypes.h"

char *_strstri_a(const char *s, const char *sub_s)
{
	char c0, c1, c2, *tmps, *tmpsub;

	if (s == sub_s)
		return (char *)s;

	if (s == 0)
		return 0;

	if (sub_s == 0)
		return 0;

	c0 = locase_a(*sub_s);
	while (c0 != 0) {

		while (*s != 0) {
			c2 = locase_a(*s);
			if (c2 == c0)
				break;
			s++;
		}

		if (*s == 0)
			return 0;

		tmps = (char *)s;
		tmpsub = (char *)sub_s;
		do {
			c1 = locase_a(*tmps);
			c2 = locase_a(*tmpsub);
			tmps++;
			tmpsub++;
		} while ((c1 == c2) && (c2 != 0));

		if (c2 == 0)
			return (char *)s;

		s++;
	}
	return 0;
}

wchar_t *_strstri_w(const wchar_t *s, const wchar_t *sub_s)
{
	wchar_t c0, c1, c2, *tmps, *tmpsub;

	if (s == sub_s)
		return (wchar_t *)s;

	if (s == 0)
		return 0;

	if (sub_s == 0)
		return 0;

	c0 = locase_w(*sub_s);
	while (c0 != 0) {

		while (*s != 0) {
			c2 = locase_w(*s);
			if (c2 == c0)
				break;
			s++;
		}

		if (*s == 0)
			return 0;

		tmps = (wchar_t *)s;
		tmpsub = (wchar_t *)sub_s;
		do {
			c1 = locase_w(*tmps);
			c2 = locase_w(*tmpsub);
			tmps++;
			tmpsub++;
		} while ((c1 == c2) && (c2 != 0));

		if (c2 == 0)
			return (wchar_t *)s;

		s++;
	}
	return 0;
}
