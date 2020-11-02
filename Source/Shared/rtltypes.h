#pragma once

#ifndef _WCHAR_T_DEFINED
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif  /* _WCHAR_T_DEFINED */

#ifndef _SIZE_T_DEFINED
#ifdef _WIN64
typedef unsigned __int64    size_t;
#else  /* _WIN64 */
typedef __w64 unsigned int   size_t;
#endif  /* _WIN64 */
#define _SIZE_T_DEFINED
#endif  /* _SIZE_T_DEFINED */

__forceinline char locase_a(char c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}

__forceinline wchar_t locase_w(wchar_t c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}

__forceinline char byteabs(char x) {
	if (x < 0)
		return -x;
	return x;
}

__forceinline int _isdigit_a(char x) {
	return ((x >= '0') && (x <= '9'));
}

__forceinline int _isdigit_w(wchar_t x) {
	return ((x >= L'0') && (x <= L'9'));
}
