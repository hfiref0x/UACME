/*
Module name:
	minirtl.h

Description:
	header for string handling and conversion routines

Date:
	1 Mar 2015
*/

#ifndef _MINIRTL_
#define _MINIRTL_

// string copy/concat/length

char *_strend_a(const char *s);
wchar_t *_strend_w(const wchar_t *s);

char *_strcpy_a(char *dest, const char *src);
wchar_t *_strcpy_w(wchar_t *dest, const wchar_t *src);

char *_strcat_a(char *dest, const char *src);
wchar_t *_strcat_w(wchar_t *dest, const wchar_t *src);

char *_strncpy_a(char *dest, size_t ccdest, const char *src, size_t ccsrc);
wchar_t *_strncpy_w(wchar_t *dest, size_t ccdest, const wchar_t *src, size_t ccsrc);

size_t _strlen_a(const char *s);
size_t _strlen_w(const wchar_t *s);

// comparing

int _strcmp_a(const char *s1, const char *s2);
int _strcmp_w(const wchar_t *s1, const wchar_t *s2);

int _strncmp_a(const char *s1, const char *s2, size_t cchars);
int _strncmp_w(const wchar_t *s1, const wchar_t *s2, size_t cchars);

int _strcmpi_a(const char *s1, const char *s2);
int _strcmpi_w(const wchar_t *s1, const wchar_t *s2);

int _strncmpi_a(const char *s1, const char *s2, size_t cchars);
int _strncmpi_w(const wchar_t *s1, const wchar_t *s2, size_t cchars);

char *_strstr_a(const char *s, const char *sub_s);
wchar_t *_strstr_w(const wchar_t *s, const wchar_t *sub_s);

char *_strstri_a(const char *s, const char *sub_s);
wchar_t *_strstri_w(const wchar_t *s, const wchar_t *sub_s);

// conversion of integer types to string, returning string length

size_t ultostr_a(unsigned long x, char *s);
size_t ultostr_w(unsigned long x, wchar_t *s);

size_t ultohex_a(unsigned long x, char *s);
size_t ultohex_w(unsigned long x, wchar_t *s);

size_t itostr_a(int x, char *s);
size_t itostr_w(int x, wchar_t *s);

size_t i64tostr_a(signed long long x, char *s);
size_t i64tostr_w(signed long long x, wchar_t *s);

size_t u64tostr_a(unsigned long long x, char *s);
size_t u64tostr_w(unsigned long long x, wchar_t *s);

size_t u64tohex_a(unsigned long long x, char *s);
size_t u64tohex_w(unsigned long long x, wchar_t *s);

// string to integers conversion

unsigned long strtoul_a(char *s);
unsigned long strtoul_w(wchar_t *s);

unsigned long long strtou64_a(char *s);
unsigned long long strtou64_w(wchar_t *s);

unsigned long hextoul_a(char *s);
unsigned long hextoul_w(wchar_t *s);

int strtoi_a(char *s);
int strtoi_w(wchar_t *s);

signed long long strtoi64_a(char *s);
signed long long strtoi64_w(wchar_t *s);

unsigned long long hextou64_a(char *s);
unsigned long long hextou64_w(wchar_t *s);

/* =================================== */

#ifdef UNICODE

#define _strend _strend_w
#define _strcpy _strcpy_w
#define _strcat _strcat_w
#define _strlen _strlen_w
#define _strncpy _strncpy_w

#define _strcmp _strcmp_w
#define _strncmp _strncmp_w
#define _strcmpi _strcmpi_w
#define _strncmpi _strncmpi_w
#define _strstr _strstr_w
#define _strstri _strstri_w

#define ultostr ultostr_w
#define ultohex ultohex_w
#define itostr itostr_w
#define i64tostr i64tostr_w
#define u64tostr u64tostr_w
#define u64tohex u64tohex_w

#define strtoul strtoul_w
#define hextoul hextoul_w
#define strtoi strtoi_w
#define strtoi64 strtoi64_w
#define strtou64 strtou64_w
#define hextou64 hextou64_w

#else // ANSI

#define _strend _strend_a
#define _strcpy _strcpy_a
#define _strcat _strcat_a
#define _strlen _strlen_a
#define _strncpy _strncpy_a
#define _strcmp _strcmp_a

#define _strcmp _strcmp_a
#define _strncmp _strncmp_a
#define _strcmpi _strcmpi_a
#define _strncmpi _strncmpi_a
#define _strstr _strstr_a
#define _strstri _strstri_a

#define ultostr ultostr_a
#define ultohex ultohex_a
#define itostr itostr_a
#define i64tostr i64tostr_a
#define u64tostr u64tostr_a
#define u64tohex u64tohex_a

#define strtoul strtoul_a
#define hextoul hextoul_a
#define strtoi strtoi_a
#define strtoi64 strtoi64_a
#define strtou64 strtou64_a
#define hextou64 hextou64_a

#endif

#endif /* _MINIRTL_ */
