#pragma once

#ifndef _FILENAMEH_
#define _FILENAMEH_

char *_filename_a(const char *f);
wchar_t *_filename_w(const wchar_t *f);
char *_fileext_a(const char *f);
wchar_t *_fileext_w(const wchar_t *f);
char *_filename_noext_a(char *dest, const char *f);
wchar_t *_filename_noext_w(wchar_t *dest, const wchar_t *f);
char *_filepath_a(const char *fname, char *fpath);
wchar_t *_filepath_w(const wchar_t *fname, wchar_t *fpath);

#ifdef UNICODE
#define _filename  _filename_w
#define _fileext   _fileext_w
#define _filepath  _filepath_w
#define _filename_noext  _filename_noext_w
#else // ANSI
#define _filename  _filename_a
#define _fileext   _fileext_a
#define _filepath  _filepath_a
#define _filename_noext  _filename_noext_a
#endif

#endif /* _FILENAMEH_ */