#pragma once

#ifndef _FILENAMEH_
#define _FILENAMEH_

char *_filename_a(const char *f);
wchar_t *_filename_w(const wchar_t *f);
char *_fileext_a(const char *f);
wchar_t *_fileext_w(const wchar_t *f);
char *_filepath_a(const char *f);
wchar_t *_filepath_w(const wchar_t *f);

#ifdef UNICODE
#define _filename  _filename_w
#define _fileext   _fileext_w
#define _filepath  _filepath_w
#else // ANSI
#define _filename  _filename_a
#define _fileext   _fileext_a
#define _filepath  _filepath_a
#endif

#endif /* _CMDLINEH_ */