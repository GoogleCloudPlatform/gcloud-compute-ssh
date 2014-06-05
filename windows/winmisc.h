/*
 * winmisc.h: Windows-specific post-include workarounds
 */

#ifndef PUTTY_WINMISC_H
#define PUTTY_WINMISC_H

#if defined _WIN64

/*
 * the problem:
 *    sizeof(int) < sizeof(size_t)
 *    sizeof(int) < sizeof((char*)a - (char*)b) // ptrdiff_t
 *    strlen() and friends return size_t or ssize_t instead of int
 * the fix:
 *    use { ptrdiff_t size_t ssize_t } where appropriate
 * the workaround:
 *    include headers that prototype the functions in scope
 *    add (int) casts with function-like-macros
 *    manually add (int) casts on pointer difference results
 */

#include <stdio.h>
#include <time.h>

#define fread(b,n,z,f)		(int)fread(b,n,z,f)
#define strftime(b,z,f,t)	(int)strftime(b,z,f,t)
#define strcspn(s,q)		(int)strcspn(s,q)
#define strlen(s)		(int)strlen(s)
#define strspn(s,q)		(int)strspn(s,q)
#define toint(u)		toint((unsigned)(u))

#endif /*_WIN64*/

#define sscanf		sscanf_s
#define stricmp		_stricmp
#define strncpy(d,s,n)	strncpy_s(d,n,s,n)
#define strnicmp	_strnicmp

#endif /*PUTTY_WINMISC_H*/
