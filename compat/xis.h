#ifndef _SQUID_COMPAT_XIS_H
#define _SQUID_COMPAT_XIS_H

#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#define xisspace(x) isspace((unsigned char)x)
#define xtoupper(x) toupper((unsigned char)x)
#define xtolower(x) tolower((unsigned char)x)
#define xisdigit(x) isdigit((unsigned char)x)
#define xisascii(x) isascii((unsigned char)x)
#define xislower(x) islower((unsigned char)x)
#define xisalpha(x) isalpha((unsigned char)x)
#define xisprint(x) isprint((unsigned char)x)
#define xisalnum(x) isalnum((unsigned char)x)
#define xiscntrl(x) iscntrl((unsigned char)x)
#define xispunct(x) ispunct((unsigned char)x)
#define xisupper(x) isupper((unsigned char)x)
#define xisxdigit(x) isxdigit((unsigned char)x)
#define xisgraph(x) isgraph((unsigned char)x)

#endif /* _SQUID_COMPAT_XIS_H */
