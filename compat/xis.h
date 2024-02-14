/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_XIS_H
#define SQUID_COMPAT_XIS_H

#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#if __cplusplus
#define xisspace(x) isspace(static_cast<unsigned char>(x))
#define xtoupper(x) toupper(static_cast<unsigned char>(x))
#define xtolower(x) tolower(static_cast<unsigned char>(x))
#define xisdigit(x) isdigit(static_cast<unsigned char>(x))
#define xisascii(x) isascii(static_cast<unsigned char>(x))
#define xislower(x) islower(static_cast<unsigned char>(x))
#define xisalpha(x) isalpha(static_cast<unsigned char>(x))
#define xisprint(x) isprint(static_cast<unsigned char>(x))
#define xisalnum(x) isalnum(static_cast<unsigned char>(x))
#define xiscntrl(x) iscntrl(static_cast<unsigned char>(x))
#define xispunct(x) ispunct(static_cast<unsigned char>(x))
#define xisupper(x) isupper(static_cast<unsigned char>(x))
#define xisxdigit(x) isxdigit(static_cast<unsigned char>(x))
#define xisgraph(x) isgraph(static_cast<unsigned char>(x))

#else /* ! __cplusplus */
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
#endif

#endif /* SQUID_COMPAT_XIS_H */

