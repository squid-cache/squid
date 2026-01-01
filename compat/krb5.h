/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_KRB5_H
#define SQUID_COMPAT_KRB5_H

/*
 * The Kerberos library has various major bugs.
 *
 * - MacOS marks as deprecated the POSIX compatible APIs.
 *   Apparently to encourage code to use their internal APIs.
 *
 * This file exists to fix those issues the best we can and to
 * ensure the logic is identical in Squid code, Squid helpers,
 * and autoconf tests. See acinclude/krb5.h for the latter.
 */

#if HAVE_KRB5_H
#  if USE_APPLE_KRB5
#    define KERBEROS_APPLE_DEPRECATED(x)
#  endif
#include <krb5.h>
#endif /* HAVE_KRB5_H */

#endif /* SQUID_COMPAT_KRB5_H */
