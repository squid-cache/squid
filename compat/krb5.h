/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_KRB5_H
#define SQUID_COMPAT_KRB5_H

/*
 * The Kerberos library krb5.h header file has various major
 * bugs in some implementations:
 *
 * - MacOS marks as deprecated the POSIX compatible APIs.
 *   Apparently to encourage code to use their internal APIs.
 *
 * - Heimdal may lack the extern "C" syntax for building in C++
 *
 * This file exists to fix those issues the best we can and to
 * ensure the logic is identical in Squid code, Squid helpers,
 * and autoconf tests. See acinclude/krb5.h for the latter.
 */

#if HAVE_KRB5_H
#  if USE_APPLE_KRB5
#    define KERBEROS_APPLE_DEPRECATED(x)
#  endif
#  if HAVE_BROKEN_HEIMDAL_KRB5_H && defined(__cplusplus)
extern "C" {
#      include <krb5.h>
}
#  else
#    include <krb5.h>
#  endif
#endif /* HAVE_KRB5_H */

#endif /* SQUID_COMPAT_KRB5_H */
