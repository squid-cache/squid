/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
 * - Solaris incorrectly implements its own the extern "C" replacement
 *   macros and as a result krb5.h contains a trailing '}'.
 *   see http://bugs.opensolaris.org/bugdatabase/view_bug.do?bug_id=6837512
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
#  elif HAVE_BROKEN_SOLARIS_KRB5_H && defined(__cplusplus)
#    define KRB5INT_BEGIN_DECLS extern "C" {
#    define KRB5INT_END_DECLS
extern "C" {
#      include <krb5.h>
    /* broken Solaris krb5.h contains the closing } */
#  else
#    include <krb5.h>
#  endif
#endif /* HAVE_KRB5_H */

#endif /* SQUID_COMPAT_KRB5_H */
