/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_COMPAT_XSTRERROR_H
#define _SQUID_COMPAT_XSTRERROR_H

#if HAVE_ERRNO_H
#include <errno.h>
#endif

/** Provide the textual display of a system error number.
 * A string is always returned.
 * Where strerror() would have provided NULL this will report the error as unknown.
 * On MS Windows the native Win32 errors are also translated.
 */
extern const char * xstrerr(int error);

#endif /* _SQUID_COMPAT_XSTRERROR_H */

