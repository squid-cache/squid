/* Copyright (C) 2004 Free Software Foundation, Inc.
 * Written by Yoann Vandoorselaere <yoann@prelude-ids.org>
 *
 * The file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 */
#ifndef GNULIB_STRSEP_H_
#define GNULIB_STRSEP_H_

#include "config.h"

#if HAVE_STRSEP

/*
 * Get strsep() declaration.
 */
#if HAVE_STRING_H
#include <string.h>
#endif

#else

/**
\par
Searches the next delimiter (char listed in DELIM) starting at *STRINGP.
If one is found, it is overwritten with a NULL, and *STRINGP is advanced
to point to the next char after it.  Otherwise, *STRINGP is set to NULL.
If *STRINGP was already NULL, nothing happens.
Returns the old value of *STRINGP.
\par
This is a variant of strtok() that is multithread-safe and supports
empty fields.

\note   Caveat: It modifies the original string.
\note   Caveat: These functions cannot be used on constant strings.
\note   Caveat: The identity of the delimiting character is lost.
\note   Caveat: It doesn't work with multibyte strings unless all of the delimiter
characters are ASCII characters < 0x30.

See also strtok_r().
*/
SQUIDCEXTERN char *strsep(char **stringp, const char *delim);

#endif /* HAVE_STRSEP */

#endif /* GNULIB_STRSEP_H_ */
