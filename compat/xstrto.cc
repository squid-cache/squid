/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_XSTRTO_C_
#define SQUID_XSTRTO_C_

/*
 *  Shamelessly duplicated from the netfilter iptables sources
 *  for use by the Squid Project under GNU Public License.
 *
 * Reason for use as explained by Luciano Coelho:
 * "I found that there is a bug in strtoul (and strtoull for
 * that matter) that causes the long to overflow if there are valid digits
 * after the maximum possible digits for the base.  For example if you try
 * to strtoul 0xfffffffff (with 9 f's) the strtoul will overflow and come
 * up with a bogus result.  I can't easily truncate the string to avoid
 * this problem, because with decimal or octal, the same valid value would
 * take more spaces.  I could do some magic here, checking whether it's a
 * hex, dec or oct and truncate appropriately, but that would be very ugly.
 * So the simplest way I came up with was to use strtoull and return
 * -EINVAL if the value exceeds 32 bits."
 *
 * Update/Maintenance History:
 *
 *    12-Sep-2010 : Copied from iptables xtables.c
 *          - xtables_strtoui renamed to xstrtoui
 *          - xtables_strtoul renamed to xstrtoul
 *
 *  Original License and code follows.
 */

#include "squid.h"
#include "compat/xstrto.h"

/*
 * (C) 2000-2006 by the netfilter coreteam <coreteam@netfilter.org>:
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <cerrno>

bool
xstrtoul(const char *s, char **end, unsigned long *value,
         unsigned long min, unsigned long max)
{
    char *my_end = NULL;

    errno = 0;
    unsigned long v = strtoul(s, &my_end, 0);

    if (my_end == s)
        return false;
    if (end != NULL)
        *end = my_end;

    if (errno != ERANGE && min <= v && (max == 0 || v <= max)) {
        if (value != NULL)
            *value = v;
        if (end == NULL)
            return *my_end == '\0';
        return true;
    }

    return false;
}

bool
xstrtoui(const char *s, char **end, unsigned int *value,
         unsigned int min, unsigned int max)
{
    unsigned long v = 0;
    bool ret = xstrtoul(s, end, &v, min, max);
    if (value != NULL) {
        *value = v;

        if (v != static_cast<unsigned long>(*value)) {
            return false;
        }
    }

    return ret;
}

#endif /* SQUID_XSTRTO_C_ */

