
/*
 * $Id: refresh.cc,v 1.2 1996/10/28 07:44:25 wessels Exp $
 *
 * DEBUG: section 22    Refresh Calculation
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX		/* put before includes; always use POSIX */
#endif

#include "squid.h"

/*
 * Defaults:
 *      MIN     NONE
 *      PCT     20%
 *      MAX     3 days
 */
#define REFRESH_DEFAULT_MIN	0
#define REFRESH_DEFAULT_PCT	20
#define REFRESH_DEFAULT_MAX	259200

typedef struct _refresh_t {
    char *pattern;
    regex_t compiled_pattern;
    time_t min;
    int pct;
    time_t max;
    struct _refresh_t *next;
} refresh_t;

static refresh_t *Refresh_tbl = NULL;
static refresh_t *Refresh_tail = NULL;

static void
refreshFreeList(refresh_t * t)
{
    refresh_t *tnext;

    for (; t; t = tnext) {
	tnext = t->next;
	safe_free(t->pattern);
	regfree(&t->compiled_pattern);
	safe_free(t);
    }
}

void
refreshFreeMemory(void)
{
    refreshFreeList(Refresh_tbl);
    Refresh_tail = Refresh_tbl = NULL;
}

void
refreshAddToList(char *pattern, int opts, time_t min, int pct, time_t max)
{
    refresh_t *t;
    regex_t comp;
    int flags = REG_EXTENDED;
    if (opts & REFRESH_ICASE)
	flags |= REG_ICASE;
    if (regcomp(&comp, pattern, flags) != REG_NOERROR) {
	debug(22, 0, "refreshAddToList: Invalid regular expression: %s\n",
	    pattern);
	return;
    }
    pct = pct < 0 ? 0 : pct;
    max = max < 0 ? 0 : max;
    t = xcalloc(1, sizeof(refresh_t));
    t->pattern = (char *) xstrdup(pattern);
    t->compiled_pattern = comp;
    t->min = min;
    t->pct = pct;
    t->max = max;
    t->next = NULL;
    if (!Refresh_tbl)
	Refresh_tbl = t;
    if (Refresh_tail)
	Refresh_tail->next = t;
    Refresh_tail = t;
}

/*
 * refreshCheck():
 *     return 1 if its time to revalidate this entry, 0 otherwise
 */
int
refreshCheck(StoreEntry * entry, request_t * request_unused)
{
    refresh_t *R;
    time_t min = REFRESH_DEFAULT_MIN;
    int pct = REFRESH_DEFAULT_PCT;
    time_t max = REFRESH_DEFAULT_MAX;
    char *pattern = ".";
    time_t age;
    int factor;
    debug(22, 3, "refreshCheck: '%s'\n", entry->url);
    for (R = Refresh_tbl; R; R = R->next) {
	if (regexec(&(R->compiled_pattern), entry->url, 0, 0, 0) != 0)
	    continue;
	min = R->min;
	pct = R->pct;
	max = R->max;
	pattern = R->pattern;
	break;
    }
    debug(22, 3, "refreshCheck: Matched '%s %d %d%% %d'\n",
	pattern, (int) min, pct, (int) max);
    age = squid_curtime - entry->timestamp;
    debug(22, 3, "refreshCheck: age = %d\n", (int) age);
    if (age <= min) {
	debug(22, 3, "refreshCheck: NO: age < min\n");
	return 0;
    }
    if (-1 < entry->expires && entry->expires <= squid_curtime) {
	debug(22, 3, "refreshCheck: YES: expires <= curtime\n");
	return 1;
    }
    if (age > max) {
	debug(22, 3, "refreshCheck: YES: age > max\n");
	return 1;
    }
    if (entry->timestamp <= entry->lastmod) {
	debug(22, 3, "refreshCheck: YES: lastvalid <= lastmod\n");
	return 1;
    }
    factor = 100 * age / (entry->timestamp - entry->lastmod);
    debug(22, 3, "refreshCheck: factor = %d\n", factor);
    if (factor > pct) {
	debug(22, 3, "refreshCheck: YES: factor > pc\n");
	return 1;
    }
    return 0;
}
