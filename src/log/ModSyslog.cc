/*
 * DEBUG: section 50    Log file handling
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "Debug.h"

#if HAVE_SYSLOG

#include "log/File.h"
#include "log/ModSyslog.h"

/* Define LOG_AUTHPRIV as LOG_AUTH on systems still using the old deprecated LOG_AUTH */
#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

typedef struct {
    const char *name;
    int value;
} syslog_symbol_t;

static int
syslog_ntoa(const char *s)
{
#define syslog_symbol(a) #a, a
    static syslog_symbol_t symbols[] = {
#ifdef LOG_AUTHPRIV
        {syslog_symbol(LOG_AUTHPRIV)},
#endif
#ifdef LOG_DAEMON
        {syslog_symbol(LOG_DAEMON)},
#endif
#ifdef LOG_LOCAL0
        {syslog_symbol(LOG_LOCAL0)},
#endif
#ifdef LOG_LOCAL1
        {syslog_symbol(LOG_LOCAL1)},
#endif
#ifdef LOG_LOCAL2
        {syslog_symbol(LOG_LOCAL2)},
#endif
#ifdef LOG_LOCAL3
        {syslog_symbol(LOG_LOCAL3)},
#endif
#ifdef LOG_LOCAL4
        {syslog_symbol(LOG_LOCAL4)},
#endif
#ifdef LOG_LOCAL5
        {syslog_symbol(LOG_LOCAL5)},
#endif
#ifdef LOG_LOCAL6
        {syslog_symbol(LOG_LOCAL6)},
#endif
#ifdef LOG_LOCAL7
        {syslog_symbol(LOG_LOCAL7)},
#endif
#ifdef LOG_USER
        {syslog_symbol(LOG_USER)},
#endif
#ifdef LOG_ERR
        {syslog_symbol(LOG_ERR)},
#endif
#ifdef LOG_WARNING
        {syslog_symbol(LOG_WARNING)},
#endif
#ifdef LOG_NOTICE
        {syslog_symbol(LOG_NOTICE)},
#endif
#ifdef LOG_INFO
        {syslog_symbol(LOG_INFO)},
#endif
#ifdef LOG_DEBUG
        {syslog_symbol(LOG_DEBUG)},
#endif
        {NULL, 0}
    };
    syslog_symbol_t *p;

    for (p = symbols; p->name != NULL; ++p)
        if (!strcmp(s, p->name) || !strcasecmp(s, p->name + 4))
            return p->value;

    debugs(1, DBG_IMPORTANT, "Unknown syslog facility/priority '" << s << "'");
    return 0;
}

typedef struct {
    int syslog_priority;
} l_syslog_t;

#define PRIORITY_MASK (LOG_ERR | LOG_WARNING | LOG_NOTICE | LOG_INFO | LOG_DEBUG)

static void
logfile_mod_syslog_writeline(Logfile * lf, const char *buf, size_t len)
{
    l_syslog_t *ll = (l_syslog_t *) lf->data;
    syslog(ll->syslog_priority, "%s", (char *) buf);
}

static void
logfile_mod_syslog_linestart(Logfile * lf)
{
}

static void
logfile_mod_syslog_lineend(Logfile * lf)
{
}

static void
logfile_mod_syslog_flush(Logfile * lf)
{
}

static void
logfile_mod_syslog_rotate(Logfile * lf)
{
}

static void
logfile_mod_syslog_close(Logfile * lf)
{
    xfree(lf->data);
    lf->data = NULL;
}

/*
 * This code expects the path to be syslog:<priority>
 */
int
logfile_mod_syslog_open(Logfile * lf, const char *path, size_t bufsz, int fatal_flag)
{
    lf->f_close = logfile_mod_syslog_close;
    lf->f_linewrite = logfile_mod_syslog_writeline;
    lf->f_linestart = logfile_mod_syslog_linestart;
    lf->f_lineend = logfile_mod_syslog_lineend;
    lf->f_flush = logfile_mod_syslog_flush;
    lf->f_rotate = logfile_mod_syslog_rotate;

    l_syslog_t *ll = static_cast<l_syslog_t*>(xcalloc(1, sizeof(*ll)));
    lf->data = ll;

    ll->syslog_priority = LOG_INFO;

    if (path[6] != '\0') {
        char *priority = xstrdup(path);
        char *facility = (char *) strchr(priority, '.');
        if (!facility)
            facility = (char *) strchr(priority, '|');
        if (facility) {
            *facility = '\0';
            ++facility;
            ll->syslog_priority |= syslog_ntoa(facility);
        }
        ll->syslog_priority |= syslog_ntoa(priority);
        xfree(priority);
        if ((ll->syslog_priority & PRIORITY_MASK) == 0)
            ll->syslog_priority |= LOG_INFO;
    }

    return 1;
}
#endif
