/*
 * $Id: logfile.cc,v 1.24 2007/08/21 23:50:12 hno Exp $
 *
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
#include "authenticate.h"
#include "fde.h"

static void logfileWriteWrapper(Logfile * lf, const void *buf, size_t len);

#if HAVE_SYSLOG

/* Define LOG_AUTHPRIV as LOG_AUTH on systems still using the old deprecated LOG_AUTH */
#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

struct syslog_symbol_t
{
    const char* name;
    int value;
};

static int syslog_ntoa (const char* s)
{
#define syslog_symbol(a) #a, a
    static syslog_symbol_t _symbols[] = {
                                            { syslog_symbol(LOG_AUTHPRIV) },
                                            { syslog_symbol(LOG_DAEMON) },
                                            { syslog_symbol(LOG_LOCAL0) },
                                            { syslog_symbol(LOG_LOCAL1) },
                                            { syslog_symbol(LOG_LOCAL2) },
                                            { syslog_symbol(LOG_LOCAL3) },
                                            { syslog_symbol(LOG_LOCAL4) },
                                            { syslog_symbol(LOG_LOCAL5) },
                                            { syslog_symbol(LOG_LOCAL6) },
                                            { syslog_symbol(LOG_LOCAL7) },
                                            { syslog_symbol(LOG_USER) },
                                            { syslog_symbol(LOG_ERR) },
                                            { syslog_symbol(LOG_WARNING) },
                                            { syslog_symbol(LOG_NOTICE) },
                                            { syslog_symbol(LOG_INFO) },
                                            { syslog_symbol(LOG_DEBUG) },
                                            { NULL, 0 }
                                        };

    for (syslog_symbol_t* p = _symbols; p->name != NULL; ++p)
        if (!strcmp(s, p->name) || !strcasecmp(s, p->name+4))
            return p->value;

    debugs(1, 1, "Unknown syslog facility/priority '" << s << "'");

    return 0;
}

#define PRIORITY_MASK (LOG_ERR | LOG_WARNING | LOG_NOTICE | LOG_INFO | LOG_DEBUG)
#endif
Logfile *
logfileOpen(const char *path, size_t bufsz, int fatal_flag)
{
    int fd;
    Logfile *lf = static_cast<Logfile *>(xcalloc(1, sizeof(*lf)));

    xstrncpy(lf->path, path, MAXPATHLEN);

#if HAVE_SYSLOG

    if (strncmp(path, "syslog", 6) == 0) {
        lf->flags.syslog = 1;
        lf->syslog_priority = LOG_INFO;
        lf->fd = -1;

        if (path[6] != '\0') {
            path += 7;
            char* delim = strchr(path, '.');

	    if (!delim)
		delim = strchr(path, '|');

            if (delim != NULL)
                *delim = '\0';

            lf->syslog_priority = syslog_ntoa(path);

            if (delim != NULL)
                lf->syslog_priority |= syslog_ntoa(delim+1);

            if (0 == lf->syslog_priority & PRIORITY_MASK)
                lf->syslog_priority |= LOG_INFO;
        }
    } else
#endif
    {
        fd = file_open(path, O_WRONLY | O_CREAT | O_TEXT);

        if (DISK_ERROR == fd) {
            if (ENOENT == errno && fatal_flag) {
                fatalf("Cannot open '%s' because\n"
                       "\tthe parent directory does not exist.\n"
                       "\tPlease create the directory.\n", path);
            } else if (EACCES == errno && fatal_flag) {
                fatalf("Cannot open '%s' for writing.\n"
                       "\tThe parent directory must be writeable by the\n"
                       "\tuser '%s', which is the cache_effective_user\n"
                       "\tset in squid.conf.", path, Config.effectiveUser);
            } else {
                debugs(50, 1, "logfileOpen: " << path << ": " << xstrerror());
                return NULL;
            }
        }

        lf->fd = fd;

        if (bufsz > 0) {
            lf->buf = (char *) xmalloc(bufsz);
            lf->bufsz = bufsz;
        }
    }

    if (fatal_flag)
        lf->flags.fatal = 1;

    return lf;
}

void
logfileClose(Logfile * lf)
{
    logfileFlush(lf);

    if (lf->fd >= 0)
        file_close(lf->fd);

    if (lf->buf)
        xfree(lf->buf);

    xfree(lf);
}

void
logfileRotate(Logfile * lf)
{
#ifdef S_ISREG

    struct stat sb;
#endif

    int i;
    char from[MAXPATHLEN];
    char to[MAXPATHLEN];
    assert(lf->path);

    if (lf->flags.syslog)
        return;

#ifdef S_ISREG

    if (stat(lf->path, &sb) == 0)
        if (S_ISREG(sb.st_mode) == 0)
            return;

#endif

    debugs(0, 1, "logfileRotate: " << lf->path);

    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
        i--;
        snprintf(from, MAXPATHLEN, "%s.%d", lf->path, i - 1);
        snprintf(to, MAXPATHLEN, "%s.%d", lf->path, i);
        xrename(from, to);
    }

    /* Rotate the current log to .0 */
    logfileFlush(lf);

    file_close(lf->fd);		/* always close */

    if (Config.Log.rotateNumber > 0) {
        snprintf(to, MAXPATHLEN, "%s.%d", lf->path, 0);
        xrename(lf->path, to);
    }

    /* Reopen the log.  It may have been renamed "manually" */
    lf->fd = file_open(lf->path, O_WRONLY | O_CREAT | O_TEXT);

    if (DISK_ERROR == lf->fd && lf->flags.fatal) {
        debugs(50, 1, "logfileRotate: " << lf->path << ": " << xstrerror());
        fatalf("Cannot open %s: %s", lf->path, xstrerror());
    }
}

void
logfileWrite(Logfile * lf, void *buf, size_t len)
{
#if HAVE_SYSLOG

    if (lf->flags.syslog) {
        syslog(lf->syslog_priority, "%s", (char *)buf);
        return;
    }

#endif

    if (0 == lf->bufsz) {
        /* buffering disabled */
        logfileWriteWrapper(lf, buf, len);
        return;
    }

    if (lf->offset > 0 && lf->offset + len > lf->bufsz)
        logfileFlush(lf);

    if (len > lf->bufsz) {
        /* too big to fit in buffer */
        logfileWriteWrapper(lf, buf, len);
        return;
    }

    /* buffer it */
    xmemcpy(lf->buf + lf->offset, buf, len);

    lf->offset += len;

    assert (lf->offset >= 0);

    assert((size_t)lf->offset <= lf->bufsz);
}

void
#if STDC_HEADERS
logfilePrintf(Logfile * lf, const char *fmt,...)
#else
logfilePrintf(va_alist)
va_dcl
#endif
{
    va_list args;
    char buf[8192];
    int s;
#if STDC_HEADERS

    va_start(args, fmt);
#else

    Logfile *lf;
    const char *fmt;
    va_start(args);
    lf = va_arg(args, Logfile *);
    fmt = va_arg(args, char *);
#endif

    s = vsnprintf(buf, 8192, fmt, args);

    if (s > 8192) {
        s = 8192;

        if (fmt[strlen(fmt) - 1] == '\n')
            buf[8191] = '\n';
    }

    logfileWrite(lf, buf, (size_t) s);
    va_end(args);
}

void
logfileFlush(Logfile * lf)
{
    if (0 == lf->offset)
        return;

    logfileWriteWrapper(lf, lf->buf, (size_t) lf->offset);

    lf->offset = 0;
}

/*
 * Aborts with fatal message if write() returns something other
 * than its length argument.
 */
static void
logfileWriteWrapper(Logfile * lf, const void *buf, size_t len)
{
    size_t s;
    s = FD_WRITE_METHOD(lf->fd, (char const *)buf, len);
    fd_bytes(lf->fd, s, FD_WRITE);

    if (s == len)
        return;

    if (!lf->flags.fatal)
        return;

    fatalf("logfileWrite: %s: %s\n", lf->path, xstrerror());
}
