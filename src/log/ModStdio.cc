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
#include "disk.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "log/File.h"
#include "log/ModStdio.h"
#include "SquidConfig.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif

typedef struct {
    int fd;
    char *buf;
    size_t bufsz;
    int offset;
} l_stdio_t;

/*
 * Aborts with fatal message if write() returns something other
 * than its length argument.
 */
static void
logfileWriteWrapper(Logfile * lf, const void *buf, size_t len)
{
    l_stdio_t *ll = (l_stdio_t *) lf->data;
    size_t s;
    s = FD_WRITE_METHOD(ll->fd, (char const *) buf, len);
    fd_bytes(ll->fd, s, FD_WRITE);

    if (s == len)
        return;

    if (!lf->flags.fatal)
        return;

    fatalf("logfileWrite: %s: %s\n", lf->path, xstrerror());
}

static void
logfile_mod_stdio_writeline(Logfile * lf, const char *buf, size_t len)
{
    l_stdio_t *ll = (l_stdio_t *) lf->data;

    if (0 == ll->bufsz) {
        /* buffering disabled */
        logfileWriteWrapper(lf, buf, len);
        return;
    }
    if (ll->offset > 0 && (ll->offset + len) > ll->bufsz)
        logfileFlush(lf);

    if (len > ll->bufsz) {
        /* too big to fit in buffer */
        logfileWriteWrapper(lf, buf, len);
        return;
    }
    /* buffer it */
    memcpy(ll->buf + ll->offset, buf, len);

    ll->offset += len;

    assert(ll->offset >= 0);

    assert((size_t) ll->offset <= ll->bufsz);
}

static void
logfile_mod_stdio_linestart(Logfile * lf)
{
}

static void
logfile_mod_stdio_lineend(Logfile * lf)
{
    lf->f_flush(lf);
}

static void
logfile_mod_stdio_flush(Logfile * lf)
{
    l_stdio_t *ll = (l_stdio_t *) lf->data;
    if (0 == ll->offset)
        return;
    logfileWriteWrapper(lf, ll->buf, (size_t) ll->offset);
    ll->offset = 0;
}

static void
logfile_mod_stdio_rotate(Logfile * lf)
{
#ifdef S_ISREG

    struct stat sb;
#endif

    int i;
    char from[MAXPATHLEN];
    char to[MAXPATHLEN];
    l_stdio_t *ll = (l_stdio_t *) lf->data;
    assert(lf->path);
    const char *realpath = lf->path+6; // skip 'stdio:' prefix.
    assert(realpath);

#ifdef S_ISREG

    if (stat(realpath, &sb) == 0)
        if (S_ISREG(sb.st_mode) == 0)
            return;

#endif

    debugs(0, DBG_IMPORTANT, "Rotate log file " << lf->path);

    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
        --i;
        snprintf(from, MAXPATHLEN, "%s.%d", realpath, i - 1);
        snprintf(to, MAXPATHLEN, "%s.%d", realpath, i);
        xrename(from, to);
    }

    /* Rotate the current log to .0 */
    logfileFlush(lf);

    file_close(ll->fd);		/* always close */

    if (Config.Log.rotateNumber > 0) {
        snprintf(to, MAXPATHLEN, "%s.%d", realpath, 0);
        xrename(realpath, to);
    }
    /* Reopen the log.  It may have been renamed "manually" */
    ll->fd = file_open(realpath, O_WRONLY | O_CREAT | O_TEXT);

    if (DISK_ERROR == ll->fd && lf->flags.fatal) {
        debugs(50, DBG_CRITICAL, "ERROR: logfileRotate: " << lf->path << ": " << xstrerror());
        fatalf("Cannot open %s: %s", lf->path, xstrerror());
    }
}

static void
logfile_mod_stdio_close(Logfile * lf)
{
    l_stdio_t *ll = (l_stdio_t *) lf->data;
    lf->f_flush(lf);

    if (ll->fd >= 0)
        file_close(ll->fd);

    if (ll->buf)
        xfree(ll->buf);

    xfree(lf->data);
    lf->data = NULL;
}

/*
 * This code expects the path to be a writable filename
 */
int
logfile_mod_stdio_open(Logfile * lf, const char *path, size_t bufsz, int fatal_flag)
{
    lf->f_close = logfile_mod_stdio_close;
    lf->f_linewrite = logfile_mod_stdio_writeline;
    lf->f_linestart = logfile_mod_stdio_linestart;
    lf->f_lineend = logfile_mod_stdio_lineend;
    lf->f_flush = logfile_mod_stdio_flush;
    lf->f_rotate = logfile_mod_stdio_rotate;

    l_stdio_t *ll = static_cast<l_stdio_t*>(xcalloc(1, sizeof(*ll)));
    lf->data = ll;

    ll->fd = file_open(path, O_WRONLY | O_CREAT | O_TEXT);

    if (DISK_ERROR == ll->fd) {
        if (ENOENT == errno && fatal_flag) {
            fatalf("Cannot open '%s' because\n"
                   "\tthe parent directory does not exist.\n"
                   "\tPlease create the directory.\n", path);
        } else if (EACCES == errno && fatal_flag) {
            fatalf("Cannot open '%s' for writing.\n"
                   "\tThe parent directory must be writeable by the\n"
                   "\tuser '%s', which is the cache_effective_user\n"
                   "\tset in squid.conf.", path, Config.effectiveUser);
        } else if (EISDIR == errno && fatal_flag) {
            fatalf("Cannot open '%s' because it is a directory, not a file.\n", path);
        } else {
            debugs(50, DBG_IMPORTANT, "ERROR: logfileOpen " << lf->path << ": " << xstrerror());
            return 0;
        }
    }
    if (bufsz > 0) {
        ll->buf = static_cast<char*>(xmalloc(bufsz));
        ll->bufsz = bufsz;
    }
    return 1;
}
