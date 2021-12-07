/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 50    Log file handling */

#include "squid.h"
#include "fatal.h"
#include "fd.h"
#include "fde.h"
#include "fs_io.h"
#include "globals.h"
#include "log/File.h"
#include "log/ModStdio.h"
#include "SquidConfig.h"

#include <cerrno>

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
    int xerrno = errno;
    fd_bytes(ll->fd, s, FD_WRITE);

    if (s == len)
        return;

    if (!lf->flags.fatal)
        return;

    fatalf("logfileWrite: %s: %s\n", lf->path, xstrerr(xerrno));
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
logfile_mod_stdio_linestart(Logfile *)
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
logfile_mod_stdio_rotate(Logfile * lf, const int16_t nRotate)
{
#ifdef S_ISREG

    struct stat sb;
#endif

    l_stdio_t *ll = (l_stdio_t *) lf->data;
    const char *realpath = lf->path+6; // skip 'stdio:' prefix.
    assert(realpath);

#ifdef S_ISREG

    if (stat(realpath, &sb) == 0)
        if (S_ISREG(sb.st_mode) == 0)
            return;

#endif

    debugs(0, DBG_IMPORTANT, "Rotate log file " << lf->path);

    SBuf basePath(realpath);

    /* Rotate numbers 0 through N up one */
    for (int16_t i = nRotate; i > 1;) {
        --i;
        SBuf from(basePath);
        from.appendf(".%d", i-1);
        SBuf to(basePath);
        to.appendf(".%d", i);
        FileRename(from, to);
        // TODO handle rename errors
    }

    /* Rotate the current log to .0 */
    logfileFlush(lf);

    file_close(ll->fd);     /* always close */

    if (nRotate > 0) {
        SBuf to(basePath);
        to.appendf(".0");
        FileRename(basePath, to);
        // TODO handle rename errors
    }
    /* Reopen the log.  It may have been renamed "manually" */
    ll->fd = file_open(realpath, O_WRONLY | O_CREAT | O_TEXT);

    if (DISK_ERROR == ll->fd && lf->flags.fatal) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << "ERROR: " << lf->path << ": " << xstrerr(xerrno));
        fatalf("Cannot open %s: %s", lf->path, xstrerr(xerrno));
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
        int xerrno = errno;
        if (ENOENT == xerrno && fatal_flag) {
            fatalf("Cannot open '%s' because\n"
                   "\tthe parent directory does not exist.\n"
                   "\tPlease create the directory.\n", path);
        } else if (EACCES == xerrno && fatal_flag) {
            fatalf("Cannot open '%s' for writing.\n"
                   "\tThe parent directory must be writeable by the\n"
                   "\tuser '%s', which is the cache_effective_user\n"
                   "\tset in squid.conf.", path, Config.effectiveUser);
        } else if (EISDIR == xerrno && fatal_flag) {
            fatalf("Cannot open '%s' because it is a directory, not a file.\n", path);
        } else {
            debugs(50, DBG_IMPORTANT, MYNAME << "ERROR: " << lf->path << ": " << xstrerr(xerrno));
            return 0;
        }
    }
    if (bufsz > 0) {
        ll->buf = static_cast<char*>(xmalloc(bufsz));
        ll->bufsz = bufsz;
    }
    return 1;
}

