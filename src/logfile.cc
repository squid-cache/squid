/*
 * $Id: logfile.cc,v 1.1 2000/03/14 23:02:18 wessels Exp $
 */

#include "squid.h"

static void logfileWriteWrapper(Logfile * lf, const void *buf, size_t len);

Logfile *
logfileOpen(const char *path, size_t bufsz)
{
    int fd;
    Logfile *lf;
    fd = file_open(path, O_WRONLY | O_CREAT);
    if (DISK_ERROR == fd) {
	if (ENOENT == errno) {
	    fatalf("Cannot open '%s' because\n"
		"\tthe parent directory does not exist.\n"
		"\tPlease create the directory.\n", path);
	} else if (EACCES == errno) {
	    fatalf("Cannot open '%s' for writing.\n"
		"\tThe parent directory must be writeable by the\n"
		"\tuser '%s', which is the cache_effective_user\n"
		"\tset in squid.conf.", path, Config.effectiveUser);
	} else {
	    debug(50, 1) ("logfileOpen: %s: %s\n", path, xstrerror());
	    return NULL;
	}
    }
    lf = xcalloc(1, sizeof(*lf));
    lf->fd = fd;
    xstrncpy(lf->path, path, MAXPATHLEN);
    if (bufsz > 0) {
	lf->buf = xmalloc(bufsz);
	lf->bufsz = bufsz;
    }
    return lf;
}

void
logfileClose(Logfile * lf)
{
    logfileFlush(lf);
    file_close(lf->fd);
    if (lf->buf)
	xfree(lf->buf);
    xfree(lf);
}

void
logfileRotate(Logfile * lf)
{
    struct stat sb;
    int i;
    char from[MAXPATHLEN];
    char to[MAXPATHLEN];
    assert(lf->path);
#ifdef S_ISREG
    if (stat(lf->path, &sb) == 0)
	if (S_ISREG(sb.st_mode) == 0)
	    return;
#endif
    debug(0, 1) ("logfileRotate: %s\n", lf->path);
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
    lf->fd = file_open(lf->path, O_WRONLY | O_CREAT);
    if (DISK_ERROR == lf->fd) {
	debug(50, 1) ("logfileRotate: %s: %s\n", lf->path, xstrerror());
	fatalf("Cannot open %s: %s", lf->path, xstrerror());
    }
}

void
logfileWrite(Logfile * lf, void *buf, size_t len)
{
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
    }
    /* buffer it */
    xmemcpy(lf->buf + lf->offset, buf, len);
    lf->offset += len;
    assert(lf->offset <= lf->bufsz);
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
    int s;
    s = write(lf->fd, buf, len);
    if (s == len)
	return;
    fatalf("logfileWrite: %s: %s\n", lf->path, xstrerror());
}
