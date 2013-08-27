/*
 * DEBUG: section 50    Log file handling
 * AUTHOR: Adrian Chadd
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
#include "comm.h"
#include "comm/Connection.h"
#include "disk.h"
#include "fd.h"
#include "log/File.h"
#include "log/ModUdp.h"
#include "Parsing.h"
#include "SquidConfig.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif

/*
 * This logfile UDP module is mostly inspired by a patch by Tim Starling
 * from Wikimedia.
 *
 * It doesn't do any UDP buffering - it'd be quite a bit of work for
 * something which the kernel could be doing for you!
 */

typedef struct {
    int fd;
    char *buf;
    size_t bufsz;
    int offset;
} l_udp_t;

static void
logfile_mod_udp_write(Logfile * lf, const char *buf, size_t len)
{
    l_udp_t *ll = (l_udp_t *) lf->data;
    ssize_t s;
    s = write(ll->fd, (char const *) buf, len);
    fd_bytes(ll->fd, s, FD_WRITE);
#if 0
    if (s < 0) {
        debugs(1, DBG_IMPORTANT, "logfile (udp): got errno (" << errno << "):" << xstrerror());
    }
    if (s != len) {
        debugs(1, DBG_IMPORTANT, "logfile (udp): len=" << len << ", wrote=" << s);
    }
#endif

    /* We don't worry about network errors for now */
}

static void
logfile_mod_udp_flush(Logfile * lf)
{
    l_udp_t *ll = (l_udp_t *) lf->data;
    if (0 == ll->offset)
        return;
    logfile_mod_udp_write(lf, ll->buf, (size_t) ll->offset);
    ll->offset = 0;
}

static void
logfile_mod_udp_writeline(Logfile * lf, const char *buf, size_t len)
{
    l_udp_t *ll = (l_udp_t *) lf->data;

    if (0 == ll->bufsz) {
        /* buffering disabled */
        logfile_mod_udp_write(lf, buf, len);
        return;
    }
    if (ll->offset > 0 && (ll->offset + len + 4) > ll->bufsz)
        logfile_mod_udp_flush(lf);

    if (len > ll->bufsz) {
        /* too big to fit in buffer */
        logfile_mod_udp_write(lf, buf, len);
        return;
    }
    /* buffer it */
    memcpy(ll->buf + ll->offset, buf, len);

    ll->offset += len;

    assert(ll->offset >= 0);

    assert((size_t) ll->offset <= ll->bufsz);
}

static void
logfile_mod_udp_linestart(Logfile * lf)
{
}

static void
logfile_mod_udp_lineend(Logfile * lf)
{
}

static void
logfile_mod_udp_rotate(Logfile * lf)
{
    return;
}

static void
logfile_mod_udp_close(Logfile * lf)
{
    l_udp_t *ll = (l_udp_t *) lf->data;
    lf->f_flush(lf);

    if (ll->fd >= 0)
        file_close(ll->fd);

    if (ll->buf)
        xfree(ll->buf);

    xfree(lf->data);
    lf->data = NULL;
}

/*
 * This code expects the path to be //host:port
 */
int
logfile_mod_udp_open(Logfile * lf, const char *path, size_t bufsz, int fatal_flag)
{
    Ip::Address addr;
    char *strAddr;

    lf->f_close = logfile_mod_udp_close;
    lf->f_linewrite = logfile_mod_udp_writeline;
    lf->f_linestart = logfile_mod_udp_linestart;
    lf->f_lineend = logfile_mod_udp_lineend;
    lf->f_flush = logfile_mod_udp_flush;
    lf->f_rotate = logfile_mod_udp_rotate;

    l_udp_t *ll = static_cast<l_udp_t*>(xcalloc(1, sizeof(*ll)));
    lf->data = ll;

    if (strncmp(path, "//", 2) == 0) {
        path += 2;
    }
    strAddr = xstrdup(path);
    if (!GetHostWithPort(strAddr, &addr)) {
        if (lf->flags.fatal) {
            fatalf("Invalid UDP logging address '%s'\n", lf->path);
        } else {
            debugs(50, DBG_IMPORTANT, "Invalid UDP logging address '" << lf->path << "'");
            safe_free(strAddr);
            return FALSE;
        }
    }
    safe_free(strAddr);

    Ip::Address any_addr;
    any_addr.setAnyAddr();

    // require the sending UDP port to be of the right family for the destination address.
    if (addr.isIPv4())
        any_addr.setIPv4();

    ll->fd = comm_open(SOCK_DGRAM, IPPROTO_UDP, any_addr, COMM_NONBLOCKING, "UDP log socket");
    if (ll->fd < 0) {
        if (lf->flags.fatal) {
            fatalf("Unable to open UDP socket for logging\n");
        } else {
            debugs(50, DBG_IMPORTANT, "Unable to open UDP socket for logging");
            return FALSE;
        }
    } else if (!comm_connect_addr(ll->fd, addr)) {
        if (lf->flags.fatal) {
            fatalf("Unable to connect to %s for UDP log: %s\n", lf->path, xstrerror());
        } else {
            debugs(50, DBG_IMPORTANT, "Unable to connect to " << lf->path << " for UDP log: " << xstrerror());
            return FALSE;
        }
    }
    if (ll->fd == -1) {
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
            debugs(50, DBG_IMPORTANT, "logfileOpen (UDP): " << lf->path << ": " << xstrerror());
            return 0;
        }
    }
    /* Force buffer size to something roughly fitting inside an MTU */
    /*
     * XXX note the receive side needs to receive the whole packet at once;
     * applications like netcat have a small default receive buffer and will
     * truncate!
     */
    bufsz = 1400;
    if (bufsz > 0) {
        ll->buf = static_cast<char*>(xmalloc(bufsz));
        ll->bufsz = bufsz;
    }

    return 1;
}
