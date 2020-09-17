/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 50    Log file handling */

#include "squid.h"
#include "cbdata.h"
#include "comm/Loops.h"
#include "fatal.h"
#include "fde.h"
#include "globals.h"
#include "log/Config.h"
#include "log/File.h"
#include "log/ModDaemon.h"
#include "mem/PoolingAllocator.h"
#include "SquidConfig.h"
#include "SquidIpc.h"
#include "SquidTime.h"

#include <cerrno>
#include <list>

/* How many buffers to keep before we say we've buffered too much */
#define LOGFILE_MAXBUFS     128

/* Size of the logfile buffer */
/*
 * For optimal performance this should match LOGFILE_BUFSIZ in logfile-daemon.c
 */
#define LOGFILE_BUFSZ       32768

/* How many seconds between warnings */
#define LOGFILE_WARN_TIME   30

static LOGWRITE logfile_mod_daemon_writeline;
static LOGLINESTART logfile_mod_daemon_linestart;
static LOGLINEEND logfile_mod_daemon_lineend;
static LOGROTATE logfile_mod_daemon_rotate;
static LOGFLUSH logfile_mod_daemon_flush;
static LOGCLOSE logfile_mod_daemon_close;

static void logfile_mod_daemon_append(Logfile * lf, const char *buf, int len);

class l_daemon_t
{
public:
    int rfd = 0;
    int wfd = 0;
    char eol = 1; // XXX: used as a bool
    pid_t pid = -1;
    int flush_pending = 0; // XXX: used as bool
    std::list<logfile_buffer_t, PoolingAllocator<logfile_buffer_t>> bufs;
    int last_warned = 0;
};

static void
logfileHandleWrite(int, void *data)
{
    Logfile *lf = static_cast<Logfile *>(data);
    l_daemon_t *ll = static_cast<l_daemon_t *>(lf->data);

    /*
     * We'll try writing the first entry until its done - if we
     * get a partial write then we'll re-schedule until its completed.
     * Its naive but it'll do for now.
     */
    if (ll->bufs.empty()) // abort if there is nothing pending right now.
        return;

    auto &b = ll->bufs.front();
    ll->flush_pending = 0;

    int ret = FD_WRITE_METHOD(ll->wfd, b.buf + b.written_len, b.len - b.written_len);
    int xerrno = errno;
    debugs(50, 3, lf->path << ": write returned " << ret);
    if (ret < 0) {
        if (ignoreErrno(xerrno)) {
            /* something temporary */
            Comm::SetSelect(ll->wfd, COMM_SELECT_WRITE, logfileHandleWrite, lf, 0);
            ll->flush_pending = 1;
            return;
        }
        debugs(50, DBG_IMPORTANT,"logfileHandleWrite: " << lf->path << ": error writing (" << xstrerr(xerrno) << ")");
        /* XXX should handle this better */
        fatal("I don't handle this error well!");
    }
    if (ret == 0) {
        /* error? */
        debugs(50, DBG_IMPORTANT, "logfileHandleWrite: " << lf->path << ": wrote 0 bytes?");
        /* XXX should handle this better */
        fatal("I don't handle this error well!");
    }
    /* ret > 0, so something was written */
    b.written_len += ret;
    assert(b.written_len <= b.len);
    if (b.written_len == b.len)
        ll->bufs.pop_front();
    /* Is there more to write? */
    if (ll->bufs.empty())
        return;
    /* there is, so schedule more */

    Comm::SetSelect(ll->wfd, COMM_SELECT_WRITE, logfileHandleWrite, lf, 0);
    ll->flush_pending = 1;
    return;
}

static void
logfileQueueWrite(Logfile * lf)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    if (ll->flush_pending || ll->bufs.empty()) {
        return;
    }
    ll->flush_pending = 1;
    if (!ll->bufs.empty()) {
        const auto &b = ll->bufs.front();
        if (b.len + 2 <= b.size)
            logfile_mod_daemon_append(lf, "F\n", 2);
    }
    /* Ok, schedule a write-event */
    Comm::SetSelect(ll->wfd, COMM_SELECT_WRITE, logfileHandleWrite, lf, 0);
}

static void
logfile_mod_daemon_append(Logfile * lf, const char *buf, int len)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;

    /* Is there a buffer? If not, create one */
    if (ll->bufs.empty()) {
        debugs(50, 5, lf->path << ": new buffer");
        ll->bufs.emplace_back(LOGFILE_BUFSZ);
    }
    debugs(50, 3, "logfile_mod_daemon_append: " << lf->path << ": appending " << len << " bytes");
    /* Copy what can be copied */
    while (len > 0) {
        auto &b = ll->bufs.back();
        debugs(50, 3, "logfile_mod_daemon_append: current buffer has " << b.len << " of " << b.size << " bytes before append");
        auto s = min(len, (b.size - b.len));
        memcpy(b.buf + b.len, buf, s);
        len = len - s;
        buf = buf + s;
        b.len = b.len + s;
        assert(b.len <= LOGFILE_BUFSZ);
        assert(len >= 0);
        if (len > 0) {
            debugs(50, 5, lf->path << ": new buffer");
            ll->bufs.emplace_back(LOGFILE_BUFSZ);
        }
    }
}

/*
 * only schedule a flush (write) if one isn't scheduled.
 */
static void
logfileFlushEvent(void *data)
{
    Logfile *lf = static_cast<Logfile *>(data);

    /*
     * This might work better if we keep track of when we wrote last and only
     * schedule a write if we haven't done so in the last second or two.
     */
    logfileQueueWrite(lf);
    eventAdd("logfileFlush", logfileFlushEvent, lf, 1.0, 1);
}

/* External code */

int
logfile_mod_daemon_open(Logfile * lf, const char *path, size_t, int)
{
    const char *args[5];
    char *tmpbuf;
    l_daemon_t *ll;

    lf->f_close = logfile_mod_daemon_close;
    lf->f_linewrite = logfile_mod_daemon_writeline;
    lf->f_linestart = logfile_mod_daemon_linestart;
    lf->f_lineend = logfile_mod_daemon_lineend;
    lf->f_flush = logfile_mod_daemon_flush;
    lf->f_rotate = logfile_mod_daemon_rotate;

    cbdataInternalLock(lf); // WTF?
    debugs(50, DBG_IMPORTANT, "Logfile Daemon: opening log " << path);
    ll = new l_daemon_t;
    lf->data = ll;
    {
        Ip::Address localhost;
        args[0] = "(logfile-daemon)";
        args[1] = path;
        args[2] = NULL;
        localhost.setLocalhost();
        ll->pid = ipcCreate(IPC_STREAM, Log::TheConfig.logfile_daemon, args, "logfile-daemon", localhost, &ll->rfd, &ll->wfd, NULL);
        if (ll->pid < 0)
            fatal("Couldn't start logfile helper");
    }

    /* Queue the initial control data */
    tmpbuf = static_cast<char*>(xmalloc(BUFSIZ));
    snprintf(tmpbuf, BUFSIZ, "r%d\nb%d\n", Config.Log.rotateNumber, Config.onoff.buffered_logs);
    logfile_mod_daemon_append(lf, tmpbuf, strlen(tmpbuf));
    xfree(tmpbuf);

    /* Start the flush event */
    eventAdd("logfileFlush", logfileFlushEvent, lf, 1.0, 1);

    return 1;
}

static void
logfile_mod_daemon_close(Logfile * lf)
{
    l_daemon_t *ll = static_cast<l_daemon_t *>(lf->data);
    debugs(50, DBG_IMPORTANT, "Logfile Daemon: closing log " << lf->path);
    logfileFlush(lf);
    if (ll->rfd == ll->wfd)
        comm_close(ll->rfd);
    else {
        comm_close(ll->rfd);
        comm_close(ll->wfd);
    }
    kill(ll->pid, SIGTERM);
    eventDelete(logfileFlushEvent, lf);
    delete ll;
    lf->data = NULL;
    cbdataInternalUnlock(lf); // WTF??
}

static void
logfile_mod_daemon_rotate(Logfile * lf, const int16_t)
{
    char tb[3];
    debugs(50, DBG_IMPORTANT, "logfileRotate: " << lf->path);
    tb[0] = 'R';
    tb[1] = '\n';
    tb[2] = '\0';
    logfile_mod_daemon_append(lf, tb, 2);
}

/*
 * This routine assumes that up to one line is written. Don't try to
 * call this routine with more than one line or subsequent lines
 * won't be prefixed with the command type and confuse the logging
 * daemon somewhat.
 */
static void
logfile_mod_daemon_writeline(Logfile * lf, const char *buf, size_t len)
{
    l_daemon_t *ll = static_cast<l_daemon_t *>(lf->data);
    /* Make sure the logfile buffer isn't too large */
    if (ll->bufs.size() > LOGFILE_MAXBUFS) {
        if (ll->last_warned < squid_curtime - LOGFILE_WARN_TIME) {
            ll->last_warned = squid_curtime;
            debugs(50, DBG_IMPORTANT, "Logfile: " << lf->path << ": queue is too large; some log messages have been lost.");
        }
        return;
    }

    /* Are we eol? If so, prefix with our logfile command byte */
    if (ll->eol == 1) {
	logfile_mod_daemon_append(lf, "L", 1);
	ll->eol = 0;
    }

    /* Append this data to the end buffer; create a new one if needed */
    logfile_mod_daemon_append(lf, buf, len);
}

static void
logfile_mod_daemon_linestart(Logfile * lf)
{
    l_daemon_t *ll = static_cast<l_daemon_t *>(lf->data);
    assert(ll->eol == 1);
    // logfile_mod_daemon_writeline() sends the starting command
}

static void
logfile_mod_daemon_lineend(Logfile * lf)
{
    l_daemon_t *ll = static_cast<l_daemon_t *>(lf->data);
    if (ll->eol == 1) // logfile_mod_daemon_writeline() wrote nothing
        return;
    ll->eol = 1;
    /* Kick a write off if the head buffer is -full- */
    if (!ll->bufs.empty()) {
        if (ll->bufs.size() > 1 || !Config.onoff.buffered_logs)
            logfileQueueWrite(lf);
    }
}

static void
logfile_mod_daemon_flush(Logfile * lf)
{
    l_daemon_t *ll = static_cast<l_daemon_t *>(lf->data);
    if (commUnsetNonBlocking(ll->wfd)) {
        debugs(50, DBG_IMPORTANT, "Logfile Daemon: Couldn't set the pipe blocking for flush! You're now missing some log entries.");
        return;
    }
    while (!ll->bufs.empty()) {
        logfileHandleWrite(ll->wfd, lf);
    }
    if (commSetNonBlocking(ll->wfd)) {
        fatalf("Logfile Daemon: %s: Couldn't set the pipe non-blocking for flush!\n", lf->path);
        return;
    }
}

