/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 02    Unlink Daemon */

#include "squid.h"

#if USE_UNLINKD
#include "fd.h"
#include "fde.h"
#include "fs_io.h"
#include "globals.h"
#include "SquidConfig.h"
#include "SquidIpc.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "store/Disk.h"
#include "tools.h"
#include "xusleep.h"

/* This code gets linked to Squid */

static int unlinkd_wfd = -1;
static int unlinkd_rfd = -1;

static void * hIpc;
static pid_t pid;

#define UNLINKD_QUEUE_LIMIT 20

void
unlinkdUnlink(const char *path)
{
    char buf[MAXPATHLEN];
    int l;
    int bytes_written;
    static int queuelen = 0;

    if (unlinkd_wfd < 0) {
        debug_trap("unlinkdUnlink: unlinkd_wfd < 0");
        safeunlink(path, 0);
        return;
    }

    /*
     * If the queue length is greater than our limit, then we pause
     * for a small amount of time, hoping that unlinkd has some
     * feedback for us.  Maybe it just needs a slice of the CPU's
     * time.
     */
    if (queuelen >= UNLINKD_QUEUE_LIMIT) {
#if defined(USE_EPOLL) || defined(USE_KQUEUE) || defined(USE_DEVPOLL)
        /*
         * DPW 2007-04-23
         * We can't use fd_set when using epoll() or kqueue().  In
         * these cases we block for 10 ms.
         */
        xusleep(10000);
#else
        /*
         * DPW 2007-04-23
         * When we can use select, block for up to 100 ms.
         */
        struct timeval to;
        fd_set R;
        FD_ZERO(&R);
        FD_SET(unlinkd_rfd, &R);
        to.tv_sec = 0;
        to.tv_usec = 100000;
        select(unlinkd_rfd + 1, &R, NULL, NULL, &to);
#endif
    }

    /*
    * If there is at least one outstanding unlink request, then
    * try to read a response.  If there's nothing to read we'll
    * get an EWOULDBLOCK or whatever.  If we get a response, then
    * decrement the queue size by the number of newlines read.
    */
    if (queuelen > 0) {
        int bytes_read;
        int i;
        char rbuf[512];
        bytes_read = read(unlinkd_rfd, rbuf, 511);

        if (bytes_read > 0) {
            rbuf[bytes_read] = '\0';

            for (i = 0; i < bytes_read; ++i)
                if ('\n' == rbuf[i])
                    --queuelen;

            assert(queuelen >= 0);
        }
    }

    l = strlen(path);
    assert(l < MAXPATHLEN);
    xstrncpy(buf, path, MAXPATHLEN);
    buf[l] = '\n';
    ++l;
    bytes_written = write(unlinkd_wfd, buf, l);

    if (bytes_written < 0) {
        int xerrno = errno;
        debugs(2, DBG_IMPORTANT, "unlinkdUnlink: write FD " << unlinkd_wfd << " failed: " << xstrerr(xerrno));
        safeunlink(path, 0);
        return;
    } else if (bytes_written != l) {
        debugs(2, DBG_IMPORTANT, "unlinkdUnlink: FD " << unlinkd_wfd << " only wrote " << bytes_written << " of " << l << " bytes");
        safeunlink(path, 0);
        return;
    }

    ++statCounter.unlink.requests;
    /*
    * Increment this syscalls counter here, even though the syscall
    * is executed by the helper process.  We try to be consistent
    * in counting unlink operations.
    */
    ++statCounter.syscalls.disk.unlinks;
    ++queuelen;
}

void
unlinkdClose(void)
#if _SQUID_WINDOWS_
{

    if (unlinkd_wfd > -1) {
        debugs(2, DBG_IMPORTANT, "Closing unlinkd pipe on FD " << unlinkd_wfd);
        shutdown(unlinkd_wfd, SD_BOTH);
        comm_close(unlinkd_wfd);

        if (unlinkd_wfd != unlinkd_rfd)
            comm_close(unlinkd_rfd);

        unlinkd_wfd = -1;

        unlinkd_rfd = -1;
    }

    if (hIpc) {
        if (WaitForSingleObject(hIpc, 5000) != WAIT_OBJECT_0) {
            getCurrentTime();
            debugs(2, DBG_IMPORTANT, "unlinkdClose: WARNING: (unlinkd," << pid << "d) didn't exit in 5 seconds");
        }

        CloseHandle(hIpc);
    }
}
#else
{

    if (unlinkd_wfd < 0)
        return;

    debugs(2, DBG_IMPORTANT, "Closing unlinkd pipe on FD " << unlinkd_wfd);

    file_close(unlinkd_wfd);

    if (unlinkd_wfd != unlinkd_rfd)
        file_close(unlinkd_rfd);

    unlinkd_wfd = -1;

    unlinkd_rfd = -1;
}

#endif

bool
unlinkdNeeded(void)
{
    // we should start unlinkd if there are any cache_dirs using it
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        const RefCount<SwapDir> sd = Config.cacheSwap.swapDirs[i];
        if (sd->unlinkdUseful())
            return true;
    }

    return false;
}

void
unlinkdInit(void)
{
    if (unlinkd_wfd >= 0)
        return; // unlinkd already started

    const char *args[2];
    Ip::Address localhost;

    args[0] = "(unlinkd)";
    args[1] = NULL;
    localhost.setLocalhost();

    pid = ipcCreate(
#if USE_POLL && _SQUID_OSF_
              /* pipes and poll() don't get along on DUNIX -DW */
              IPC_STREAM,
#elif _SQUID_WINDOWS_
              /* select() will fail on a pipe */
              IPC_TCP_SOCKET,
#else
              /* We currently need to use FIFO.. see below */
              IPC_FIFO,
#endif
              Config.Program.unlinkd,
              args,
              "unlinkd",
              localhost,
              &unlinkd_rfd,
              &unlinkd_wfd,
              &hIpc);

    if (pid < 0)
        fatal("Failed to create unlinkd subprocess");

    xusleep(250000);

    fd_note(unlinkd_wfd, "squid -> unlinkd");

    fd_note(unlinkd_rfd, "unlinkd -> squid");

    commUnsetFdTimeout(unlinkd_rfd);
    commUnsetFdTimeout(unlinkd_wfd);

    /*
    * unlinkd_rfd should already be non-blocking because of
    * ipcCreate.  We change unlinkd_wfd to blocking mode because
    * we never want to lose an unlink request, and we don't have
    * code to retry if we get EWOULDBLOCK.  Unfortunately, we can
    * do this only for the IPC_FIFO case.
    */
    assert(fd_table[unlinkd_rfd].flags.nonblocking);

    if (FD_PIPE == fd_table[unlinkd_wfd].type)
        commUnsetNonBlocking(unlinkd_wfd);

    debugs(2, DBG_IMPORTANT, "Unlinkd pipe opened on FD " << unlinkd_wfd);

#if _SQUID_WINDOWS_

    debugs(2, 4, "Unlinkd handle: 0x" << std::hex << hIpc << std::dec << ", PID: " << pid);

#endif

}
#endif /* USE_UNLINKD */

