/*
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

#ifndef SQUID_FDE_H
#define SQUID_FDE_H

#include "comm.h"
#include "defines.h"
#include "ip/Address.h"

#if USE_SSL
#include <openssl/ssl.h>
#endif

#if USE_DELAY_POOLS
class ClientInfo;
#endif

class PconnPool;
class dwrite_q;
class _fde_disk
{
public:
    DWCB *wrt_handle;
    void *wrt_handle_data;
    dwrite_q *write_q;
    dwrite_q *write_q_tail;
    off_t offset;
    _fde_disk() { memset(this, 0, sizeof(_fde_disk)); }
};

class fde
{

public:
    fde() { clear(); };

    /// True if comm_close for this fd has been called
    bool closing() { return flags.close_request; }

    /* NOTE: memset is used on fdes today. 20030715 RBC */
    static void DumpStats (StoreEntry *);

    char const *remoteAddr() const;
    void dumpStats (StoreEntry &, int);
    bool readPending(int);
    void noteUse(PconnPool *);

public:

    /// global table of FD and their state.
    static fde* Table;

    unsigned int type;
    unsigned short remote_port;

    Ip::Address local_addr;
    tos_t tosToServer;          /**< The TOS value for packets going towards the server.
                                        See also tosFromServer. */
    nfmark_t nfmarkToServer;    /**< The netfilter mark for packets going towards the server.
                                        See also nfmarkFromServer. */
    int sock_family;
    char ipaddr[MAX_IPSTRLEN];            /* dotted decimal address of peer */
    char desc[FD_DESC_SZ];

    struct _fde_flags {
        unsigned int open:1;
        unsigned int close_request:1; // file_ or comm_close has been called
        unsigned int write_daemon:1;
        unsigned int socket_eof:1;
        unsigned int nolinger:1;
        unsigned int nonblocking:1;
        unsigned int ipc:1;
        unsigned int called_connect:1;
        unsigned int nodelay:1;
        unsigned int close_on_exec:1;
        unsigned int read_pending:1;
        unsigned int write_pending:1;
        unsigned int transparent:1;
    } flags;

    int64_t bytes_read;
    int64_t bytes_written;

    struct {
        int uses;                   /* ie # req's over persistent conn */
        PconnPool *pool;
    } pconn;

#if USE_DELAY_POOLS
    ClientInfo * clientInfo;/* pointer to client info used in client write limiter or NULL if not present */
#endif
    unsigned epoll_state;

    _fde_disk disk;
    PF *read_handler;
    void *read_data;
    PF *write_handler;
    void *write_data;
    AsyncCall::Pointer timeoutHandler;
    time_t timeout;
    time_t writeStart;
    void *lifetime_data;
    AsyncCall::Pointer closeHandler;
    AsyncCall::Pointer halfClosedReader; /// read handler for half-closed fds
    CommWriteStateData *wstate;         /* State data for comm_write */
    READ_HANDLER *read_method;
    WRITE_HANDLER *write_method;
#if USE_SSL
    SSL *ssl;
    SSL_CTX *dynamicSslContext; ///< cached and then freed when fd is closed
#endif
#if _SQUID_MSWIN_
    struct {
        long handle;
    } win32;
#endif
    tos_t tosFromServer;                /**< Stores the TOS flags of the packets from the remote server.
                                            See FwdState::dispatch(). Note that this differs to
                                            tosToServer in that this is the value we *receive* from the,
                                            connection, whereas tosToServer is the value to set on packets
                                            *leaving* Squid.  */
    unsigned int nfmarkFromServer;      /**< Stores the Netfilter mark value of the connection from the remote
                                            server. See FwdState::dispatch(). Note that this differs to
                                            nfmarkToServer in that this is the value we *receive* from the,
                                            connection, whereas nfmarkToServer is the value to set on packets
                                            *leaving* Squid.   */

private:
    /** Clear the fde class back to NULL equivalent. */
    inline void clear() {
        type = 0;
        remote_port = 0;
        local_addr.SetEmpty();
        tosToServer = '\0';
        nfmarkToServer = 0;
        sock_family = 0;
        memset(ipaddr, '\0', MAX_IPSTRLEN);
        memset(desc,'\0',FD_DESC_SZ);
        memset(&flags,0,sizeof(_fde_flags));
        bytes_read = 0;
        bytes_written = 0;
        pconn.uses = 0;
        pconn.pool = NULL;
#if USE_DELAY_POOLS
        clientInfo = NULL;
#endif
        epoll_state = 0;
        read_handler = NULL;
        read_data = NULL;
        write_handler = NULL;
        write_data = NULL;
        timeoutHandler = NULL;
        timeout = 0;
        writeStart = 0;
        lifetime_data = NULL;
        closeHandler = NULL;
        halfClosedReader = NULL;
        wstate = NULL;
        read_method = NULL;
        write_method = NULL;
#if USE_SSL
        ssl = NULL;
        dynamicSslContext = NULL;
#endif
#if _SQUID_MSWIN_
        win32.handle = NULL;
#endif
        tosFromServer = '\0';
        nfmarkFromServer = 0;
    }
};

#define fd_table fde::Table

int fdNFree(void);

#define FD_READ_METHOD(fd, buf, len) (*fd_table[fd].read_method)(fd, buf, len)
#define FD_WRITE_METHOD(fd, buf, len) (*fd_table[fd].write_method)(fd, buf, len)

#endif /* SQUID_FDE_H */
